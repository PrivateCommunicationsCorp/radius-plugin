/*
 *  radiusplugin -- An OpenVPN plugin for do radius authentication
 *                  and accounting.
 *
 *  Copyright (C) 2005 EWE TEL GmbH/Ralf Luebben <ralfluebben@gmx.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "AccountingProcess.h"

/** This method is the background process for accounting. It is in a endless loop
 * until it gets a exit command. In the loop the process is
 * waiting for a command from the foregroundprocess (USER_ADD, USER_DEL, EXIT).
 * If no command is arrived in an interval of 0,5s the accounting is done
 * for all users who need a update. The interval is 0,5s because every second
 * a user can connect with an unknown interval, so this interval must be shorter.
 * @param context The plugin context as object from the class PluginContext.
 */

void AccountingProcess::Accounting(PluginContext * context)
{
  UserAcct              *user = NULL; // The user for acconting.
  int                   command,      // The command from foreground process.
                        result;       // The result from the socket.
  string                    key;        //The unique key.
  AcctScheduler             scheduler;  //The scheduler for the accounting.
  fd_set                set;        //A set for the select function.
  struct timeval            tv;         //A timeinterval for the
                                        //select function.
  StdLogger log("RADIUS-PLUGIN [PLUGIN-ACCT-LOOP]", context->getVerbosity());
  log.debug() << "  Starting...\n";

  //Tell the parent everythink is ok.
  try {
    context->acctsocketforegr.send(RESPONSE_INIT_SUCCEEDED);
    log() << " Started, RESPONSE_INIT_SUCCEEDED was sent to Foreground Process.\n";
  }
  catch (Exception &e) {
    log() << "  send response init_ok failed: " << e << "\n";
    goto done;
  }
  catch (std::exception &e)
  {
    log() << "  send response init_ok failed: " << e.what() << "\n";
    goto done;
  }
  catch(...) {
    log() << "  send response init_ok failed: unknown error\n";
  }

  /*if (DEBUG (context->getVerbosity()))
    cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND ACCT: "
    << "Started, RESPONSE_INIT_SUCCEEDED was sent to Foreground
    Process.\n"; */

  // Event loop
  while (1)
  {
    try {
    //create the informations for the result function
    tv.tv_sec = 0;
    tv.tv_usec = 500000;    //wait 0,5s
    FD_ZERO(&set);          // clear out the set
    FD_SET(context->acctsocketforegr.getSocket(), &set); // wait only on the socket from the foreground process
    result = select(FD_SETSIZE, &set, NULL, NULL, &tv);

    //if there is a data on the socket
    if (result>0)
    {
      // get a command from foreground process
      command = context->acctsocketforegr.recvInt();
      log.debug() << " Got command: '" << command << "'\n";

      switch (command)
      {
        //add a new user to the scheduler
      case ADD_USER:
        try
        {
          log.debug() << " New User.\n";

          // if accounting errors are non fatal return success and proceed with accounting
          if(context->conf.getNonFatalAccounting()==true) {
            log() << "send nonfatal success response\n";
            context->acctsocketforegr.send(RESPONSE_SUCCEEDED);
          }
          UserAcct new_user;
          user = &new_user;
          //get the information from the foreground process
          try {
            user->setUsername(context->acctsocketforegr.recvStr());
            user->setSessionId(context->acctsocketforegr.recvStr()) ;
            user->setPortnumber(context->acctsocketforegr.recvInt());
            user->setCallingStationId(context->acctsocketforegr.recvStr());
            user->setFramedIp(context->acctsocketforegr.recvStr());
            user->setCommonname(context->acctsocketforegr.recvStr());
            user->setAcctInterimInterval(context->acctsocketforegr.recvInt());
            user->setFramedRoutes(context->acctsocketforegr.recvStr());
            user->setKey(context->acctsocketforegr.recvStr());
            user->setStatusFileKey(context->acctsocketforegr.recvStr());
            user->setUntrustedPort(context->acctsocketforegr.recvStr());
            context->acctsocketforegr.recvBuf(user);
            log.debug() << "New user acct: username: "
                        << user->getUsername() << ", interval: " << user->getAcctInterimInterval()
                        << ", calling station: " << user->getCallingStationId() << ", commonname: "
                        << user->getCommonname() << ", framed ip: " << user->getFramedIp() <<".\n";
          }
          catch(std::exception &e) {
            log() << "Fail while read user info from socket: " << e.what() << "\n";
          }
          catch(...) {
            log() << "Fail while read user info from socket\n";
          }

          //set the starttime
          user->setStarttime(time(NULL));

          //calculate the nextupdate
          user->setNextUpdate(user->getStarttime() + user->getAcctInterimInterval());
          if(user->getAcctInterimInterval() != 60) {
            log() << "got acct interim interval = " << user->getAcctInterimInterval() << "\n";
          }

          //send the start packet
          if (user->sendStartPacket(context)==0)
          {
            log.debug() << " Start packet sent.\n";
            log.debug() << "RADIUS-PLUGIN: BACKGROUND ACCT: User was added to accounting scheduler.\n";

            //set the system routes
            user->addSystemRoutes(context);


            string script = context->conf.getVsaScript();
            //execute vendor specific attribute script
            if (script.length() > 0)
            {
              log.debug() << " Call vendor specific attribute script: '" << script << "'.\n";
              if (callVsaScript(context, user, 1, 0) != 0) {
                log() << " Vendor specific script failed to execute (fatal)!" << "\n";
                throw Exception("Vendor specific attribute script failed.\n");
              }
            }

            //add the user to the scheduler
            scheduler.addUser(*user);
            //send the ok to the parent process
            if(context->conf.getNonFatalAccounting()==false) {
              log() << "send non nonfatal success response\n";
              context->acctsocketforegr.send(RESPONSE_SUCCEEDED);
            }
          }
          else
          {
            //delete the ccd file which was created at authentication
            //user->deleteCcdFile(context);
            //tell the parent parent process something is wrong
            log() << " Failed to send start ticket (fatal)!" << "\n";
            throw Exception("Accounting failed.\n");
          }
          // free the user, he was copied to the accounting scheduler list
        }
        catch (Exception &e)
        {
          log() << "failed while do add user command: " << e << "!\n";
          if(context->conf.getNonFatalAccounting()==false) {
            log() << " send non nonfatal fail response\n";
            context->acctsocketforegr.send(RESPONSE_FAILED);
          }
          //close the background process, if the ipc socket is bad
          if (e.getErrnum()==Exception::SOCKETSEND || e.getErrnum()==Exception::SOCKETRECV)
          {
            log() << "Error in socket!\n";
            goto done;
          }
        }
        catch (std::exception &e) {
          log() << "failed while do add user command: " << e.what() << "!\n";
          if(context->conf.getNonFatalAccounting()==false) {
            log() << "send non nonfatal fail response\n";
            context->acctsocketforegr.send(RESPONSE_FAILED);
          }
        }
        catch (...) {
          if(context->conf.getNonFatalAccounting()==false) {
            log() << "send non nonfatal fail response\n";
            context->acctsocketforegr.send(RESPONSE_FAILED);
          }
          log() << "Unknown Exception!\n";
        }
        break;

        //delete a user
      case DEL_USER:
        log.debug() << "Deleting user from accounting...\n";

        // if accounting errors are non fatal return success
        if(context->conf.getNonFatalAccounting()==true) {
          log() << " send nonfatal success response\n";
          context->acctsocketforegr.send(RESPONSE_SUCCEEDED);
        }

        //receive the information
        try {
          key=context->acctsocketforegr.recvStr();
        }
        catch (Exception &e) {
          log() << " fail while read user key from socket: "<< e << "!\n";
          //close the background process, if the ipc socket is bad
          if (e.getErrnum()==Exception::SOCKETSEND || e.getErrnum()==Exception::SOCKETRECV)
          {
            log() << " fail while read user key, socket error (critical)\n";
            goto done;
          }
        }
        catch (std::exception &e) {
          log() << " fail while read user key from socket: "<< e.what() << "!\n";
        }
        catch (...) {
          log() << " Unknown Exception!\n";
        }

        //find the user, he must be already there
        user=scheduler.findUser(key);

        if (user)
        {
          log.debug() << " Stop acct(" << key << "): username: " << user->getUsername()
                      << ", calling station: " << user->getCallingStationId()
                      << ", commonname: " << user->getCommonname() << ".\n";

          //delete the system routes
          user->delSystemRoutes(context);

          //delete the ccd file which was created at authentication
          //user->deleteCcdFile(context);

          string script = context->conf.getVsaScript();
          //execute vendor specific attribute script
          if (script.length() > 0)
          {
            //string command= context->conf.getVsaScript() + string(" ") + string("ACTION=CLIENT_CONNECT")+string(" ")+string("USERNAME=")+user->getUsername()+string(" ")+string("COMMONNAME=")+user->getCommonname()+string(" ")+string("UNTRUSTED_IP=")+user->getCallingStationId() + string(" ") + string("UNTRUSTED_PORT=") + user->getUntrustedPort() + user->getVsaString();
            log.debug() << " Call vendor specific attribute script.\n";
            if (callVsaScript(context, user, 2, 0) != 0) {
              log() << " fail to execute vendor script while delete user (fatal)\n";
              throw Exception("Vendor specific attribute script failed.\n");
            }
          }

          try
          {
            //delete the user from the accounting scheduler
            scheduler.delUser(context, user);

            log.debug() << " User with key: " << key << " was deleted from accounting.\n";

            //send the parent process the ok
            if(context->conf.getNonFatalAccounting()==false) {
              log() << "send non nonfatal success response\n";
              context->acctsocketforegr.send(RESPONSE_SUCCEEDED);
            }
          }
          catch (Exception &e) {
            log() << " fail while do delete user command(critical): " << e << "\n";
            goto done;
          }
          catch (std::exception &e) {
            log() << " fail while do delete user command(critical): " << e.what() << "\n";
          }
          catch (...) {
            log() << " Unknown Exception while do dele user cmd!\n";
          }
        }
        else {
          log() << "No user with this key "<< key <<".\n";
          if(context->conf.getNonFatalAccounting()==false) {
            log() << "send non nonfatal fail response\n";
            context->acctsocketforegr.send(RESPONSE_FAILED);
          }
        }
        break;

        //exit the loop
      case COMMAND_EXIT:
        log.debug() << " Get command exit.\n";
        goto done;

      case -1:
        log() << " read error on command channel (cmd = -1).\n";
        break;

      default:
        log() << " unknown command code: code= "<< command <<", exiting (critical).\n";
        goto done;
      }
    }
    //after 0,5sec without a command call the scheduler
    scheduler.doAccounting(context);
    }
    catch (std::exception &e) {
      log() << " Acct loop fail. Got unhandled exception : " << e.what() << ".\n";
      throw e;
    }
    catch (Exception &e) {
      log() << " Acct loop fail. Got unhandled exception : " << e << ".\n";
      throw e;
    }
    catch (...) {
      log() << " Acct loop fail. Got unknown unhandled exception.\n";
      throw "Unknown exception in ACCT loop";
    }
  }
done:
  //end the process
  log() << "doing end acct loop!\n";
  if (1)
    scheduler.delallUsers(context);
  log() << "EXIT\n";
  return;
}

/** This method executes the program for the vendor specific attributes and pass
 * attributes to the program and vendor specific attributes as a buffer
 * to the program.
 * Attributes               Code for decoding
 *
 *  string username         => 101
 *  string commonname       => 102
 *  string framedip         => 103
 *  string callingstationid => 104
 *  string untrustedport    => 105
 *  string framedroutes     => 106
 *  Octet vsabuf            => 107
 * The code is used for decoding in the additional program. The vsabuf must be decode also in the program.
 * Example: vsascript.pl
 * @param context The PluginContext
 * @param user The user for which the script is executed.
 * @param action Action: 0 => Authentication, 1 => Client-Connect, 2 => Client-Disconnect
 * @param rekeying If equal 1 this is a rekeying.
 * @return -1 in case of error, else 0
 */

int AccountingProcess::callVsaScript(PluginContext * context, User * user, unsigned int action, unsigned int rekeying)
{
  StdLogger log("RADIUS-PLUGIN [PLUGIN-CALL-VSASCRIPT]", context->getVerbosity());

  char * route;
  Octet * buf;
  int buflen = 3 * sizeof(int);
  if (user->getUsername().length() != 0)
  {
    buflen=buflen+user->getUsername().length()+2*sizeof(int);
  }
  if (user->getCommonname().length() != 0)
  {
    buflen=buflen+user->getCommonname().length()+2*sizeof(int);
  }
  if (user->getFramedIp().length() != 0)
  {
    buflen=buflen+user->getFramedIp().length()+2*sizeof(int);
  }
  if (user->getCallingStationId().length() != 0)
  {
    buflen=buflen+user->getCallingStationId().length()+2*sizeof(int);
  }
  if (user->getUntrustedPort().length() != 0)
  {
    buflen=buflen+user->getUntrustedPort().length()+2*sizeof(int);
  }
  if (user->getVsaBufLen() != 0)
  {
    buflen=buflen+user->getVsaBufLen() +2*sizeof(int);
  }

  char routes[user->getFramedRoutes().length()+1];
  strncpy(routes, user->getFramedRoutes().c_str(), user->getFramedRoutes().length());
  routes[user->getFramedRoutes().length()]=0;
  if ((route = strtok(routes,";")) != NULL)
  {
    buflen=buflen+strlen(route)+2*sizeof(int);
    while ((route = strtok(NULL,";"))!= NULL)
    {
      buflen=buflen+strlen(route)+2*sizeof(int);
    }
  }
  try{
    buf = new Octet[buflen];
  }
  catch(...)
  {
    log() << "Memory allocatoin failed for framedroutes buf.\n";
  }
  unsigned int value = htonl(action);
  memcpy(buf,&value, 4);

  value = htonl(rekeying);
  memcpy(buf+4,&value, 4);

  value = htonl(buflen);
  memcpy(buf+8,&value, 4);

  int i=12;

  if (user->getUsername().length() != 0)
  {
    value = htonl(101);
    memcpy(buf+i,&value, 4);
    i+=4;
    value = htonl(user->getUsername().length());
    memcpy(buf+i,&value, 4);
    i+=4;
    memcpy( buf+i, user->getUsername().c_str(),user->getUsername().length());
    i=i+user->getUsername().length();
  }
  if (user->getCommonname().length() != 0)
  {
    value = htonl(102);
    memcpy(buf+i,&value, 4);
    i+=4;
    value = htonl(user->getCommonname().length());
    memcpy(buf+i,&value, 4);
    i+=4;
    memcpy( buf+i, user->getCommonname().c_str(),user->getCommonname().length());
    i=i+user->getCommonname().length();
  }
  if (user->getFramedIp().length() != 0)
  {
    value = htonl(103);
    memcpy(buf+i,&value, 4);
    i+=4;
    value = htonl(user->getFramedIp().length());
    memcpy(buf+i,&value, 4);
    i+=4;
    memcpy( buf+i, user->getFramedIp().c_str(),user->getFramedIp().length());
    i=i+user->getFramedIp().length();
  }
  if (user->getCallingStationId().length() != 0)
  {
    value = htonl(104);
    memcpy(buf+i,&value, 4);
    i+=4;
    value = htonl(user->getCallingStationId().length());
    memcpy(buf+i,&value, 4);
    i+=4;
    memcpy( buf+i, user->getCallingStationId().c_str(),user->getCallingStationId().length());
    i=i+user->getCallingStationId().length();
  }
  if (user->getUntrustedPort().length() != 0)
  {
    value = htonl(105);
    memcpy(buf+i,&value, 4);
    i+=4;
    value = htonl(user->getUntrustedPort().length());
    memcpy(buf+i,&value, 4);
    i+=4;
    memcpy( buf+i, user->getUntrustedPort().c_str(),user->getUntrustedPort().length());
    i=i+user->getUntrustedPort().length();
  }
  strncpy(routes, user->getFramedRoutes().c_str(), user->getFramedRoutes().length());

  routes[user->getFramedRoutes().length()]=0;
  if ((route = strtok(routes,";")) != NULL)
  {
    value = htonl(106);
    memcpy(buf+i,&value, 4);
    i+=4;
    value = htonl(strlen(route));
    memcpy(buf+i,&value, 4);
    i+=4;
    memcpy(buf+i, route, strlen(route));
    i=i+strlen(route);
    while ((route = strtok(NULL,";"))!= NULL)
    {
      value = htonl(106);
      memcpy(buf+i,&value, 4);
      i+=4;
      value = htonl(strlen(route));
      memcpy(buf+i,&value, 4);
      i+=4;
      memcpy(buf+i, route, strlen(route));
      i=i+strlen(route);
    }
  }

  if (user->getVsaBufLen() != 0)
  {
    value = htonl(107);
    memcpy(buf+i,&value, 4);
    i+=4;
    value = htonl(user->getVsaBufLen());
    memcpy(buf+i,&value, 4);
    i+=4;
    memcpy(buf+i, user->getVsaBuf(),user->getVsaBufLen());
    i=i+user->getVsaBufLen();
  }


  if (mkfifo(context->conf.getVsaNamedPipe().c_str(), 0600) == -1)
  {
    /* FIFO bereits vorhanden - kein fataler Fehler */
    if (errno == EEXIST) {
      log() << "FIFO already exist.\n";
    } else {
      log() <<"Error in mkfifio()\n";
      return -1;
    }
  }
  int fd_fifo=open(context->conf.getVsaNamedPipe().c_str(), O_RDWR | O_NONBLOCK);

  if (fd_fifo == -1) {
    log() <<"Error in opening pipe to VSAScript.";
    return -1;
  }
  string exe=string(context->conf.getVsaScript()) + " " + string(context->conf.getVsaNamedPipe());
  if (write (fd_fifo, buf, buflen) != buflen) {
    close(fd_fifo);
    log() << "Could not write in Pipe to VSAScript!";
    return -1;
  }

  if (system(exe.c_str())!=0) {
    close(fd_fifo);
    log() << "Error in VSAScript!";
    return -1;
  }
  close(fd_fifo);

  delete [] buf;
  return 0;
}


