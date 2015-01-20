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

#include "AcctScheduler.h"
#include "PluginContext.h"
#include "RadiusClass/RadiusConfig.h"
#include "Config.h"
#include "radiusplugin.h"

using namespace std;

/** The constructor of the class.
 * Nothing happens here.
 */

AcctScheduler::AcctScheduler()
{
}

/**The destructor of the class.
 * The user lists are cleared here.
 */
AcctScheduler::~AcctScheduler()
{
    activeuserlist.clear();
    passiveuserlist.clear();
}

/** The method adds an user to the user lists. An user with an acct interim
 * interval is added to the activeuserlist, an user
 * without this interval is added to passiveuserlist.
 * @param user A pointer to an object from the class UserAcct.
 */
void AcctScheduler::addUser(const UserAcct &user)
{
  StdLogger log("RADIUS-PLUGIN [PLUGIN-ADDUSR]");
  std::pair<std::map<string, UserAcct>::iterator,bool> res;
  if (user.getAcctInterimInterval()==0) {
    res = this->passiveuserlist.insert(make_pair(user.getKey(),user));
  } else {
    res = this->activeuserlist.insert(make_pair(user.getKey(),user));
  }
  if(!res.second) {
    log() << "Fail to add user (key='" << user.getKey() << "') to any map!" << "\n";
  }
}

/** The method deletes an user from the user lists. Before
 * the user is deleted the status file is parsed for the sent and received bytes
 * and the stop accounting ticket is send to the server.
 * @param context The plugin context as an object from the class PluginContext.
 * @param user A pointer to an object from the class UserAcct
 */
void AcctScheduler::delUser(PluginContext * context, UserAcct *user)
{
    uint64_t bytesin=0, bytesout=0;
    StdLogger log("RADIUS-PLUGIN [PLUGIN-DELUSR]", context->getVerbosity());
    log.debug() << "prepare to send del ticket and del user...\n";

    //get the sent and received bytes
    this->parseStatusFile(context, &bytesin, &bytesout,user->getStatusFileKey().c_str());

    user->setBytesIn(bytesin & 0xFFFFFFFF);
    user->setBytesOut(bytesout & 0xFFFFFFFF);
    user->setGigaIn(bytesin >> 32);
    user->setGigaOut(bytesout >> 32);

    log.debug() << "Got accounting data from file, CN: " << user->getCommonname()
                << " in: " << user->getBytesIn()
                << " out: " << user->getBytesOut() << "\n";

    //send the stop ticket
    if (user->sendStopPacket(context)==0) {
      log.debug() << "Stop packet was sent. CN: " << user->getCommonname() << ".\n";
    }
    else {
      log() << "Error on sending stop packet.\n";
    }

    if (user->getAcctInterimInterval()==0) {
        passiveuserlist.erase(user->getKey());
        log() << "erase from passive user map\n";
    } else {
        activeuserlist.erase(user->getKey());
        log() << "erase from active user map\n";
    }
}


/** The method deletes all users from the user lists. Before
 * the user is deleted the status file is parsed for the sent and received bytes
 * and the stop accounting ticket is send to the server.
 * @param context The plugin context as an object from the class PluginContext.
 */
void AcctScheduler::delallUsers(PluginContext * context)
{
  StdLogger log("RADIUS-PLUGIN [PLUGIN-DELUSER-ALL]", context->getVerbosity());
  log.debug() << "preparing...\n";

    map<string, UserAcct>::iterator iter1, iter2;
    iter1=activeuserlist.begin();
    iter2=activeuserlist.end();

    while (iter1!=iter2) {
      try {
        this->delUser(context,&(iter1->second));
      } catch (std::exception &e) {
        log() << "Got error while deleting user: " << e.what() << "\n";
      }
      catch (...) {
        log() << "Got error while deleting user\n";
      }
      ++iter1;
    }
    log.debug() << "done\n";
}


/** The accounting method. When the method is called it
 * searches for users in activeuserlist for users who need an update.
 * If a user is found the sent and received bytes are read from the
 * OpenVpn status file.
 * @param context The plugin context as an object from the class PluginContext.
 */

void AcctScheduler::doAccounting(PluginContext * context)
{
    time_t t;
    uint64_t bytesin=0, bytesout=0;
    map<string, UserAcct>::iterator iter1, iter2;

    StdLogger log("RADIUS-PLUGIN [PLUGIN-ACCTUPD-ALL]", context->getVerbosity());
    // log.debug() << "preparing...\n";

    iter1=activeuserlist.begin();
    iter2=activeuserlist.end();

    while (iter1!=iter2)
    {
        //get the time
        time(&t);
        //if the user needs an update
        if ( t>=iter1->second.getNextUpdate())
        {
          log.debug() << "UPD user: " << iter1->second.getStatusFileKey() << "\n";
          // << " Scheduler: Update for User " << iter1->second.getUsername() << ".\n";

            this->parseStatusFile(context, &bytesin, &bytesout,iter1->second.getStatusFileKey().c_str());
            iter1->second.setBytesIn(bytesin & 0xFFFFFFFF);
            iter1->second.setBytesOut(bytesout & 0xFFFFFFFF);
            iter1->second.setGigaIn(bytesin >> 32);
            iter1->second.setGigaOut(bytesout >> 32);

            if(iter1->second.sendUpdatePacket(context) == 0) {
              log.debug() << "Sent update packet for User " << iter1->second.getUsername()
                          << " (" << iter1->second.getStatusFileKey() << ")\n";
            } else {
              log() << "Fail while send update packet for User " << iter1->second.getUsername()
                    << " (" << iter1->second.getStatusFileKey() << ")\n";
            }

            //calculate the next update
            iter1->second.setNextUpdate(iter1->second.getNextUpdate() +
                                        iter1->second.getAcctInterimInterval());
        }
        iter1++;
    }
}


/**The method parses the status file for accounting information. It reads the bytes sent
 * and received from the status file. It finds the values about the commonname. The method will
 * only work if there are no changes in the structure of the status file.
 * The method was tested with OpenVpn 2.0.
 * @param context The plugin context as an object from the class PluginContext.
 * @param bytesin An int pointer for the received bytes.
 * @param bytesout An int pointer for the sent bytes.
 * @param key  A key which identifies the row in the statusfile, it looks like: "commonname,ip:port".
 */
void AcctScheduler::parseStatusFile(PluginContext *context, uint64_t *bytesin,
                                    uint64_t *bytesout, string key)
{
  StdLogger log("RADIUS-PLUGIN [PLUGIN-STATUSFILE]", context->getVerbosity());

    char line[512], newline[512];
    memset(newline, 0, 512);

    //open the status file to read
    ifstream file(context->conf.getStatusFile().c_str(), ios::in);
    if (file.is_open())
    {
      log.debug() << "Parsing status file...\n";

        //find the key, is delimited with a ',' from the informations

        //loop until the name is found, there is no delimiter, the string
        //"ROUTING TABLE" is found or EOF

        do {
            file.getline(line, 512);
        } while (line != NULL &&
                 strncmp(line, key.c_str(), key.length()) != 0 &&
                 strcmp(line, "ROUTING TABLE") != 0 &&
                 file.eof() == false);

        //the information is behind the next delimiters
        if (line!=NULL && strncmp(line,key.c_str(),key.length())==0) {
            memcpy(newline, line+key.length(), strlen(line)-key.length()+1);
            *bytesin=strtoull(strtok(newline,","),NULL,10);
            *bytesout=strtoull(strtok(NULL,","),NULL,10);
        } else {
          log() << "No accounting data was found for "<< key << " in file "
                << context->conf.getStatusFile() << "\n";
        }
        file.close();
    }
    else {
      log() << "Statusfile "<< context->conf.getStatusFile() <<" couldn't be opened.\n";
    }
}


/** The method finds an user.
 * @param key The commonname of the user to find.
 * @return A poniter to an object of the class UserAcct.
 */
UserAcct * AcctScheduler::findUser(const std::string &key)
{
  std::map<std::string, UserAcct>::iterator iter;
  iter = activeuserlist.find(key);
  if (iter != activeuserlist.end()) {
    return &(iter->second);
  }
  iter = passiveuserlist.find(key);
  if (iter != passiveuserlist.end()) {
    return &(iter->second);
  }

  return NULL;
}
