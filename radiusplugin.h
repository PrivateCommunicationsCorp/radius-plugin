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

#ifndef _PLUGIN_H_
#define _PLUGIN_H_


#include <stdio.h>
#include <string>
#include <ostream>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <dlfcn.h>
#include <syslog.h>
#include <time.h>
#include <fstream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <time.h>
#include<sys/ipc.h>
#include<sys/msg.h>
#include<sys/wait.h>
#include<sys/errno.h>
#include "RadiusClass/RadiusAttribute.h"
#include "RadiusClass/RadiusPacket.h"
#include "RadiusClass/RadiusServer.h"
#include "RadiusClass/RadiusServer.h"
#include "RadiusClass/RadiusConfig.h"
#include "RadiusClass/radius.h"
#include "openvpn-plugin.h"
#include "PluginContext.h"
#include "UserPlugin.h"
#include "UserAuth.h"
#include "UserAcct.h"
#include "AcctScheduler.h"
#include "Exception.h"
#include "AccountingProcess.h"
#include "AuthenticationProcess.h"

using namespace std;

/** This file defines some constants and some functions. The constants and functions
 * are the original function from openvpn auth-pam plugin.*/

enum MiscConstants {
  logVerbThreshold = 5,
};

#define DEBUG(verb) ((verb) >= 5) /**< A macro for the debugging.*/

/* Command codes for foreground -> background communication */
#define COMMAND_VERIFY 0 /**<The verify command for the background process.*/
#define COMMAND_EXIT   1 /**<The ecit command for the background process.*/
#define ADD_USER       2 /**<The add user command for the background process.*/
#define DEL_USER       3 /**<The del user command for the background process.*/

/* Response codes for background -> foreground communication */
#define RESPONSE_INIT_SUCCEEDED   10    /**< Response code from background process to foreground procce.*/
#define RESPONSE_INIT_FAILED      11    /**< Response code from background process to foreground procce.*/
#define RESPONSE_SUCCEEDED 12           /**< Response code from background process to foreground procce.*/
#define RESPONSE_FAILED    13           /**< Response code from background process to foreground procce.*/



/** A struct for additional command line arguments.*/
struct name_value {
  const char *name;     /**<The name of name value pair.*/
  const char *value;    /**<The value of the name value pair.*/
};


#define N_NAME_VALUE 16 /**<The array length for data in the value list.*/

/** A list for the struct name_value.*/
struct name_value_list {
  int len;                                  /**<The length of the list.*/
  struct name_value data[N_NAME_VALUE];     /**<The data of the list.*/
};


const char * get_env (const char *name, const char *envp[]);
int string_array_len (const char *array[]);
void close_fds_except (int keep);
void set_signals (void);
string createSessionId (UserPlugin *);
void get_user_env(PluginContext *, const int type,const char *envp[], UserPlugin *);
void * auth_user_pass_verify(void *);
void write_auth_control_file(PluginContext *, string filename, char c);
string getTime();


class StdLogger
{
public:
  // default openvpn verb = 1
  StdLogger(const std::string &log_tag, int cur_verbosity = 1);
  ~StdLogger();
  void init_verbosity(int cur_verbosity);

  void flush();

  std::ostream &operator()();
  std::ostream &debug();

private:
  const static std::size_t time_buf_len_ = 32;

  static const char* date_fmt_;

  std::string tag_;
  int verb_;
  bool debug_allowed_;
  char buf_[time_buf_len_];

  std::ostream &log_;
  std::ostream null_out_;

  const char *time_();
};


#endif //_PLUGIN_H_
