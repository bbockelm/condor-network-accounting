/***************************Copyright-DO-NOT-REMOVE-THIS-LINE**
  *
  * Condor Software Copyright Notice
  * Copyright (C) 1990-2006, Condor Team, Computer Sciences Department,
  * University of Wisconsin-Madison, WI.
  *
  * This source code is covered by the Condor Public License, which can
  * be found in the accompanying LICENSE.TXT file, or online at
  * www.condorproject.org.
  *
  * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  * AND THE UNIVERSITY OF WISCONSIN-MADISON "AS IS" AND ANY EXPRESS OR
  * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  * WARRANTIES OF MERCHANTABILITY, OF SATISFACTORY QUALITY, AND FITNESS
  * FOR A PARTICULAR PURPOSE OR USE ARE DISCLAIMED. THE COPYRIGHT
  * HOLDERS AND CONTRIBUTORS AND THE UNIVERSITY OF WISCONSIN-MADISON
  * MAKE NO MAKE NO REPRESENTATION THAT THE SOFTWARE, MODIFICATIONS,
  * ENHANCEMENTS OR DERIVATIVE WORKS THEREOF, WILL NOT INFRINGE ANY
  * PATENT, COPYRIGHT, TRADEMARK, TRADE SECRET OR OTHER PROPRIETARY
  * RIGHT.
  *
  ****************************Copyright-DO-NOT-REMOVE-THIS-LINE**/

#ifndef CONDOR_VM_GAHP_SERVER_H
#define CONDOR_VM_GAHP_SERVER_H

#include "condor_common.h"
#include "condor_classad.h"
#include "../condor_daemon_core.V6/condor_daemon_core.h"
#include "condor_distribution.h"
#include "gahp_common.h"
#include "HashTable.h"
#include "MyString.h"
#include "condor_string.h"
#include "condor_arglist.h"
#include "vm_gahp_request.h"

class VMGahpRequest;
class VMGahpServer : public Service {
	public:
		VMGahpServer(const char *vmgahpserver, const char* vmgahpconfig, 
				const char *vmtype, ClassAd* job_ad);
		virtual ~VMGahpServer();

		bool startUp(Env *job_env, const char* job_iwd, int nice_inc, 
				FamilyInfo *family_info);
		bool cleanup(void);

		void setPollInterval(unsigned int interval);
		unsigned int getPollInterval(void);

		void cancelPendingRequest(int req_id);
		bool isPendingRequest(int req_id);
		VMGahpRequest *findRequestbyReqId(int req_id);

		bool nowPending(const char *command, const char *args, 
				VMGahpRequest *req);

		int numOfPendingRequests(void);

		// Result will be stored in m_pending_result of VMGahpRequest
		void getPendingResult(int req_id, bool is_blocking);

		// Return the pid of vmgahp
		int getVMGahpServerPid(void) {return m_vmgahp_pid;}

		// Return VM type 
		const char* getVMType(void) {return m_vm_type.Value();}

		bool isSupportedCommand(const char *command);
		bool isSupportedVMType(const char *vmtype);

		bool publishVMClassAd(const char *workingdir);

		void setVMid(int vm_id);

		// Print system error message to dprintf
		void printSystemErrorMsg(void);

		// Error message during startUp
		MyString start_err_msg;

	protected:
		bool read_argv(Gahp_Args &g_args);
		bool read_argv(Gahp_Args *g_args) { return read_argv(*g_args);}
		bool write_line(const char *command);
		bool write_line(const char *command, int req, const char *args);
		int pipe_ready();
		int err_pipe_ready();
		int poll();
		void poll_real_soon();

		int new_reqid(void);

		// Methods for VMGahp commands
		bool command_version(void);
		bool command_commands(void);
		bool command_support_vms(void);
		bool command_async_mode_on(void);
		bool command_quit(void);

	private:
		int m_is_initialized;
		bool m_is_cleanuped;
		bool m_is_async_mode;
		bool m_send_all_classad;

		// Does Starter log include log from vmgahp?
		bool m_include_gahp_log;

		MyString m_vm_type;
		MyString m_vmgahp_server;
		MyString m_vmgahp_config;
		ClassAd *m_job_ad;
		MyString m_workingdir;

		int m_vmgahp_pid;
		int m_vm_id;
		int m_vmgahp_readfd;
		int m_vmgahp_writefd;
		int m_vmgahp_errorfd;

		HashTable<int,VMGahpRequest*> m_request_table;

		unsigned int m_pollInterval;
		int m_poll_tid;
		bool m_poll_pending;
		int m_stderr_tid;

		int m_next_reqid;
		bool m_rotated_reqids;

		MyString m_vmgahp_version;
		MyString m_vmgahp_error_buffer;
		StringList m_commands_supported;
		StringList m_vms_supported;

		void killVM(void);
};

#endif //CONDOR_VM_GAHP_SERVER_H