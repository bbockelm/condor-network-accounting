/***************************************************************
 *
 * Copyright (C) 1990-2007, Condor Team, Computer Sciences Department,
 * University of Wisconsin-Madison, WI.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

#include "condor_common.h"
#include "condor_daemon_core.h"
#include "condor_debug.h"
#include "condor_td.h"
#include "extArray.h"
#include "condor_classad.h"
#include "MyString.h"
#include "condor_attributes.h"
#include "condor_ftp.h"

// smart structure
class ThreadArg
{
	public:
		ThreadArg(int prot, TransferRequest *tr) { 
			protocol = prot; 
			treq = tr;
		}

		~ThreadArg() {};

		int protocol;
		TransferRequest *treq;
};

// This handler is called when a client wishes to write files from the
// transferd's storage.
int
TransferD::write_files_handler(int cmd, Stream *sock) 
{
	ReliSock *rsock = (ReliSock*)sock;
	MyString capability;
	int protocol = FTP_UNKNOWN;
	TransferRequest *treq = NULL;
	MyString fquser;
	static int transfer_reaper_id = -1;
	ThreadArg *thread_arg;
	int tid;
	ClassAd reqad;
	ClassAd respad;

	cmd = cmd; // quiet the compiler.

	dprintf(D_ALWAYS, "Got TRANSFERD_WRITE_FILES!\n");

	/////////////////////////////////////////////////////////////////////////
	// make sure we are authenticated
	/////////////////////////////////////////////////////////////////////////
	if( ! rsock->triedAuthentication() ) {
		CondorError errstack;
		if( ! SecMan::authenticate_sock(rsock, WRITE, &errstack) ) {
			// we failed to authenticate, we should bail out now
			// since we don't know what user is trying to perform
			// this action.
			// TODO: it'd be nice to print out what failed, but we
			// need better error propagation for that...
			errstack.push( "TransferD::setup_transfer_request_handler()", 42,
				"Failure to register transferd - Authentication failed" );
			dprintf( D_ALWAYS, "setup_transfer_request_handler() "
				"aborting: %s\n",
				errstack.getFullText() );
			refuse( rsock );
			return CLOSE_STREAM;
		} 
	}

	fquser = rsock->getFullyQualifiedUser();


	/////////////////////////////////////////////////////////////////////////
	// Check to see if the capability the client tells us is something that
	// we have knowledge of. We ONLY check the capability and not the
	// identity of the person in question. This allows people of different
	// identities to write files here as long as they had the right 
	// capability. While this might not sound secure, they STILL had to have
	// authenticated as someone this daemon trusts. 
	// Similarly, check the protocol it wants to use as well as ensure that
	// the direction the transfer request was supposed to be is being honored.
	/////////////////////////////////////////////////////////////////////////
	rsock->decode();

	// soak the request ad from the client about what it wants to transfer
	reqad.initFromStream(*rsock);
	rsock->end_of_message();

	reqad.LookupString(ATTR_TREQ_CAPABILITY, capability);

	rsock->encode();

	// do I know of such a capability?
	if (m_treqs.lookup(capability, treq) != 0) {
		// didn't find it. Log it and tell them to leave and close up shop
		respad.Assign(ATTR_TREQ_INVALID_REQUEST, TRUE);
		respad.Assign(ATTR_TREQ_INVALID_REASON, "Invalid capability!");
		respad.put(*rsock);
		rsock->end_of_message();

		dprintf(D_ALWAYS, "Client identity '%s' tried to write some files "
			"using capability '%s', but there was no such capability. "
			"Access denied.\n", fquser.Value(), capability.Value());
		return CLOSE_STREAM;
	}

	reqad.LookupInteger(ATTR_TREQ_FTP, protocol);

	// am I willing to use this protocol?
	switch(protocol) {
		case FTP_CFTP: // FileTrans protocol, I'm happy.
			break;

		default:
			respad.Assign(ATTR_TREQ_INVALID_REQUEST, TRUE);
			respad.Assign(ATTR_TREQ_INVALID_REASON, 
				"Invalid file transfer protocol!");
			respad.put(*rsock);
			rsock->end_of_message();

			dprintf(D_ALWAYS, "Client identity '%s' tried to write some files "
				"using protocol '%d', but I don't support that protocol. "
				"Access denied.\n", fquser.Value(), protocol);
			return CLOSE_STREAM;
	}

	// nsure that this transfer request was of the uploading variety
	if (treq->get_direction() != FTPD_UPLOAD) {
			respad.Assign(ATTR_TREQ_INVALID_REQUEST, TRUE);
			respad.Assign(ATTR_TREQ_INVALID_REASON, 
				"Transfer Request was not an uploading request!");
			respad.put(*rsock);
			rsock->end_of_message();

			dprintf(D_ALWAYS, "Client identity '%s' tried to write some files "
				"to a transfer request that wasn't expecting to be written. "
				"Access denied.\n", fquser.Value());
	}

	/////////////////////////////////////////////////////////////////////////
	// Tell the client everything was ok.
	/////////////////////////////////////////////////////////////////////////

	respad.Assign(ATTR_TREQ_INVALID_REQUEST, FALSE);
	respad.put(*rsock);
	rsock->end_of_message();

	/////////////////////////////////////////////////////////////////////////
	// Set up a thread (a process under unix) to read ALL of the job files
	// for all of the ads in the TransferRequest.
	/////////////////////////////////////////////////////////////////////////

	// now create a thread, passing in the sock, which uses the file transfer
	// object to accept the files.

	if (transfer_reaper_id == -1) {
		// only set this up ONCE so each and every thread gets one.
		transfer_reaper_id = daemonCore->Register_Reaper(
						"write_files_reaper",
						(ReaperHandlercpp) &TransferD::write_files_reaper,
						"write_files_reaper",
						this
						);
	}

	thread_arg = new ThreadArg(protocol, treq);

	// Start a new thread (process on Unix) to do the work
	tid = daemonCore->Create_Thread(
		(ThreadStartFunc)&TransferD::write_files_thread,
		(void *)thread_arg,
		rsock,
		transfer_reaper_id
		);
	
	if (tid == FALSE) {
		// XXX How do I handle this failure?
	}


	// associate the tid with the request so I can deal with it propery in
	// the reaper
	m_client_to_transferd_threads.insert(tid, treq);

	// The stream is inherited to the thread, who does the transfer and
	// finishes the protocol, but in the parent, I'm closing it.
	return CLOSE_STREAM;
}

// The function occurs in a seperate thread or process
int
TransferD::write_files_thread(void *targ, Stream *sock)
{	
	ThreadArg *thread_arg = (ThreadArg*)targ;
	ReliSock *rsock = (ReliSock*)sock;
	TransferRequest *treq = NULL;
	// int protocol;
	SimpleList<ClassAd*> *jad_list = NULL;
	ClassAd *jad = NULL;
	int cluster, proc;
	int old_timeout;
	int result;
	ClassAd respad;

	// XXX This is a damn dirty hack whose solution resides in implementing
	// a checksum for the files.
	// Now we sleep here for one second.  Why?  So we are certain
	// to transfer back output files even if the job ran for less
	// than one second. This is because:
	// stat() can't tell the difference between:
	//   1) A job starts up, touches a file, and exits all in one second
	//   2) A job starts up, doesn't touch the file, and exits all in one
	//    second
	// So if we force the start time of the job to be one second later than
	// the time we know the files were written, stat() should be able
	// to perceive what happened, if anything.

	sleep(1);

	// even though I'm in a new process, I got here either through forking
	// or through a thread, so this memory is a copy.
	// protocol = thread_arg->protocol;
	treq = thread_arg->treq;
	delete thread_arg;

	// XXX deal with protocol value.

	////////////////////////////////////////////////////////////////////////
	// Sort the classads (XXX maybe put at a higher level in the protocol)
	////////////////////////////////////////////////////////////////////////
	
	// XXX TODO

	////////////////////////////////////////////////////////////////////////
	// Do the transfer.
	////////////////////////////////////////////////////////////////////////

	// file transfers can take a long time....
	old_timeout = rsock->timeout(60 * 60 * 8);

	jad_list = treq->todo_tasks();

	while(jad_list->Next(jad)) {
		FileTransfer ftrans;

		jad->LookupInteger(ATTR_CLUSTER_ID, cluster);
		jad->LookupInteger(ATTR_PROC_ID, proc);
		dprintf( D_ALWAYS, "TransferD::write_files_thread(): "
			"Transferring fileset for job %d.%d\n",
				cluster, proc);

		result = ftrans.SimpleInit(jad, true, true, rsock);
		if ( !result ) {
			dprintf( D_ALWAYS, "TransferD::write_files_thread(): "
				"failed to init file transfer for job %d.%d \n",
				cluster, proc );

			respad.Assign(ATTR_TREQ_INVALID_REQUEST, TRUE);
			respad.Assign(ATTR_TREQ_INVALID_REASON, 
				"FileTransfer Object failed to SimpleInit.");
			respad.put(*rsock);
			rsock->end_of_message();

			rsock->timeout(old_timeout);

			return EXIT_FAILURE;
		}

		ftrans.setPeerVersion(treq->get_peer_version().Value());

		// We're "downloading" from the client to here.
		result = ftrans.DownloadFiles();
		if ( !result ) {

			dprintf( D_ALWAYS, "TransferD::write_files_thread(): "
				"failed to transfer files for job %d.%d \n",
				cluster, proc );

			respad.Assign(ATTR_TREQ_INVALID_REQUEST, TRUE);
			respad.Assign(ATTR_TREQ_INVALID_REASON, 
				"FileTransfer Object failed to download.");
			respad.put(*rsock);
			rsock->end_of_message();

			rsock->timeout(old_timeout);
			return EXIT_FAILURE;
		}
	}

	rsock->end_of_message();

	//////////////////////////////////////////////////////////////////////////
	// Now that the file transfer is done, tell the client everything is ok.
	//////////////////////////////////////////////////////////////////////////

	dprintf(D_ALWAYS, "Informing client of finished transfer.\n");

	rsock->encode();

	respad.Assign(ATTR_TREQ_INVALID_REQUEST, FALSE);

	// This response ad to the client will contain:
	//
	//	ATTR_TREQ_INVALID_REQUEST (set to false)
	//
	respad.put(*rsock);
	rsock->end_of_message();

	delete rsock;

	return EXIT_SUCCESS;
}

int
TransferD::write_files_reaper(int tid, int exit_status)
{
	TransferRequest *treq = NULL;
	MyString str;
	ClassAd result;
	int exit_code;
	int signal;

	dprintf(D_ALWAYS, "TransferD::write_files_reaper(): "
		"A file transfer into the transferd has completed: "
		"tid %d, status: %d\n",
		tid, exit_status);
	
	/////////////////////////////////////////////////////////////////////////
	// Consistancy check to make sure I asked to do the transfer
	/////////////////////////////////////////////////////////////////////////
	if (m_client_to_transferd_threads.lookup((long)tid, treq) != 0) 
	{
		EXCEPT("TransferD::write_files_reaper(): "
			"Programmer error: I have no record of it! ");
	}
	// remove it from the thread hash now that I'm dealing with it.
	m_client_to_transferd_threads.remove((long)tid);

	/////////////////////////////////////////////////////////////////////////
	// Determine status ad.
	/////////////////////////////////////////////////////////////////////////

	// The schedd will know who I'm talking about cause it has the
	// same capability for this transfer request.
	str = treq->get_capability();
	result.Assign(ATTR_TREQ_CAPABILITY, str);

	// figure out what the exit_status means and encode it into the result ad
	if (WIFSIGNALED(exit_status)) {
		signal = WTERMSIG(exit_status);
		dprintf(D_ALWAYS, "Thread exited with signal: %d\n", signal);

		result.Assign(ATTR_TREQ_UPDATE_STATUS, "NOT OK");
		str.sprintf("Died with signal %d", signal);
		result.Assign(ATTR_TREQ_UPDATE_REASON, str);
		result.Assign(ATTR_TREQ_SIGNALED, TRUE);

	} else {
		exit_code = WEXITSTATUS(exit_status);
		dprintf(D_ALWAYS, "Thread exited with exit code: %d\n", exit_code);
		switch(exit_code) {
			case EXIT_SUCCESS:
				result.Assign(ATTR_TREQ_UPDATE_STATUS, "OK");
				result.Assign(ATTR_TREQ_UPDATE_REASON, "Successful transfer");
				result.Assign(ATTR_TREQ_SIGNALED, FALSE);
				result.Assign(ATTR_TREQ_EXIT_CODE, exit_code);

				break;

			default:
				result.Assign(ATTR_TREQ_UPDATE_STATUS, "NOT OK");
				str.sprintf("Exited with bad exit code %d", exit_code);
				result.Assign(ATTR_TREQ_UPDATE_REASON, str);
				result.Assign(ATTR_TREQ_SIGNALED, FALSE);
				result.Assign(ATTR_TREQ_EXIT_CODE, exit_code);

				break;
		}
	}

	/////////////////////////////////////////////////////////////////////////
	// Call back schedd with status ad. If failed, don't repeat
	// it, the schedd will send another transfer request if it wants it
	// done again.
	/////////////////////////////////////////////////////////////////////////
	m_update_sock->encode();
	result.put(*m_update_sock);
	m_update_sock->end_of_message();

	// now remove the treq forever from our knowledge
	m_treqs.remove(treq->get_capability());

	// bye bye.
	delete treq;

	// Now, if the hash is empty, mark it down as the start of our inactivity
	// timer
	if (m_treqs.getNumElements() == 0) {
		dprintf(D_ALWAYS, 
			"Last transfer request handled. Becoming inactive.\n");
		m_inactivity_timer = time(NULL);
	}

	return TRUE;
}






