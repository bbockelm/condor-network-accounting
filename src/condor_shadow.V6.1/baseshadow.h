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


#ifndef BASESHADOW_H
#define BASESHADOW_H

#include "condor_common.h"
#include "condor_daemon_core.h"
#include "condor_classad.h"
#include "shadow_user_policy.h"
#include "write_user_log.h"
#include "exit.h"
#include "internet.h"
#include "../condor_schedd.V6/qmgr_job_updater.h"
#include "condor_update_style.h"

/* Forward declaration to prevent loops... */
class RemoteResource;

/** This is the base class for the various incarnations of the Shadow.<p>

	If you want to change something related to the shadow, 
	make sure you know how these classes interact.  If it's a general
	shadow thing, you very well may want to add it to this class.  
	However, if it is specific to one remote resource, you want to
	look at RemoteResource.  If it is single, MPI
	specific, make the change in that derived class. <p>

	More to come...<p>

	This class has some pure virtual functions, so it's an abstract
	class.  You therefore can't instantiate it; you must instantiate
	one of its dervide classes.<p>

	Based heavily on code by Todd Tannenbaum.
	@see RemoteResource
	@author Mike Yoder
*/
class BaseShadow : public Service 
{
 public:
		/// Default constructor
	BaseShadow();

		/// Destructor, it's virtual
	virtual ~BaseShadow();

		/** This is the basic initialization function.

			It does the following:
			<ul>
			 <li>Puts the args into class data members
			 <li>Stores the classAd, checks its info, and pulls
			     everything we care about out of the ad and into class
			     data members.
			 <li>calls config()
			 <li>calls initUserLog()
			 <li>registers handleJobRemoval on SIGUSR1
			</ul>
			It should be called right after the constructor.
			@param job_ad The ClassAd for this job.
			@param schedd_addr The sinful string of the schedd
		*/
	void baseInit( ClassAd *job_ad, const char* schedd_addr, const char *xfer_queue_contact_info );

		/** Everyone must make an init with a bunch of parameters.<p>
			This function is <b>pure virtual</b>.
		 */
	virtual void init( ClassAd* job_ad, const char* schedd_addr, const char *xfer_queue_contact_info ) = 0;

		/** Shadow should spawn a new starter for this job.
			This function is <b>pure virtual</b>.
		 */
	virtual void spawn( void ) = 0;

	bool waitingToUpdateSchedd() { return m_cleanup_retry_tid != -1; }

		/** Shadow should attempt to reconnect to a disconnected
			starter that might still be running for this job.  
			This function is <b>pure virtual</b>.
		 */
	virtual void reconnect( void ) = 0;

		/** Does the shadow support reconnect for this job? 
		 */
	virtual bool supportsReconnect( void ) = 0;

		/** Given our config parameters, figure out how long we should
			delay until our next attempt to reconnect.
		*/
	int nextReconnectDelay( int attempts );

		/**	Called by any part of the shadow that finally decides the
			reconnect has completely failed, we should give up, try
			one last time to release the claim, write a UserLog event
			about it, and exit with a special status. 
			@param reason Why we gave up (for UserLog, dprintf, etc)
		*/
	void reconnectFailed( const char* reason ); 

	virtual bool shouldAttemptReconnect(RemoteResource *) { return true;};

		/** Here, we param for lots of stuff in the config file.  Things
			param'ed for are: SPOOL, FILESYSTEM_DOMAIN, UID_DOMAIN, 
			USE_AFS, USE_NFS, and CKPT_SERVER_HOST.
		*/
	virtual void config();

		/** Everyone should be able to shut down.<p>
			@param reason The reason the job exited (JOB_BLAH_BLAH)
		 */
	virtual void shutDown( int reason );

		/** Graceful shutdown method.  This is virtual so each kind of
			shadow can do the right thing.
		 */
	virtual void gracefulShutDown( void ) = 0;

		/** Get name of resource job is running on.  This is for
			informational purposes only.  It may be empty if there
			is no appropriate answer (and function will return false).
		*/
	virtual bool getMachineName( MyString &machineName );

		/** Put this job on hold, if requested, notify the user about
			it.  This function does _not_ exit.  Use holdJobAndExit()
			instead to exit with appropriate status so that the
			schedd actually puts the job on hold.
			This uses the virtual cleanUp() method to take care of any
			universe-specific code before we exit.
			@param reason String describing why the job is held
		*/
	virtual void holdJob( const char* reason, int hold_reason_code, int hold_reason_subcode );

		/** Put this job on hold, if requested, notify the user about
			it and exit with the appropriate status so that the
			schedd actually puts the job on hold.
			This uses the virtual cleanUp() method to take care of any
			universe-specific code before we exit.
			@param reason String describing why the job is held
		*/
	void holdJobAndExit( const char* reason, int hold_reason_code, int hold_reason_subcode );

		/** Remove the job from the queue, if requested, notify the
			user about it, and exit with the appropriate status so
			that the schedd actually removes the job.<p>
			This uses the virtual cleanUp() method to take care of any
			universe-specific code before we exit.
			@param reason String describing why the job is removed
		*/
	virtual void removeJob( const char* reason );

		/** The job exited, but we want to put it back in the job
			queue so it will run again.  If requested, notify the user about
			it, and exit with the appropriate status so that the
			schedd doesn't remove the job from the queue.<p>
			This uses the virtual cleanUp() method to take care of any
			universe-specific code before we exit.
			@param reason String describing why the job is requeued
		*/
	void requeueJob( const char* reason );

		/** The job exited, and it's ready to leave the queue.  If
			requested, notify the user about it, log a terminate
			event, update the job queue, etc.<p>
			This uses the virtual cleanUp() method to take care of any
			universe-specific code before we exit.
			The optional style parameter dictates if the job terminated of
			its own accord or if the shadow had been born with a 
			previously terminated job classad.
		*/
	void terminateJob( update_style_t kind = US_NORMAL );

		/** The job exited, but it _isn't_ ready to leave the queue.

			For example, the job segfaulted and didn't produce all of the
			output files specifically labeled in transfer_output_files, so
			this causes file transfer to fail which puts the job on hold
			(as of 7.4.4). However, the user would like to write periodic or
			exit policies about the job and for that we need to know exactly
			how the job exited. So this call places how the job exited into
			the jobad, but doesn't write any events about it.
		*/
	void mockTerminateJob( MyString exit_reason, bool exited_by_signal, 
		int exit_code, int exit_signal, bool core_dumped );

		/** Set a timer to call terminateJob() so we retry
		    our attempts to update the job queue etc.
		*/
	void retryJobCleanup( void );

		/// DaemonCore timer handler to actually do the retry.
	int retryJobCleanupHandler( void );

		/** The job exited but it's not ready to leave the queue.  
			We still want to log an evict event, possibly email the
			user, etc.  We want to update the job queue, but not with
			anything about how the job was killed.<p>
			This uses the virtual cleanUp() method to take care of any
			universe-specific code before we exit.
		*/
	void evictJob( int reason );

		/** The total number of bytes sent over the network on
			behalf of this job.
			Each shadow class should override this function and
			do whatever it needs to do.
			The default implementation in the base just returns
			zero bytes.
			@return number of bytes sent over the network.
		*/
	virtual float bytesSent() { return 0.0; }

		/** The total number of bytes received over the network on
			behalf of this job.
			Each shadow class should override this function and
			do whatever it needs to do.
			The default implementation in the base just returns
			zero bytes.
			@return number of bytes sent over the network.
		*/
	virtual float bytesReceived() { return 0.0; }

	virtual int getExitReason( void ) = 0;

	virtual bool claimIsClosing( void ) = 0;

	static void CommitSuspensionTime(ClassAd *jobAd);

		/** Initializes the user log.  'Nuff said. 
		 */
	void initUserLog();

		/** Change to the 'Iwd' directory.  Send email if problem.
			@return 0 on success, -1 on failure.
		*/
	int cdToIwd();

		/** Remove this job.  This function is <b>pure virtual</b>.

		 */
	virtual int handleJobRemoval(int sig) = 0;

	/**
	 * Handle the situation where the job is to be suspended
	 */
	virtual int JobSuspend(int sig)=0;
	
	/**
	 * Handle the situation where the job is to be continued.
	 */
	virtual int JobResume(int sig)=0;
	
		/** Update this job.
		 */
	int handleUpdateJobAd(int sig);

		/** This function returns a file pointer that one can 
			write an email message into.
			@return A mail message file pointer.
		*/
	FILE* emailUser( const char *subjectline );

		/** This is used to tack on something (like "res #") 
			after the header and before the text of a dprintf
			message.
		*/
	virtual void dprintf_va( int flags, const char* fmt, va_list args );

		/** A local dprintf maker that uses dprintf_va...
		 */
	void dprintf( int flags, const char* fmt, ... ) CHECK_PRINTF_FORMAT(3,4);

		/// Returns the jobAd for this job
	ClassAd *getJobAd() { return jobAd; }
		/// Returns this job's cluster number
	int getCluster() { return cluster; }
		/// Returns this job's proc number
	int getProc() { return proc; }
		/// Returns this job's GlobalJobId string
	const char* getGlobalJobId() { return gjid; }
		/// Returns the spool
	char *getSpool() { return spool; }
		/// Returns the schedd address
	char *getScheddAddr() { return scheddAddr; }
        /// Returns the current working dir for the job
    char const *getIwd() { return iwd.Value(); }
        /// Returns the owner of the job - found in the job ad
    char const *getOwner() { return owner.Value(); }
		/// Returns true if job requests graceful removal
	bool jobWantsGracefulRemoval();

		/// Called by EXCEPT handler to log to user log
	static void log_except(const char *msg);

	//set by pseudo_ulog() to suppress "Shadow exception!"
	bool exception_already_logged;

		/// Used by static and global functions to access shadow object
	static BaseShadow* myshadow_ptr;

		/** Method to handle command from the starter to update info 
			about the job.  Each kind of shadow needs to handle this
			differently, since, for example, cpu usage is stored in
			the remote resource object, and in mpi, we've got a whole
			list of those, while in the unishadow, we've only got 1.
		*/
	virtual int updateFromStarter(int command, Stream *s) = 0;

		/** Method to process an update from the starter with info 
			about the job.  This is shared by both the daemoncore
			command handler and the CONDOR_register_job_info RSC. 
		 */
	virtual int updateFromStarterClassAd(ClassAd* update_ad) = 0;

	virtual int64_t getImageSize( int64_t & memory_usage, int64_t & rss, int64_t & pss ) = 0;

	virtual int getDiskUsage( void ) = 0;

	virtual struct rusage getRUsage( void ) = 0;

	virtual bool setMpiMasterInfo( char* str ) = 0;

		/** Connect to the job queue and update all relevent
			attributes of the job class ad.  This checks our job
			classad to find any dirty attributes, and compares them
			against the lists of attribute names we care about.  
			@param type What kind of update we want to do
			@return true on success, false on failure
		*/
	bool updateJobInQueue( update_t type );

		/** Connect to the job queue and update one attribute */
	virtual bool updateJobAttr( const char *name, const char *expr, bool log=false );

		/** Connect to the job queue and update one integer attribute */
	virtual bool updateJobAttr( const char *name, int value, bool log=false );

		/** Do whatever cleanup (like killing starter(s)) that's
			required before the shadow can exit.
		*/
	virtual void cleanUp( void ) = 0;

		/** Did this shadow's job exit by a signal or not?  This is
			virtual since each kind of shadow will need to implement a
			different method to decide this. */
	virtual bool exitedBySignal( void ) = 0;

		/** If this shadow's job exited by a signal, what was it?  If
			not, return -1.  This is virtual since shadow will need to
			implement a different method to supply this
			information. */ 
	virtual int exitSignal( void ) = 0;

		/** If this shadow's job exited normally, what was the return
			code?  If it was killed by a signal, return -1.  This is
			virtual since shadow will need to implement a different
			method to supply this information. */
	virtual int exitCode( void ) = 0;

		// make UserLog static so it can be accessed by EXCEPTION handler
	static std::vector<WriteUserLog*> uLog;

	void evalPeriodicUserPolicy( void );

	const char* getCoreName( void );

	virtual void resourceBeganExecution( RemoteResource* rr ) = 0;

	virtual void resourceReconnected( RemoteResource* rr ) = 0;

		/** Start a timer to do periodic updates of the job queue for
			this job.
		*/
	void startQueueUpdateTimer( void );

	void publishShadowAttrs( ClassAd* ad );

	virtual void logDisconnectedEvent( const char* reason ) = 0;

	char const *getTransferQueueContactInfo() {return m_xfer_queue_contact_info.Value();}

 protected:

		/** Note that this is the base, "unexpanded" ClassAd for the job.
			If we're a regular shadow, this pointer gets copied into the
			remoteresource.  If we're an MPI job we expand it based on
			something like $(NODE) into each remoteresource. */
	ClassAd *jobAd;

	QmgrJobUpdater *job_updater;

		/// Are we trying to remove this job (condor_rm)?
	bool remove_requested;

	ShadowUserPolicy shadow_user_policy;

	float prev_run_bytes_sent;
	float prev_run_bytes_recvd;

	bool began_execution;

	void emailHoldEvent( const char* reason );

	void emailRemoveEvent( const char* reason );

	void logRequeueEvent( const char* reason );
	
	void removeJobPre( const char* reason ); 
	
		// virtual void emailRequeueEvent( const char* reason );

	void logTerminateEvent( int exitReason, update_style_t kind = US_NORMAL );

	void logEvictEvent( int exitReason );

	virtual void logReconnectedEvent( void ) = 0;

	virtual void logReconnectFailedEvent( const char* reason ) = 0;

	virtual void emailTerminateEvent( int exitReason, update_style_t kind = US_NORMAL ) = 0;

	void startdClaimedCB(DCMsgCallback *cb);
	bool m_lazy_queue_update;

 private:

	// private methods

		/** See if there's enough swap space for this shadow, and if  
			not, exit with JOB_NO_MEM.
		*/
	void checkSwap( void );

	// config file parameters
	char *spool;
	char *fsDomain;
	char *uidDomain;
	int reconnect_ceiling;
	double reconnect_e_factor;
	bool m_RunAsNobody;

	// job parameters
	int cluster;
	int proc;
	char* gjid;
	MyString owner;
	MyString domain;
	MyString iwd;
	char *scheddAddr;
	char *core_file_name;
	MyString m_xfer_queue_contact_info;

		/// Timer id for the job cleanup retry handler.
	int m_cleanup_retry_tid;

		/// Number of times we have retried job cleanup.
	int m_num_cleanup_retries;

		/// Maximum number of times we will retry job cleanup.
	int m_max_cleanup_retries;

		/// How long to delay between attempts to retry job cleanup.
	int m_cleanup_retry_delay;

		// This makes this class un-copy-able:
	BaseShadow( const BaseShadow& );
	BaseShadow& operator = ( const BaseShadow& );

};

extern void dumpClassad( const char*, ClassAd*, int );

// Register the shadow "exit status" for the previous job
// and restart this shadow with a new job.
// Returns false if no new job found.
extern bool recycleShadow(int previous_job_exit_reason);

extern BaseShadow *Shadow;

#endif

