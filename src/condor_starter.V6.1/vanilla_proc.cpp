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
#include "condor_classad.h"
#include "condor_debug.h"
#include "condor_daemon_core.h"
#include "condor_attributes.h"
#include "condor_syscall_mode.h"
#include "exit.h"
#include "vanilla_proc.h"
#include "starter.h"
#include "syscall_numbers.h"
#include "dynuser.h"
#include "condor_config.h"
#include "domain_tools.h"
#include "classad_helpers.h"
#include "network_namespaces.h"
#include "filesystem_remap.h"
#include "directory.h"

#include <memory>
#include <sstream>

#ifdef WIN32
#include "executable_scripts.WINDOWS.h"
extern dynuser* myDynuser;
#endif

extern CStarter *Starter;

VanillaProc::VanillaProc(ClassAd* jobAd) : OsProc(jobAd), m_network_manager(NULL), m_cleanup_manager(false)
{
#if !defined(WIN32)
	m_escalation_tid = -1;
#endif
}

int
VanillaProc::StartJob()
{
	dprintf(D_FULLDEBUG,"in VanillaProc::StartJob()\n");

	// vanilla jobs, unlike standard jobs, are allowed to run 
	// shell scripts (or as is the case on NT, batch files).  so
	// edit the ad so we start up a shell, pass the executable as
	// an argument to the shell, if we are asked to run a .bat file.
#ifdef WIN32

	CHAR		interpreter[MAX_PATH+1],
				systemshell[MAX_PATH+1];    
	const char* jobtmp				= Starter->jic->origJobName();
	int			joblen				= strlen(jobtmp);
	const char	*extension			= joblen > 0 ? &(jobtmp[joblen-4]) : NULL;
	bool		binary_executable	= ( extension && 
										( MATCH == strcasecmp ( ".exe", extension ) || 
										  MATCH == strcasecmp ( ".com", extension ) ) ),
				java_universe		= ( CONDOR_UNIVERSE_JAVA == job_universe );
	ArgList		arguments;
	MyString	filename,
				jobname, 
				error;
	
	if ( extension && !java_universe && !binary_executable ) {

		/** since we do not actually know how long the extension of
			the file is, we'll need to hunt down the '.' in the path,
			if it exists */
		extension = strrchr ( jobtmp, '.' );

		if ( !extension ) {

			dprintf ( 
				D_ALWAYS, 
				"VanillaProc::StartJob(): Failed to extract "
				"the file's extension.\n" );

			/** don't fail here, since we want executables to run
				as usual.  That is, some condor jobs submit 
				executables that do not have the '.exe' extension,
				but are, nonetheless, executable binaries.  For
				instance, a submit script may contain:

				executable = executable$(OPSYS) */

		} else {

			/** pull out the path to the executable */
			if ( !JobAd->LookupString ( 
				ATTR_JOB_CMD, 
				jobname ) ) {
				
				/** fall back on Starter->jic->origJobName() */
				jobname = jobtmp;

			}

			/** If we transferred the job, it may have been
				renamed to condor_exec.exe even though it is
				not an executable. Here we rename it back to
				a the correct extension before it will run. */
			if ( MATCH == strcasecmp ( 
					CONDOR_EXEC, 
					condor_basename ( jobname.Value () ) ) ) {
				filename.sprintf ( "condor_exec%s", extension );
				rename ( CONDOR_EXEC, filename.Value () );					
			} else {
				filename = jobname;
			}
			
			/** Since we've renamed our executable, we need to
				update the job ad to reflect this change. */
			if ( !JobAd->Assign ( 
				ATTR_JOB_CMD, 
				filename ) ) {

				dprintf (
					D_ALWAYS,
					"VanillaProc::StartJob(): ERROR: failed to "
					"set new executable name.\n" );

				return FALSE;

			}

			/** We've moved the script to argv[1], so we need to 
				add	the remaining arguments to positions argv[2]..
				argv[/n/]. */
			if ( !arguments.AppendArgsFromClassAd ( JobAd, &error ) ||
				 !arguments.InsertArgsIntoClassAd ( JobAd, NULL, 
				&error ) ) {

				dprintf (
					D_ALWAYS,
					"VanillaProc::StartJob(): ERROR: failed to "
					"get arguments from job ad: %s\n",
					error.Value () );

				return FALSE;

			}

			/** Since we know already we don't want this file returned
				to us, we explicitly add it to an exception list which
				will stop the file transfer mechanism from considering
				it for transfer back to its submitter */
			Starter->jic->removeFromOutputFiles (
				filename.Value () );

		}
			
	}
#endif

	// set up a FamilyInfo structure to tell OsProc to register a family
	// with the ProcD in its call to DaemonCore::Create_Process
	//
	FamilyInfo fi;

	// take snapshots at no more than 15 seconds in between, by default
	//
	fi.max_snapshot_interval = param_integer("PID_SNAPSHOT_INTERVAL", 15);

	char const *dedicated_account = Starter->jic->getExecuteAccountIsDedicated();
	if( ThisProcRunsAlongsideMainProc() ) {
			// If we track a secondary proc's family tree (such as
			// sshd) using the same dedicated account as the job's
			// family tree, we could end up killing the job when we
			// clean up the secondary family.
		dedicated_account = NULL;
	}
	if (dedicated_account) {
			// using login-based family tracking
		fi.login = dedicated_account;
			// The following message is documented in the manual as the
			// way to tell whether the dedicated execution account
			// configuration is being used.
		dprintf(D_ALWAYS,
		        "Tracking process family by login \"%s\"\n",
		        fi.login);
	}

	FilesystemRemap * fs_remap = NULL;
#if defined(LINUX)
	// on Linux, we also have the ability to track processes via
	// a phony supplementary group ID
	//
	gid_t tracking_gid;
	if (param_boolean("USE_GID_PROCESS_TRACKING", false)) {
		if (!can_switch_ids() &&
		    (Starter->condorPrivSepHelper() == NULL))
		{
			EXCEPT("USE_GID_PROCESS_TRACKING enabled, but can't modify "
			           "the group list of our children unless running as "
			           "root or using PrivSep");
		}
		fi.group_ptr = &tracking_gid;
	}
#endif

#if defined(LINUX)

	// On Linux kernel 2.6.24 and later, we can give each
	// job its own PID namespace
	if (param_boolean("USE_PID_NAMESPACES", false)) {
		if (!can_switch_ids()) {
			EXCEPT("USE_PID_NAMESPACES enabled, but can't perform this "
					"call in Linux unless running as root.");
		}
		fi.want_pid_namespace = true;
	}
	dprintf(D_FULLDEBUG, "PID namespace option: %s\n", fi.want_pid_namespace ? "true" : "false");
#endif

#if defined(HAVE_EXT_LIBCGROUP)
	// Determine the cgroup
	char* cgroup_base = param("BASE_CGROUP"), *cgroup = NULL;
	int cluster, proc, bufpos=0, buflen=0;
	if (cgroup_base && JobAd->LookupInteger(ATTR_CLUSTER_ID, cluster) &&
			JobAd->LookupInteger(ATTR_PROC_ID, proc)) {
		cgroup = (char *)malloc(sizeof(char)*80);
		ASSERT (cgroup != NULL);
		int rc = sprintf_realloc(&cgroup,&bufpos,&buflen,"%s%c%s%d%c%d",
			cgroup_base, DIR_DELIM_CHAR, "job_",
			cluster, '_', proc);
		if (rc < 0) {
			EXCEPT("Unable to determine the cgroup to use.");
		} else {
			fi.cgroup = cgroup;
			dprintf(D_FULLDEBUG, "Requesting cgroup %s for job %d.%d.\n",
				cgroup, cluster, proc);
		}
	}
#endif

{
	// Have Condor manage a chroot
	std::string requested_root_dir;
	JobAd->EvalString(ATTR_JOB_ROOT_DIR, NULL, requested_root_dir);
	const char * allowed_root_dirs = param("ALLOWED_ROOT_DIRS");
	if (requested_root_dir.size()) {
		TemporaryPrivSentry priv_sentry(PRIV_ROOT);
		if (get_priv() != PRIV_ROOT) {
			dprintf(D_ALWAYS, "Unable switch to root privileges; Condor must be run as root to use the ALLOWED_ROOT_DIRS features.\n");
			return FALSE;
		}
		StringList chroot_list(allowed_root_dirs);
		chroot_list.rewind();
		const char * next_dir;
		bool acceptable_chroot = false;
		while ( (next_dir=chroot_list.next()) ) {
			dprintf(D_FULLDEBUG, "Considering directory for chroot: %s.\n", next_dir);
			if (IsDirectory(next_dir) && (strcmp(requested_root_dir.c_str(), next_dir) == 0)) {
				acceptable_chroot = true;
			}
		}
		// TODO: path to chroot MUST be all root-owned, or we have a nice security exploit.
		if (!acceptable_chroot) {
			return FALSE;
		}
		dprintf(D_FULLDEBUG, "Will attempt to set the chroot to %s.\n", requested_root_dir.c_str());

		std::string execute_dir(Starter->GetExecuteDir());
		const char * full_dir = dirscat(requested_root_dir, execute_dir);
		std::string full_dir_str;
		if (full_dir) {
			full_dir_str = full_dir;
		} else {
			dprintf(D_ALWAYS, "Unable to concatenate %s and %s.\n", requested_root_dir.c_str(), execute_dir.c_str());
			return FALSE;
		}
		delete [] full_dir;
		if (IsDirectory(execute_dir.c_str())) {
			if (!mkdir_and_parents_if_needed( full_dir_str.c_str(), S_IRWXU, PRIV_USER )) {
				dprintf(D_ALWAYS, "Failed to create scratch directory %s\n", full_dir_str.c_str());
				return FALSE;
			}
			if (!fs_remap) {
				fs_remap = new FilesystemRemap();
			}
			dprintf(D_FULLDEBUG, "Adding mapping: %s -> %s.\n", execute_dir.c_str(), full_dir_str.c_str());
			if (fs_remap->AddMapping(execute_dir, full_dir_str)) {
				// FilesystemRemap object prints out an error message for us.
				return FALSE;
			}
			dprintf(D_FULLDEBUG, "Adding mapping %s -> %s.\n", requested_root_dir.c_str(), "/");
			std::string root_str("/");
			if (fs_remap->AddMapping(requested_root_dir, root_str)) {
				return FALSE;
			}
		} else {
			dprintf(D_ALWAYS, "Unable to do chroot because working dir %s does not exist.\n", execute_dir.c_str());
		}
	} else {
		dprintf(D_ALWAYS, "Value of RootDir is unset.\n");
	}
}

{
	// On Linux kernel 2.4.19 and later, we can give each job its
	// own FS mounts.
	char * mount_under_scratch = param("MOUNT_UNDER_SCRATCH");
	if (mount_under_scratch) {
 		// It's very likely the 'condor' user doesn't have permission to stat some of these
 		// directories.  Switch to root for now.  We have to have the root priv to do this anyway
 		TemporaryPrivSentry priv_sentry(PRIV_ROOT);
		if (get_priv() != PRIV_ROOT) {
			dprintf(D_ALWAYS, "Unable to switch to root privileges; Condor must be run as root to use the MOUNT_UNDER_SCRATCH features.\n");
			return FALSE;
		}

 		std::string working_dir = Starter->GetWorkingDir();
 		if (IsDirectory(working_dir.c_str())) {
			StringList mount_list(mount_under_scratch);
			mount_list.rewind();
			if (!fs_remap) {
				fs_remap = new FilesystemRemap();
			}
 			char * next_dir;
			while ( (next_dir=mount_list.next()) ) {
				if (!*next_dir) {
					// empty string?
					mount_list.deleteCurrent();
					continue;
				}
				std::string next_dir_str(next_dir);
				// Gah, I wish I could throw an exception to clean up these nested if statements.
				if (IsDirectory(next_dir)) {
					char * full_dir = dirscat(working_dir, next_dir_str);
					if (full_dir) {
						std::string full_dir_str(full_dir);
						delete [] full_dir; full_dir = NULL;
						if (!mkdir_and_parents_if_needed( full_dir_str.c_str(), S_IRWXU, PRIV_USER )) {
							dprintf(D_ALWAYS, "Failed to create scratch directory %s\n", full_dir_str.c_str());
							return FALSE;
						}
						dprintf(D_FULLDEBUG, "Adding mapping: %s -> %s.\n", full_dir_str.c_str(), next_dir_str.c_str());
						if (fs_remap->AddMapping(full_dir_str, next_dir_str)) {
							// FilesystemRemap object prints out an error message for us.
							return FALSE;
						}
					} else {
						dprintf(D_ALWAYS, "Unable to concatenate %s and %s.\n", working_dir.c_str(), next_dir_str.c_str());
						return FALSE;
					}
				} else {
					dprintf(D_ALWAYS, "Unable to add mapping %s -> %s because %s doesn't exist.\n", working_dir.c_str(), next_dir, next_dir);
 				}
				// Create mount.
 			}
		} else {
			dprintf(D_ALWAYS, "Unable to perform mappings because %s doesn't exist.\n", working_dir.c_str());
			return FALSE;
 		}
		// Long term, we'd like to squash $(EXECUTE) to prevent a job from poking
		// around inside other job's sandboxes.  However, to do this, we'd need to
		// rewrite the environment, the job ad, and the machine ad.  Don't know where
		// this hooks in yet.
		//
	}
}

	if (param_boolean("USE_NETWORK_NAMESPACES", false)) {
		std::stringstream namespace_name_ss;
		namespace_name_ss << "slot";
		namespace_name_ss << (Starter->getMySlotNumber());
		std::string namespace_name = namespace_name_ss.str();
		m_network_manager.reset(new NetworkNamespaceManager(namespace_name));
		priv_state orig_priv = set_priv(PRIV_ROOT);
		int rc = m_network_manager->CreateNamespace();
		set_priv(orig_priv);
		if (rc) {
			dprintf(D_ALWAYS, "Failed to create network namespace - bailing.\n");
			return FALSE;
		}
	}

	// have OsProc start the job
	//
	int retval = OsProc::StartJob(&fi, m_network_manager.get(), fs_remap);

#if defined(HAVE_EXT_LIBCGROUP)
	if (cgroup != NULL)
		free(cgroup);
#endif
	if (!retval && m_network_manager.get()) {
		priv_state orig_priv = set_priv(PRIV_ROOT);
		int rc = m_network_manager->Cleanup();
		set_priv(orig_priv);
		dprintf(D_ALWAYS, "Failed to cleanup network namespace (rc=%d)\n", rc);
	}
	if (fs_remap) {
		delete fs_remap;
	}

	return retval;
}


bool
VanillaProc::PublishUpdateAd( ClassAd* ad )
{
	dprintf( D_FULLDEBUG, "In VanillaProc::PublishUpdateAd()\n" );

	ProcFamilyUsage* usage;
	ProcFamilyUsage cur_usage;
	if (m_proc_exited) {
		usage = &m_final_usage;
	}
	else {
		if (daemonCore->Get_Family_Usage(JobPid, cur_usage) == FALSE) {
			dprintf(D_ALWAYS, "error getting family usage in "
					"VanillaProc::PublishUpdateAd() for pid %d\n", JobPid);
			return false;
		}
		usage = &cur_usage;
	}

		// Publish the info we care about into the ad.
	char buf[200];
	sprintf( buf, "%s=%lu", ATTR_JOB_REMOTE_SYS_CPU, usage->sys_cpu_time );
	ad->InsertOrUpdate( buf );
	sprintf( buf, "%s=%lu", ATTR_JOB_REMOTE_USER_CPU, usage->user_cpu_time );
	ad->InsertOrUpdate( buf );

	sprintf( buf, "%s=%lu", ATTR_IMAGE_SIZE, usage->max_image_size );
	ad->InsertOrUpdate( buf );
	sprintf( buf, "%s=%lu", ATTR_RESIDENT_SET_SIZE, usage->total_resident_set_size );
	ad->InsertOrUpdate( buf );

#if HAVE_PSS
	if( usage->total_proportional_set_size_available ) {
		ad->Assign( ATTR_PROPORTIONAL_SET_SIZE, usage->total_proportional_set_size );
	}
#endif

	if (usage->block_read_bytes >= 0) {
		sprintf( buf, "%s=%lu", ATTR_BLOCK_READ_KBYTES, usage->block_read_bytes/1024 );
		ad->InsertOrUpdate( buf );
	}
	if (usage->block_write_bytes >= 0) {
		sprintf( buf, "%s=%lu", ATTR_BLOCK_WRITE_KBYTES, usage->block_write_bytes/1024 );
		ad->InsertOrUpdate( buf );
	}

		// Update our knowledge of how many processes the job has
	num_pids = usage->num_procs;

	if (m_network_manager.get()) {
		priv_state orig_priv = set_priv(PRIV_ROOT);
		m_network_manager->PerformJobAccounting(ad);
		set_priv(orig_priv);
	}

		// Now, call our parent class's version
	return OsProc::PublishUpdateAd( ad );
}


bool
VanillaProc::JobReaper(int pid, int status)
{
	dprintf(D_FULLDEBUG,"Inside VanillaProc::JobReaper()\n");

	if (pid == JobPid) {
			// Make sure that nothing was left behind.
		daemonCore->Kill_Family(JobPid);

			// Record final usage stats for this process family, since
			// once the reaper returns, the family is no longer
			// registered with DaemonCore and we'll never be able to
			// get this information again.
		if (daemonCore->Get_Family_Usage(JobPid, m_final_usage) == FALSE) {
			dprintf(D_ALWAYS, "error getting family usage for pid %d in "
					"VanillaProc::JobReaper()\n", JobPid);
		}
		if (m_network_manager.get()) {
			priv_state orig_priv = set_priv(PRIV_ROOT);
			// Call this before removing the statistics; PublishUpdateAd is called after JobReaper
			m_network_manager->PerformJobAccounting(NULL);
			int rc = m_network_manager->Cleanup();
			set_priv(orig_priv);
			if (rc) {
				dprintf(D_ALWAYS, "Failed to cleanup network namespace (rc=%d)\n", rc);
			}
		}
	}

		// This will reset num_pids for us, too.
	return OsProc::JobReaper( pid, status );
}


void
VanillaProc::Suspend()
{
	dprintf(D_FULLDEBUG,"in VanillaProc::Suspend()\n");
	
	// suspend the user job
	if (JobPid != -1) {
		if (daemonCore->Suspend_Family(JobPid) == FALSE) {
			dprintf(D_ALWAYS,
			        "error suspending family in VanillaProc::Suspend()\n");
		}
	}
	
	// set our flag
	is_suspended = true;
}

void
VanillaProc::Continue()
{
	dprintf(D_FULLDEBUG,"in VanillaProc::Continue()\n");
	
	// resume user job
	if (JobPid != -1) {
		if (daemonCore->Continue_Family(JobPid) == FALSE) {
			dprintf(D_ALWAYS,
			        "error continuing family in VanillaProc::Continue()\n");
		}
	}

	// set our flag
	is_suspended = false;
}

bool
VanillaProc::ShutdownGraceful()
{
	dprintf(D_FULLDEBUG,"in VanillaProc::ShutdownGraceful()\n");
	
	if ( JobPid == -1 ) {
		// there is no process family yet, probably because we are still
		// transferring files.  just return true to say we're all done,
		// and that way the starter class will simply delete us and the
		// FileTransfer destructor will clean up.
		return true;
	}

	// WE USED TO.....
	//
	// take a snapshot before we softkill the parent job process.
	// this helps ensure that if the parent exits without killing
	// the kids, our JobExit() handler will get em all.
	//
	// TODO: should we make an explicit call to the procd here to tell
	// it to take a snapshot???

	// now softkill the parent job process.  this is exactly what
	// OsProc::ShutdownGraceful does, so call it.
	//
	OsProc::ShutdownGraceful();
	return false; // shutdown is pending (same as OsProc::ShutdownGraceful()
}

bool
VanillaProc::ShutdownFast()
{
	dprintf(D_FULLDEBUG,"in VanillaProc::ShutdownFast()\n");
	
	if ( JobPid == -1 ) {
		// there is no process family yet, probably because we are still
		// transferring files.  just return true to say we're all done,
		// and that way the starter class will simply delete us and the
		// FileTransfer destructor will clean up.
		return true;
	}

	// We purposely do not do a SIGCONT here, since there is no sense
	// in potentially swapping the job back into memory if our next
	// step is to hard kill it.
	requested_exit = true;

	return finishShutdownFast();
}

bool
VanillaProc::finishShutdownFast()
{
	// this used to be the only place where we would clean up the process
	// family. this, however, wouldn't properly clean up local universe jobs
	// so a call to Kill_Family has been added to JobReaper(). i'm not sure
	// that this call is still needed, but am unwilling to remove it on the
	// eve of Condor 7
	//   -gquinn, 2007-11-14
	daemonCore->Kill_Family(JobPid);

	return false;	// shutdown is pending, so return false
}
