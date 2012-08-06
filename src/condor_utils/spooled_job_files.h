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

#ifndef _SPOOLED_JOB_FILES_H
#define _SPOOLED_JOB_FILES_H

#include <string>
#include "condor_uid.h"
#include "condor_classad.h"


class SpooledJobFiles {
public:
	static void getJobSpoolPath(int cluster,int proc,std::string &spool_path);

		/* Create the spool directory and/or chown the spool directory
		   to the desired ownership.  The shared parent spool directories
		   are also created if they do not already exist.  For standard
		   universe, only the parent spool directories are created,
		   not per-job directories, because standard universe does not
		   need per-job directories (it has checkpoint files of the same
		   name and path as the per-job directories).
		 */
	static bool createJobSpoolDirectory(ClassAd const *job_ad,priv_state desired_priv_state );

		/* Like createJobSpoolDirectory, but just create the directories
		 * as condor and do not chown them.
		 */
	static bool createJobSpoolDirectory_PRIV_CONDOR(int cluster, int proc, bool is_standard_universe );

		/* Like createJobSpoolDirectory, but just create the .swap directory.
		 * Assumes the other (parent) directories have already been created.
		 */
	static bool createJobSwapSpoolDirectory(ClassAd const *job_ad,priv_state desired_priv_state );

		/* Create the shared spool directories but not the actual
		 * per-job directories.
		 */
	static bool createParentSpoolDirectories(ClassAd const *job_ad);

		/* Remove the spool directory belonging to a job.
		 * Also removes the .tmp and .swap directories.
		 * This also removes the shared proc directory from the
		 * hierarchy if possible.
		 */
	static void removeJobSpoolDirectory( ClassAd * ad);

		/* Remove the .swap spool directory belonging to a job.
		 */
	static void removeJobSwapSpoolDirectory( ClassAd * ad);

		/* Remove files spooled for a job cluster.
		 * This also removes the shared cluster directory from the
		 * hierarchy if possible.
		 */
	static void removeClusterSpooledFiles(int cluster);

		/* Restore ownership of spool directory to condor after job ran.
		   Returns true on success.
		 */
	static bool chownSpoolDirectoryToCondor(ClassAd const *job_ad);

		/* Returns true if this job requires a spool directory.
		 */
	static bool jobRequiresSpoolDirectory(ClassAd const *job_ad);
};

char *gen_ckpt_name ( char const *dir, int cluster, int proc, int subproc );

#endif
