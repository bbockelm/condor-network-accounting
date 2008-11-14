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
#include "file_transfer_db.h"
#include "condor_attributes.h"
#include "condor_constants.h"
#include "pgsqldatabase.h"
#include "basename.h"
#include "nullfile.h"
#include "my_hostname.h"
#include "internet.h"
#include "file_sql.h"
#include "subsystem_info.h"

extern FILESQL *FILEObj;

#define MAXSQLLEN 500
#define MAXMACHNAME 128

// Filenames are case sensitive on UNIX, but not Win32
#ifdef WIN32
#   define file_contains contains_anycase
#   define file_contains_withwildcard contains_anycase_withwildcard
#else
#   define file_contains contains
#   define file_contains_withwildcard contains_withwildcard
#endif


void file_transfer_db(file_transfer_record *rp, ClassAd *ad)
{
	MyString dst_host = "", 
		dst_path = "",
		globalJobId = "",
		src_name = "",
		src_path = "",
		iwd_path = "",
		job_name = "",
		dst_name = "",
		src_fullname = "";

	char *dynamic_buf = NULL;
	char buf[ATTRLIST_MAX_EXPRESSION];
	StringList *InputFiles = NULL;

	char src_host[MAXMACHNAME];
	bool inStarter  = FALSE;
	char *tmpp;
	char *dir_tmp;

	struct stat file_status;

	ClassAd tmpCl1;
	ClassAd *tmpClP1 = &tmpCl1;
	MyString tmp;

	int dst_port = 0;
	int src_port = 0;
	MyString isEncrypted = "";

		// this function access the following pointers
	if  (!rp || !ad || !FILEObj)
		return;

		// check if we are in starter process
	if (mySubSystem->isType(SUBSYSTEM_TYPE_STARTER) )
		inStarter = TRUE;

	ad->LookupString(ATTR_GLOBAL_JOB_ID, globalJobId);

		// dst_host, dst_name and dst_path, since file_transfer_db
		// is called in the destination process, dst_host is my
		// hostname
	dst_host = my_full_hostname();
	dst_name = condor_basename(rp->fullname);
	dir_tmp = condor_dirname(rp->fullname);
	dst_path = dir_tmp;
	free(dir_tmp);

		// src_host
	src_host[0] = '\0';
	if (rp->sockp && 
		(tmpp = sin_to_hostname(rp->sockp->endpoint(), NULL))) {
		snprintf(src_host, MAXMACHNAME, "%s", tmpp);
		dst_port = rp->sockp->get_port(); /* get_port retrieves the local port */
		src_port = rp->sockp->endpoint_port();
		isEncrypted = (rp->sockp->is_encrypt()==FALSE)?"FALSE":"TRUE";
	}

	bool found = false;
		// src_name, src_path
	if (inStarter && !dst_name.IsEmpty() &&
		(strcmp(dst_name.GetCStr(), CONDOR_EXEC) == 0)) {
		ad->LookupString(ATTR_ORIG_JOB_CMD, job_name);
		if (!job_name.IsEmpty() && fullpath(job_name.GetCStr())) {
			src_name = condor_basename(job_name.GetCStr());
			dir_tmp = condor_dirname(job_name.GetCStr());
			src_path = dir_tmp;
			free(dir_tmp);
			found = true;
		} else
			src_name = job_name;
		
	}
	else 
		src_name = dst_name;

	dynamic_buf = NULL;
	if (ad->LookupString(ATTR_TRANSFER_INPUT_FILES, &dynamic_buf) == 1) {
		InputFiles = new StringList(dynamic_buf,",");
		free(dynamic_buf);
		dynamic_buf = NULL;
	} else {
		InputFiles = new StringList(NULL,",");
	}
	if (ad->LookupString(ATTR_JOB_INPUT, buf) == 1) {
        // only add to list if not NULL_FILE (i.e. /dev/null)
        if ( ! nullFile(buf) ) {
            if ( !InputFiles->file_contains(buf) )
                InputFiles->append(buf);
        }
    }

	if (src_path.IsEmpty()) {
		if (inStarter)
			ad->LookupString(ATTR_ORIG_JOB_IWD, iwd_path);
		else 
			ad->LookupString(ATTR_JOB_IWD, iwd_path);
	}

	char *inputFile = NULL;

	InputFiles->rewind();
	while( !found && (inputFile = InputFiles->next()) ) {	
		const char *inputBaseName = condor_basename(inputFile);
		if(strcmp(inputBaseName, src_name.GetCStr()) == 0) {
			found = true;
			if(fullpath(inputFile)) {
				dir_tmp = condor_dirname(inputFile);
				src_path = dir_tmp;
				free(dir_tmp);
			} else {
				src_path = iwd_path;
				char *inputDirName = condor_dirname(inputFile);
				// if dirname gives back '.', don't bother sticking it on
				if(!(inputDirName[0] == '.' && inputDirName[1] == '\0')) {
					src_path += DIR_DELIM_CHAR;
					src_path += inputDirName;
				}
				free(inputDirName);
			}	
		}
	}

	if(!found) {
		src_path = iwd_path;	
	}
	if(InputFiles) {
		delete InputFiles;
		InputFiles = NULL;
	}

	if (stat(rp->fullname, &file_status) < 0) {
		dprintf( D_ALWAYS, 
		"WARNING: File %s can not be accessed by Quill file transfer tracking.\n", rp->fullname);
	}
	tmp.sprintf("globalJobId = \"%s\"", globalJobId.GetCStr());
	tmpClP1->Insert(tmp.GetCStr());			
	
	tmp.sprintf("src_name = \"%s\"", src_name.GetCStr());
	tmpClP1->Insert(tmp.GetCStr());

	tmp.sprintf("src_host = \"%s\"", src_host);
	tmpClP1->Insert(tmp.GetCStr());

	tmp.sprintf("src_port = %d", src_port);
	tmpClP1->Insert(tmp.GetCStr());

	tmp.sprintf("src_path = \"%s\"", src_path.GetCStr());
	tmpClP1->Insert(tmp.GetCStr());

	tmp.sprintf("dst_name = \"%s\"", dst_name.GetCStr());
	tmpClP1->Insert(tmp.GetCStr());

	tmp.sprintf("dst_host = \"%s\"", dst_host.GetCStr());
	tmpClP1->Insert(tmp.GetCStr());

	tmp.sprintf("dst_port = %d", dst_port);
	tmpClP1->Insert(tmp.GetCStr());

	tmp.sprintf("dst_path = \"%s\"", dst_path.GetCStr());
	tmpClP1->Insert(tmp.GetCStr());

	tmp.sprintf("transfer_size = %d", (int)rp->bytes);
	tmpClP1->Insert(tmp.GetCStr());

	tmp.sprintf("elapsed = %d", (int)rp->elapsed);
	tmpClP1->Insert(tmp.GetCStr());

	tmp.sprintf("dst_daemon = \"%s\"", rp->daemon);
	tmpClP1->Insert(tmp.GetCStr());

	tmp.sprintf("f_ts = %d", (int)file_status.st_mtime);
	tmpClP1->Insert(tmp.GetCStr());

	tmp.sprintf("transfer_time = %d", (int)rp->transfer_time);
	tmpClP1->Insert(tmp.GetCStr());	

	tmp.sprintf("is_encrypted = %s", isEncrypted.GetCStr());
	tmpClP1->Insert(tmp.GetCStr());	

	tmp.sprintf("delegation_method_id = %d", rp->delegation_method_id);
	tmpClP1->Insert(tmp.GetCStr());	

	FILEObj->file_newEvent("Transfers", tmpClP1);

}