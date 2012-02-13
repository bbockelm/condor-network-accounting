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
#include "condor_config.h"
#include "directory_util.h"

/*
  Returns a path to subdirectory to use for temporary files.
  The pointer returned must be de-allocated by the caller w/ free().
*/
char*
temp_dir_path()
{
	char *prefix = param("TMP_DIR");
	if  (!prefix) {
		prefix = param("TEMP_DIR");
	}
	if (!prefix) {
#ifndef WIN32
		prefix = strdup("/tmp");
#else
			// try to get the temp dir, then try SPOOL,
			// then use the root directory
		char buf[MAX_PATH];
		int len;
		if ((len = GetTempPath(sizeof(buf), buf)) <= sizeof(buf)) {
			buf[len - 1] = '\0';
			prefix = strdup(buf);
		} else {
			dprintf(D_ALWAYS, "GetTempPath: buffer of size %d too small\n", sizeof(buf));

			prefix = param("SPOOL");
			if (!prefix) {
				prefix = strdup("\\");
			}
		}
#endif
	}
	return prefix;
}

/*
  Concatenates a given directory path and filename into a single
  string, stored in space allocated with new[].  This function makes
  sure that if the given directory path doesn't end with the
  appropriate directory delimiter for this platform, that the new
  string includes that.  Delete return string with delete[].
*/
char*
dircat( const char *dirpath, const char *filename )
{
	ASSERT(dirpath);
	ASSERT(filename);
	bool needs_delim = true;
	int extra = 2, dirlen = strlen(dirpath);
	char* rval;
	if( dirpath[dirlen - 1] == DIR_DELIM_CHAR ) {
		needs_delim = false;
		extra = 1;
	}
	rval = new char[ extra + dirlen + strlen(filename)];
	if( needs_delim ) {
		sprintf( rval, "%s%c%s", dirpath, DIR_DELIM_CHAR, filename );
	} else {
		sprintf( rval, "%s%s", dirpath, filename );
	}
	return rval;
}

/*
  Concatenates a given directory path and subdirectory path into a single
  string, stored in space allocated with new[].  This function makes
  sure that if the given directory path doesn't end with the
  appropriate directory delimiter for this platform, that the new
  string includes that -- it will contain the trailing delimiter too.  
  Delete return string with delete[].
*/
char*
dirscat( const char *dirpath, const char *subdir )
{
	ASSERT(dirpath);
	ASSERT(subdir);
	bool needs_delim1 = true, needs_delim2 = true;
	int extra = 3, dirlen = strlen(dirpath), subdirlen = strlen(subdir);
	char* rval;
	if( dirpath[dirlen - 1] == DIR_DELIM_CHAR ) {
		needs_delim1 = false;
		--extra;
	}
	if (subdir[subdirlen - 1] == DIR_DELIM_CHAR ) {
		--extra;
		needs_delim2 = false;
	}
	rval = new char[ extra + dirlen + strlen(subdir)];
	if( needs_delim1 ) {
		if ( needs_delim2 ) {
			sprintf( rval, "%s%c%s%c", dirpath, DIR_DELIM_CHAR, subdir, DIR_DELIM_CHAR );
		} else {
			sprintf( rval, "%s%c%s", dirpath, DIR_DELIM_CHAR, subdir );
		}
	} else {
		if ( needs_delim2 ) {
			sprintf( rval, "%s%s%c", dirpath, subdir, DIR_DELIM_CHAR );
		} else {
			sprintf( rval, "%s%s", dirpath, subdir );
		}
	}
	return rval;
}

char*
dirscat( std::string &dirpath, std::string &subdir ) {
	return dirscat(dirpath.c_str(), subdir.c_str());
}

int 
rec_touch_file(char *path, mode_t file_mode, mode_t directory_mode , int pos) 
{
	// in case a process deletes parts of the directory tree, retry up to three times 
	int retry_value = 4;
	int retry = retry_value;
	int m_fd = -1;
	int size = strlen(path);
	while (m_fd <= 0 && retry > 0 ){
		m_fd = safe_open_wrapper_follow(path, O_CREAT | O_RDWR, file_mode);
		if (m_fd >= 0)
			return m_fd;
		if (errno == 2) {
			if (retry < retry_value) {
				dprintf(D_ALWAYS, "directory_util::rec_touch_file: Directory creation completed successfully but \
					still cannot touch file. Likely another process deleted parts of the directory structure. \
					Will retry now to recover (retry attempt %i)\n", (retry_value-retry));
			}
			pos = 0;
			--retry;
			while (pos < size){
				if (path[pos] == DIR_DELIM_CHAR && pos > 0){
					char *dir = new char[pos+1];
					strncpy(dir, path, pos);
					dir[pos] = '\0';
					dprintf(D_FULLDEBUG, "directory_util::rec_touch_file: Creating directory %s \n", dir);
					int err = mkdir(dir, directory_mode);
					if (err != 0) {
						if (errno != EEXIST) {
							dprintf(D_ALWAYS, "directory_util::rec_touch_file: Directory %s cannot be created (%s) \n", dir, strerror(errno));
							delete []dir;
							return -1;
						}
					}
					delete []dir;
					++pos;
				}
				++pos;
			}
		} else {
			dprintf(D_ALWAYS, "directory_util::rec_touch_file: File %s cannot be created (%s) \n", path, strerror(errno));
			return -1;
		}
	}
	dprintf(D_ALWAYS, "Tried to recover from problems but failed. Path to lock file %s cannot be created. Giving up.\n", path);
	return -1;
} 


int 
rec_clean_up(char *path, int depth, int pos ) 
{
	if (depth == -1)
		return 0;
	int deleted;
	if (pos < 0) {
		deleted =  unlink(path);
		if (deleted == 0){ 
			dprintf(D_FULLDEBUG, "directory_util::rec_clean_up: file %s has been deleted. \n", path);
			if (depth == 0)
				return 0;
		} else{
			dprintf(D_FULLDEBUG, "directory_util::rec_clean_up: file %s cannot be deleted. \n", path);
			return -1;
		}
		pos = strlen(path);
	} else {
		char *dirpath = new char[pos+1];
		strncpy(dirpath, path, pos);
		dirpath[pos] = '\0';
		deleted = rmdir(dirpath);
		if (deleted != 0) {
			dprintf(D_FULLDEBUG, "directory_util::rec_clean_up: directory %s cannot be deleted -- it may not \
				be empty and therefore this is not necessarily an error or problem. (Error: %s) \n", dirpath, strerror(errno));
			delete []dirpath;
			return -1;
		}
		delete []dirpath;
	}
	while (path[pos] == DIR_DELIM_CHAR && pos > 0)
			--pos;
	while (pos > 0){
		if (path[pos] == DIR_DELIM_CHAR ){
			return rec_clean_up(path, --depth, pos);
		}
		--pos; 	
	}
	return 0; 	
}



