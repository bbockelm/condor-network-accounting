/***************************************************************
 *
 * Copyright (C) 1990-2011, Condor Team, Computer Sciences Department,
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

/** directory scanning  */

#ifndef WIN32
int scandirectory(const char *dir, struct dirent ***namelist,
            int (*select)(const struct dirent *),
        int (*compar)(const void*, const void*) );
int doalphasort(const void *a, const void *b); 
#endif

/******************************/

 
/** set the base name for the log file, i.e. the basic daemon log filename w/ path*/
void setBaseName(const char *baseName);

int rotateSingle(void);

/** create a rotation filename depending on maxNum and existing ending */
const char *createRotateFilename(const char *ending, int maxNum);

/** perform rotation */
int rotateTimestamp(const char *timeStamp, int maxNum);

/** Rotate away all old history files exceeding maxNum count */
int cleanUp(int maxNum);

/** is it a *.old file? */
int isOldString(char *str);

/** is the argument an ISO timestamp? */
int isTimestampString(char *str);

/** is the argument a valid log filename? */
int isLogFilename( char *filename);

/** find the oldest file in the directory matching the 
  *current base name according to iso time ending 
 */
char *findOldest(char *dirName, int *count);
