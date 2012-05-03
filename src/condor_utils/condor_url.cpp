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
#include "condor_url.h"

bool IsUrl( const char *url )
{
	if ( !url ) {
		return false;
	}
	const char *ptr = url;
	while ( isalpha( *ptr ) ) {
		ptr++;
	}
	if ( ptr != url && ptr[0] == ':' && ptr[1] == '/' && ptr[2] == '/' ) {
		return true;
	}
	return false;
}

MyString getURLType( const char *url ) {
	MyString t;
	if(IsUrl(url)) {
		MyString u = url;
		t = u.Substr(0,u.FindChar(':')-1);
	}
	return t;
}

