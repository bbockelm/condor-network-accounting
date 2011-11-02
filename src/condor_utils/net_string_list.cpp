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

#include "net_string_list.h"
#include "condor_debug.h"
#include "condor_netaddr.h"

NetStringList::NetStringList(const char *s, const char *delim ) 
	: StringList(s,delim)
{
		// nothing else to do
}


// string_withnetmask() handles the following four forms:
//
// 192.168.*
// 192.168.10.1
// 192.168.0.0/24 
// 192.168.0.0/255.255.255.0
//
// this only checks against strings which are in the above form.  so, just a
// hostname will not match in this function.
//
// function returns a string pointer to the pattern it matched against.

bool
NetStringList::find_matches_withnetwork(const char *ip_address,StringList *matches)
{
	condor_sockaddr target;
	if (!target.from_ip_string(ip_address))
		return false;

	m_strings.Rewind();
	while (char* x = m_strings.Next()) {
		condor_netaddr netaddr;
		if (!netaddr.from_net_string(x))
			continue;

		if (netaddr.match(target)) {
			if (matches)
				matches->append(x);
			else
				return true;
		}
	}
	if( matches ) {
		return !matches->isEmpty();
	}
	return false;
}
