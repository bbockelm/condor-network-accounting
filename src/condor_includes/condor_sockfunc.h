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

#ifndef CONDOR_SOCKFUNC_H
#define CONDOR_SOCKFUNC_H

#include "condor_sockaddr.h"

int condor_connect(int sockfd, const condor_sockaddr& addr);
int condor_accept(int sockfd, condor_sockaddr& addr);
int condor_bind(int sockfd, const condor_sockaddr& addr);
int condor_getsockname(int sockfd, condor_sockaddr& addr);
int condor_getpeername(int sockfd, condor_sockaddr& addr);

// if the sockfd has any address, it replaces with local ip address
int condor_getsockname_ex(int sockfd, condor_sockaddr& addr);

int condor_getnameinfo (const condor_sockaddr& addr,
				char * __host, socklen_t __hostlen, 
				char * __serv, socklen_t __servlen,
				unsigned int __flags);


int condor_getaddrinfo(const char *node,
                const char *service,
                const addrinfo *hints,
                addrinfo **res);

int condor_sendto(int sockfd, const void* buf, size_t len, int flags,
				  const condor_sockaddr& addr);
int condor_recvfrom(int sockfd, void* buf, size_t buf_size, int flags,
		condor_sockaddr& addr);

// it is not really required...
//
// create IPv6 socket if the build is configured to ipv6
// else create IPv4 socket
//int condor_socket(int socket_type, int protocol);

struct addrinfo;
// create a socket based on addrinfo
int condor_socket(const addrinfo& ai);

// Reer the syntax of IP address
// from http://www.opengroup.org/onlinepubs/000095399/functions/inet_ntop.html

// it converts given text string to condor_sockaddr.
// it automatically detects whether given text is ipv4 or ipv6.
// returns 0 if it is not ip address at all
// returns 1 if succeeded
int condor_inet_pton(const char* src, condor_sockaddr& dest);

hostent* condor_gethostbyaddr_ipv6(const condor_sockaddr& addr);
int condor_getsockaddr(int fd, condor_sockaddr& addr);
// moved to my_hostname.h --> ipv6_hostname.h
//condor_sockaddr ipv6_my_ip_addr();
//int ipv6_is_ipaddr(const char* host, condor_sockaddr& addr);
//const char* ipv6_addr_to_hostname(const condor_sockaddr& addr, char* buf, int len);

#endif // CONDOR_SOCKFUNC_H
