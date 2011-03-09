#include "condor_common.h"
#include "MyString.h"
#include "condor_ipaddr.h"
#include "ipv6_hostname.h"

ipaddr ipaddr::null;

void ipaddr::clear()
{
	memset(&storage, 0, sizeof(sockaddr_storage));
}

// init only accepts network-ordered ip and port
void ipaddr::init(int ip, unsigned port)
{
	clear();
	v4.sin_family = AF_INET;
	v4.sin_port = port;
	v4.sin_addr.s_addr = ip;
}

ipaddr::ipaddr()
{
	clear();
}

ipaddr::ipaddr(in_addr ip, unsigned short port)
{
	init(ip.s_addr, htons(port));
}

ipaddr::ipaddr(const in6_addr& in6, unsigned short port)
{
	memset(&storage, 0, sizeof(storage));
	v6.sin6_family = AF_INET6;
	v6.sin6_port = htons(port);
	v6.sin6_addr = in6;
}

ipaddr::ipaddr(const sockaddr* sa)
{
	if (sa->sa_family == AF_INET) {
		sockaddr_in* sin = (sockaddr_in*)sa;
		init(sin->sin_addr.s_addr, sin->sin_port);
	} else if (sa->sa_family == AF_INET6) {
		sockaddr_in6* sin6 = (sockaddr_in6*)sa;
		v6 = *sin6;
	} else {
		clear();
	}
}

ipaddr::ipaddr(const sockaddr_in* sin) 
{
	init(sin->sin_addr.s_addr, sin->sin_port);
}

ipaddr::ipaddr(const sockaddr_in6* sin6)
{
	v6 = *sin6;
}

sockaddr_in ipaddr::to_sin() const
{
	return v4;
}

sockaddr_in6 ipaddr::to_sin6() const
{
	return v6;
}

bool ipaddr::is_ipv4() const
{
	return v4.sin_family == AF_INET;
}

bool ipaddr::is_ipv6() const
{
	return v6.sin6_family == AF_INET6;
}

// IN6_* macro are came from netinet/inet.h
// need to check whether it is platform-independent macro
// -- compiled on every unix/linux platforms
bool ipaddr::is_addr_any() const
{
	if (is_ipv4()) {
		return v4.sin_addr.s_addr == ntohl(INADDR_ANY);
	}
	else if (is_ipv6()) {
		return IN6_IS_ADDR_UNSPECIFIED(&v6.sin6_addr);
	}
	return false;
}

void ipaddr::set_addr_any()
{
	if (is_ipv4()) {
		v4.sin_addr.s_addr = ntohl(INADDR_ANY);
	}
	else if (is_ipv6()) {
		v6.sin6_addr = in6addr_any;
	}
}

bool ipaddr::is_loopback() const
{
	if (is_ipv4()) {
		return v4.sin_addr.s_addr == ntohl(INADDR_LOOPBACK);
	}
	else {
		return IN6_IS_ADDR_LOOPBACK( &v6.sin6_addr );
	}
}

void ipaddr::set_loopback()
{
	if (is_ipv4()) {
		v4.sin_addr.s_addr = ntohl(INADDR_LOOPBACK);
	}
	else {
		v6.sin6_addr = in6addr_loopback;
	}
}

unsigned short ipaddr::get_port() const
{
	if (is_ipv4()) {
		return ntohs(v4.sin_port);
	}
	else {
		return ntohs(v6.sin6_port);
	}
}

void ipaddr::set_port(unsigned short port)
{
	if (is_ipv4()) {
		v4.sin_port = htons(port);
	}
	else {
		v6.sin6_port = htons(port);
	}
}

MyString ipaddr::to_sinful() const
{
	MyString ret;
	char tmp[IP_STRING_BUF_SIZE];
		// if it is not ipv4 or ipv6, to_ip_string_ex will fail.
	if ( !to_ip_string_ex(tmp, IP_STRING_BUF_SIZE) )
		return ret;

	if (is_ipv4()) {
		ret.sprintf("<%s:%d>", tmp, ntohs(v4.sin_port));
	}
	else if (is_ipv6()) {
		ret.sprintf("<[%s]:%d>", tmp, ntohs(v6.sin6_port));
	}

	return ret;
}

const char* ipaddr::to_sinful(char* buf, int len) const
{
	char tmp[IP_STRING_BUF_SIZE];
		// if it is not ipv4 or ipv6, to_ip_string_ex will fail.
	if ( !to_ip_string_ex(tmp, IP_STRING_BUF_SIZE) )
		return NULL;

	if (is_ipv4()) {
		snprintf(buf, len, "<%s:%d>", tmp, ntohs(v4.sin_port));
	}
	else if (is_ipv6()) {
		snprintf(buf, len, "<[%s]:%d>", tmp, ntohs(v6.sin6_port));
	}

	return buf;
}

// faithful reimplementation of 'string_to_sin' of internet.c
bool ipaddr::from_sinful(const char* sinful)
{
	const char* addr = sinful;
	bool ipv6 = false;
	const char* addr_begin = NULL;
	const char* port_begin = NULL;
	int addr_len = 0;
	int port_len = 0;
	if ( *addr != '<' ) return false;
	addr++;
	if ( *addr == '[' ) {
		ipv6 = true;
		addr_begin = addr;
		addr++;

		while( *addr && *addr != ']' )
			addr++;

		if ( *addr == 0 ) return false;

		addr_len = addr-addr_begin;
		addr++;
	}
	else {
		addr_begin = addr;
		while ( *addr && *addr != ':' && *addr != '>' )
			addr++;

		if ( *addr == 0 ) return false;

		addr_len = addr-addr_begin;
		// you should not do 'addr++' here
	}

	if ( *addr == ':' ) {
		addr++;
		port_begin = addr;
		port_len = strspn(addr, "0123456789");
		addr += port_len;
	}
	if ( *addr == '?' ) {
		addr++;
		int len = strcspn(addr, ">");
		addr += len;
	}

	if ( addr[0] != '>' || addr[1] != '\0' ) return false;

	clear();

	int port_no = atoi(port_begin);

	char tmp[INET6_ADDRSTRLEN];
	if ( ipv6 ) {
		if ( addr_len >= INET6_ADDRSTRLEN ) return false;
		memcpy(tmp, addr_begin, addr_len);
		tmp[addr_len] = '\0';
		v6.sin6_family = AF_INET6;
		if ( inet_pton(AF_INET6, tmp, &v6.sin6_addr) <= 0) return false;
		v6.sin6_port = htons(port_no);
	}	
	else {
		if ( addr_len >= INET_ADDRSTRLEN ) return false;
		memcpy(tmp, addr_begin, addr_len);
		tmp[addr_len] = '\0';
		v4.sin_family = AF_INET;
		if ( inet_pton(AF_INET, tmp, &v4.sin_addr) <= 0) return false;
		v4.sin_port = htons(port_no);
	}
	return true;
}

sockaddr* ipaddr::to_sockaddr() const
{
	return (sockaddr*)&storage;
}

socklen_t ipaddr::get_socklen() const
{
	if (is_ipv4())
		return sizeof(sockaddr_in);
	else if (is_ipv6())
		return sizeof(sockaddr_in6);
	else
		return sizeof(sockaddr_storage);
}

bool ipaddr::from_ip_string(const MyString& ip_string)
{
	return from_ip_string(ip_string.Value());
}

bool ipaddr::from_ip_string(const char* ip_string)
{
	if (inet_pton(AF_INET, ip_string, &v4.sin_addr) == 1) {
		v4.sin_family = AF_INET;
		v4.sin_port = 0;
		return true;
	} else if (inet_pton(AF_INET, ip_string, &v6.sin6_addr) == 1) {
		v6.sin6_family = AF_INET6;
		v6.sin6_port = 0;
		return true;
	}
	return false;
}

/*
const char* ipaddr::to_ip_string(char* buf, int len) const
{
	if (is_addr_any())
		return get_local_ipaddr().to_raw_ip_string(buf, len);
	else
		return to_raw_ip_string(buf, len);
}

MyString ipaddr::to_ip_string() const
{
	if (is_addr_any())
		return get_local_ipaddr().to_raw_ip_string();
	else
		return to_raw_ip_string();
}
*/

const char* ipaddr::to_ip_string(char* buf, int len) const
{
	if ( is_ipv4() ) 
		return inet_ntop(AF_INET, &v4.sin_addr, buf, len);	
	else if (is_ipv6()) {
			// [m] Special Case for IPv4-mapped-IPv6 string
			// certain implementation such as IpVerify internally uses
			// IPv6 format to store all IP addresses.
			// Although they use IPv6 address, they rely on
			// IPv4-style text representation.
			// for example, IPv4-mapped-IPv6 string will be shown as
			// a form of '::ffff:a.b.c.d', however they need
			// 'a.b.c.d'
			//
			// These reliance should be corrected at some point.
			// hopefully, at IPv6-Phase3
		uint32_t* addr = (uint32_t*)&v6.sin6_addr;
		if (addr[0] == 0 && addr[1] == 0 && addr[2] == htonl(0xffff)) {
			return inet_ntop(AF_INET, (const void*)&addr[3], buf, len);
		}

		return inet_ntop(AF_INET6, &v6.sin6_addr, buf, len);
	}
	else 
		return NULL;
}

MyString ipaddr::to_ip_string() const
{
	char tmp[IP_STRING_BUF_SIZE];
	MyString ret;
	if ( !to_ip_string(tmp, IP_STRING_BUF_SIZE) )
		return ret;
	ret = tmp;
	return ret;
}

MyString ipaddr::to_ip_string_ex() const
{
		// no need to check is_valid()
	if ( is_addr_any() )
		return get_local_ipaddr().to_ip_string();
	else
		return to_ip_string();
}

const char* ipaddr::to_ip_string_ex(char* buf, int len) const
{
		// no need to check is_valid()
	if (is_addr_any())
		return get_local_ipaddr().to_ip_string(buf, len);
	else
		return to_ip_string(buf, len);
}

bool ipaddr::is_valid() const
{
		// the field name of sockaddr_storage differs from platform to
		// platform. For AIX, it defines __ss_family while others usually
		// define ss_family. Also, the layout is not quite same.
		// some defines length before ss_family.
		// So, here, we use sockaddr_in and sockaddr_in6 directly.
	return v4.sin_family == AF_INET || v6.sin6_family == AF_INET6;
}

bool ipaddr::is_private_network() const
{
	if (is_ipv4()) {
		uint32_t ip = (uint32_t)v4.sin_addr.s_addr;
		return ((ip & 0xFF000000) == 0x0A000000 ||      // 10/8
				(ip & 0xFFF00000) == 0xAC100000 ||      // 172.16/12
				(ip & 0xFFFF0000) == 0xC0A80000);       // 192.168/16
	}
	else if (is_ipv6()) {
		return IN6_IS_ADDR_LINKLOCAL(&v6.sin6_addr);
	}
	else {

	}
	return false;
}

void ipaddr::set_ipv4() 
{
	v4.sin_family = AF_INET;
}

int ipaddr::get_aftype() const
{
	if (is_ipv4())
		return AF_INET;
	else if (is_ipv6())
		return AF_INET6;
	return AF_UNSPEC;
}

in6_addr ipaddr::to_ipv6_address() const
{
	if (is_ipv6()) return v6.sin6_addr;
	in6_addr ret;
		// the field name of struct in6_addr is differ from platform to
		// platform. thus, we use a pointer.
	uint32_t* addr = (uint32_t*)&ret;
	addr[0] = 0;
	addr[1] = 0;
	addr[2] = htonl(0xffff);
	addr[3] = v4.sin_addr.s_addr;
	return ret;
}

bool ipaddr::compare_address(const ipaddr& addr) const
{
	if (is_ipv4()) {
		if (!addr.is_ipv4())
			return false;
		return v4.sin_addr.s_addr == addr.v4.sin_addr.s_addr;
	} else if (is_ipv6()) {
		if (!addr.is_ipv6())
			return false;
		return memcmp((const void*)&v6.sin6_addr,
					  (const void*)&addr.v6.sin6_addr,
					  sizeof(in6_addr)) == 0;
	}
	return false;
}

// lexicographical ordering of IP address
// 1. compare aftype
// 2. compare address
// 3. compare port

bool ipaddr::operator<(const ipaddr& rhs) const
{
	const void* l = (const void*)&storage;
	const void* r = (const void*)&rhs.storage;
	return memcmp(l, r, sizeof(sockaddr_storage)) < 0;
}

bool ipaddr::operator==(const ipaddr& rhs) const
{
	const void* l = (const void*)&storage;
	const void* r = (const void*)&rhs.storage;
	return memcmp(l, r, sizeof(sockaddr_storage)) == 0;
}