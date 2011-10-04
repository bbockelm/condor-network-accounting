
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <linux/sched.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>

extern int handle_match(const char *, long long);

// Below is the raw nasty netlink stuff
// I find it much easier to do this in straight-up C.

/**
 *  Create a socket to talk to the kernel via netlink
 *  Returns the socket fd upon success, or -errno upon failure
 */

int seq;

int create_socket() {
	int sock;
	sock = socket (AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (sock == -1) {
		fprintf(stderr, "Unable to create a netlink socket: %s\n", strerror(errno));
		return -errno;
	}

	struct sockaddr_nl addr = {
		.nl_family = AF_NETLINK,
		.nl_pid = getpid (),
		.nl_groups = 0,
	};
    
	int result = bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_nl));
	if (result == -1) {
		fprintf(stderr, "Unable to bind netlink socket to kernel: %s\n", strerror(errno));
		return -errno;
	}
    
		return sock;
}

static int send_to_kernel(int sock, struct iovec* iov, size_t ioveclen) {

	if (sock < 0) {
		fprintf(stderr, "Invalid socket: %d.\n", sock);
		return 1;
	}

	struct sockaddr_nl nladdr = {
		.nl_family = AF_NETLINK,
		.nl_pid = 0,
		.nl_groups = 0,
	};
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = iov,
		.msg_iovlen = ioveclen,
	};

	if (sendmsg(sock, &msg, 0) < 0) {
		fprintf(stderr, "Unable to send create_veth message to kernel: %d %s\n", errno, strerror(errno));
		return errno;
	}
	return 0;
}

static int send_and_ack(int sock, struct iovec* iov, size_t ioveclen) {

	int rc;
	if ((rc = send_to_kernel(sock, iov, ioveclen))) {
		fprintf(stderr, "Send to kernel failed: %d\n", rc);
		return rc;
	} 
	if ((rc = recv_message(sock))) {
		fprintf(stderr, "Message not successfully ACK'd: %d.\n", rc);
		return rc;
	}
	return 0;

}


#define VETH "veth"
#define VETH_LEN strlen(VETH)
int create_veth(int sock, const char * veth0, const char * veth1) {

	struct iovec iov[12];

	size_t veth0_len = strlen(veth0);
	size_t veth1_len = strlen(veth1);
	if (veth0_len >= IFNAMSIZ) {
		fprintf(stderr, "Name too long for network device: %s (size %d, max %d).\n", veth0, veth0_len, IFNAMSIZ);
		return 1;
	}
	if (veth1_len >= IFNAMSIZ) {
		fprintf(stderr, "Name too long for network device: %s\n", veth1, veth1_len, IFNAMSIZ);
		return 1;
	}

	// Create the header of the netlink message
	struct nlmsghdr nlmsghdr = {
		.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)) + RTA_LENGTH(0) + RTA_LENGTH(VETH_LEN) + 
			RTA_LENGTH(0) + RTA_LENGTH(0) + NLMSG_ALIGN(sizeof(struct ifinfomsg)) + 
			RTA_LENGTH(0) + RTA_ALIGN(veth1_len) + RTA_LENGTH(0) + RTA_ALIGN(veth0_len),
		.nlmsg_type = RTM_NEWLINK,
		.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK,
		.nlmsg_seq = ++seq,
		.nlmsg_pid = 0,
	};
	iov[0].iov_base = &nlmsghdr;
	iov[0].iov_len = NLMSG_LENGTH (0);

	// Request the link
	struct ifinfomsg info_msg = {
		.ifi_family = AF_UNSPEC,
	};
	iov[1].iov_base = &info_msg;
	iov[1].iov_len = NLMSG_ALIGN(sizeof(struct ifinfomsg));

	struct rtattr rta;
	rta.rta_type = IFLA_LINKINFO;
	rta.rta_len = RTA_LENGTH(0) + RTA_LENGTH(VETH_LEN) + RTA_LENGTH(0) + RTA_LENGTH(0) + NLMSG_ALIGN(sizeof(struct ifinfomsg)) + RTA_LENGTH(0) + RTA_ALIGN(veth1_len);;
	iov[2].iov_base = &rta;
	iov[2].iov_len = RTA_LENGTH(0);

	struct rtattr rta2;
	rta2.rta_type = IFLA_INFO_KIND;
	rta2.rta_len = RTA_LENGTH(VETH_LEN);
	iov[3].iov_base = &rta2;
	iov[3].iov_len = RTA_LENGTH(0);

	char type[VETH_LEN];
	memcpy(type, VETH, VETH_LEN);
	iov[4].iov_base = type;
	iov[4].iov_len = RTA_ALIGN(VETH_LEN);

	struct rtattr rta3 = {
		.rta_type = IFLA_INFO_DATA,
		.rta_len = RTA_LENGTH(0) + RTA_LENGTH(0) + NLMSG_ALIGN(sizeof(struct ifinfomsg)) + RTA_LENGTH(0) + RTA_ALIGN(veth1_len),
	};
	iov[5].iov_base = &rta3;
	iov[5].iov_len = RTA_LENGTH(0);

	struct rtattr rta4 = {
		.rta_type =  VETH_INFO_PEER,
		.rta_len = RTA_LENGTH(0) + NLMSG_ALIGN(sizeof(struct ifinfomsg)) + RTA_LENGTH(0) + RTA_ALIGN(veth1_len),
	};
	iov[6].iov_base = &rta4;
	iov[6].iov_len = RTA_LENGTH(0);

	// Add hole of size of size ifinfomsg
	struct ifinfomsg info_msg2 = {};
	iov[7].iov_base = &info_msg2;
	iov[7].iov_len = NLMSG_ALIGN(sizeof(struct ifinfomsg));
	

	struct rtattr rta5 = {
		.rta_type = IFLA_IFNAME,
		.rta_len = RTA_LENGTH(veth1_len),
	};
	iov[8].iov_base = &rta5;
	iov[8].iov_len = RTA_LENGTH(0);

	char veth1_copy[IFNAMSIZ];
	memcpy(veth1_copy, veth1, veth1_len);
	iov[9].iov_base = veth1_copy;
	iov[9].iov_len = RTA_ALIGN(veth1_len);

	struct rtattr rta6 = {
		.rta_type = IFLA_IFNAME,
		.rta_len = RTA_LENGTH(veth0_len),
	};
	iov[10].iov_base = &rta6;
	iov[10].iov_len = RTA_LENGTH(0);

	char veth0_copy[IFNAMSIZ];
	memcpy(veth0_copy, veth0, veth0_len);
	iov[11].iov_base = veth0_copy;
	iov[11].iov_len = RTA_ALIGN(veth0_len);

	return send_and_ack(sock, iov, 12);
}

int delete_veth(int sock, const char * eth) {

	struct iovec iov[2];

	struct nlmsghdr nlmsghdr = {
		.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.nlmsg_type = RTM_DELLINK,
		.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK,
		.nlmsg_seq = ++seq,
		.nlmsg_pid = 0,
	};
	iov[0].iov_base = &nlmsghdr;
	iov[0].iov_len = NLMSG_LENGTH(0);

	struct ifinfomsg info_msg = {
		.ifi_family = AF_UNSPEC,
		.ifi_index = if_nametoindex(eth),
	};
	iov[1].iov_base = &info_msg;
	iov[1].iov_len = NLMSG_ALIGN(sizeof(struct ifinfomsg));

	return send_and_ack(sock, iov, 2);

}

int set_status(int sock, const char * eth, int status) {

	struct iovec iov[2];

	struct nlmsghdr nlmsghdr = {
		.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.nlmsg_type = RTM_NEWLINK,
		.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK,
		.nlmsg_seq = ++seq,
		.nlmsg_pid = 0,
	};
	iov[0].iov_base = &nlmsghdr;
	iov[0].iov_len = NLMSG_LENGTH(0);

	struct ifinfomsg info_msg = {
		.ifi_family = AF_UNSPEC,
		.ifi_index = if_nametoindex(eth),
		.ifi_change = IFF_UP,
	};
	info_msg.ifi_flags = (status == IFF_UP) ? IFF_UP : 0;
	iov[1].iov_base = &info_msg;
	iov[1].iov_len = NLMSG_ALIGN(sizeof(struct ifinfomsg));

	return send_and_ack(sock, iov, 2);

}

#define INET_LEN 4
#define INET_PREFIX_LEN 32
int add_address(int sock, const char * addr, const char * eth) {

	struct iovec iov[4];

	struct nlmsghdr nlmsghdr = {
		.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)) + RTA_LENGTH(INET_LEN),
		.nlmsg_type = RTM_NEWADDR,
		.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK,
		.nlmsg_seq = ++seq,
		.nlmsg_pid = 0,
	};
	iov[0].iov_base = &nlmsghdr;
	iov[0].iov_len = NLMSG_LENGTH(0);

	// TODO: ipv6 support
	unsigned char ipv4_addr[4];
	if (inet_pton(AF_INET, addr, (void *)&ipv4_addr) != 1) {
		fprintf(stderr, "Invalid IP address: %s\n", addr);
		return 1;
	}

	unsigned eth_dev;
	if (!(eth_dev = if_nametoindex(eth))) {
		fprintf(stderr, "Unable to determine index of %s.\n", eth);
		return 1;
	}

	struct ifaddrmsg info_msg = {
		.ifa_family = AF_INET,
		.ifa_prefixlen = INET_PREFIX_LEN,
		.ifa_index = if_nametoindex(eth),
	};
	iov[1].iov_base = &info_msg;
	iov[1].iov_len = NLMSG_ALIGN(sizeof(struct ifaddrmsg));

	struct rtattr rta;
	rta.rta_type = IFA_LOCAL;
	rta.rta_len = RTA_LENGTH(INET_LEN);
	iov[2].iov_base = &rta;
	iov[2].iov_len = RTA_LENGTH(0);

	iov[3].iov_base = ipv4_addr;
	iov[3].iov_len = RTA_ALIGN(INET_LEN);
        
	return send_and_ack(sock, iov, 4);

}

int add_local_route(int sock, const char * gw, const char * eth, int dst_len) {

	// Equivalent to:
	// ip route add default via 10.10.10.1
	// internally, default = 0/0
	struct iovec iov[6];

	unsigned char ipv4_addr[4];
	if (inet_pton(AF_INET, gw, (void *)&ipv4_addr) != 1) {
		fprintf(stderr, "Invalid IP address: %s\n", gw);
		return 1;
	}
	if (dst_len == 24) {
		ipv4_addr[3] = 0;
	} else {
		fprintf(stderr, "For the time being, only /24 local routes are supported (dst_len=%d).\n", dst_len);
		return 1;
	}
	//fprintf(stderr, "Ip address: %d.%d.%d.%d\n", ipv4_addr[0], ipv4_addr[1], ipv4_addr[2], ipv4_addr[3]);

	unsigned eth_dev;
	if (!(eth_dev = if_nametoindex(eth))) {
		fprintf(stderr, "Unable to determine index of %s.\n", eth);
		return 1;
	}

	struct nlmsghdr nlmsghdr = {
		.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)) + RTA_LENGTH(INET_LEN) + RTA_LENGTH(sizeof(unsigned)),
		.nlmsg_type = RTM_NEWROUTE,
		.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK,
		.nlmsg_seq = ++seq,
		.nlmsg_pid = 0,
	};
	iov[0].iov_base = &nlmsghdr;
	iov[0].iov_len = NLMSG_LENGTH(0);

	struct rtmsg rtmsg = {
		.rtm_family = AF_INET,
		.rtm_dst_len = dst_len,
		.rtm_table = RT_TABLE_MAIN,
		.rtm_protocol = RTPROT_KERNEL,
		.rtm_scope = RT_SCOPE_LINK,
		.rtm_type = RTN_UNICAST,
	};
	iov[1].iov_base = &rtmsg;
	iov[1].iov_len = NLMSG_ALIGN(sizeof(struct rtmsg)); // Note: not sure if there's a better alignment here

	struct rtattr rta = {
		.rta_type = RTA_DST,
		.rta_len = RTA_LENGTH(INET_LEN),
	};
	iov[2].iov_base = &rta;
	iov[2].iov_len = RTA_LENGTH(0);

	iov[3].iov_base = ipv4_addr;	
	iov[3].iov_len = RTA_ALIGN(INET_LEN);

	struct rtattr rta2 = {
		.rta_type = RTA_OIF,
		.rta_len = RTA_LENGTH(sizeof(unsigned)),
	};
	iov[4].iov_base = &rta2;
	iov[4].iov_len = RTA_LENGTH(0);

	iov[5].iov_base = &eth_dev;
	iov[5].iov_len = RTA_ALIGN(sizeof(unsigned));

	return send_and_ack(sock, iov, 6);
}

int add_default_route(int sock, const char * gw) {

	// Equivalent to:
	// ip route add default via 10.10.10.1
	// internally, default = 0/0
	struct iovec iov[4];

	// Setup the dest address/prefix
	char dest_addr[4]; dest_addr[0] = 0; dest_addr[1] = 0; dest_addr[2] = 0; dest_addr[3] = 0;
	size_t dst_len = 0;

	// TODO: ipv6 support
	unsigned char ipv4_addr[4];
	if (inet_pton(AF_INET, gw, (void *)&ipv4_addr) != 1) {
		fprintf(stderr, "Invalid IP address: %s\n", gw);
		return 1;
	}
	ipv4_addr[3] = 1;
	//fprintf(stderr, "Ip address: %d.%d.%d.%d\n", ipv4_addr[0], ipv4_addr[1], ipv4_addr[2], ipv4_addr[3]);

	struct nlmsghdr nlmsghdr = {
		.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)) + RTA_LENGTH(INET_LEN),
		.nlmsg_type = RTM_NEWROUTE,
		.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK,
		.nlmsg_seq = ++seq,
		.nlmsg_pid = 0,
	};
	iov[0].iov_base = &nlmsghdr;
	iov[0].iov_len = NLMSG_LENGTH(0);

	struct rtmsg rtmsg = {
		.rtm_family = AF_INET,
		.rtm_dst_len = dst_len,
		.rtm_table = RT_TABLE_MAIN,
		.rtm_protocol = RTPROT_BOOT,
		.rtm_scope = RT_SCOPE_UNIVERSE,
		.rtm_type = RTN_UNICAST,
	};
	iov[1].iov_base = &rtmsg;
	iov[1].iov_len = NLMSG_ALIGN(sizeof(struct rtmsg)); // Note: not sure if there's a better alignment here
	struct rtattr rta2 = {
		.rta_type = RTA_GATEWAY,
		.rta_len = RTA_LENGTH(INET_LEN),
	};
	iov[2].iov_base = &rta2;
	iov[2].iov_len = RTA_LENGTH(0);

	iov[3].iov_base = ipv4_addr;
	iov[3].iov_len = RTA_ALIGN(INET_LEN);
	return send_and_ack(sock, iov, 4);
}

#define PID_T_LEN sizeof(pid_t)
int set_netns(int sock, const char * eth, pid_t pid) {

	struct iovec iov[4];

	struct nlmsghdr nlmsghdr = {
		.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)) + RTA_LENGTH(PID_T_LEN),
		.nlmsg_type = RTM_NEWLINK,
		.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK,
		.nlmsg_seq = ++seq,
		.nlmsg_pid = 0,
	};
	iov[0].iov_base = &nlmsghdr;
	iov[0].iov_len = NLMSG_LENGTH(0);

	struct ifinfomsg info_msg = {
		.ifi_family = AF_UNSPEC,
		.ifi_index = if_nametoindex(eth),
	};
	iov[1].iov_base = &info_msg;
	iov[1].iov_len = NLMSG_ALIGN(sizeof(struct ifinfomsg));

	struct rtattr rta = {
		.rta_type = IFLA_NET_NS_PID,
		.rta_len = RTA_LENGTH(PID_T_LEN),
	};
	iov[2].iov_base = &rta;
	iov[2].iov_len = RTA_LENGTH(0);

	iov[3].iov_base = &pid;
	iov[3].iov_len = RTA_ALIGN(PID_T_LEN);

	return send_and_ack(sock, iov, 4);
}

int recv_message(int sock) {

	struct msghdr msghdr;
	struct sockaddr_nl addr;
	struct iovec iov[1];
	char buf[getpagesize()];
	ssize_t len;

	msghdr.msg_name = &addr;
	msghdr.msg_namelen = sizeof addr;
	msghdr.msg_iov = iov;
	msghdr.msg_iovlen = 1;
	msghdr.msg_control = NULL;
	msghdr.msg_controllen = 0;
	msghdr.msg_flags = 0;

	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof buf;

	struct nlmsghdr *nlmsghdr;

	len = recvmsg (sock, &msghdr, 0);

	for (nlmsghdr = (struct nlmsghdr *)buf; NLMSG_OK (nlmsghdr, len); nlmsghdr = NLMSG_NEXT (nlmsghdr, len)) {

		if (nlmsghdr->nlmsg_type == NLMSG_NOOP) {
			fprintf(stderr, "Ignoring message due to error.\n");
			continue;
		}
	
		if (nlmsghdr->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(nlmsghdr);
			if (nlmsghdr->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
				fprintf(stderr, "Error message truncated.\n");
				return 1;
			} else if (err->error) {
				fprintf(stderr, "Error message back from netlink: %d %s\n", -err->error, strerror(-err->error));
				errno = -err->error;
				return errno;
			} else {
				//fprintf(stderr, "Ack received - no error.\n");
				return 0;
			}
			return 1;
		}

		fprintf(stderr, "Unknown message type: %d\n", nlmsghdr->nlmsg_type);

	}

}

int setup_pipes(int *p2c, int *c2p) {
	
	if (pipe(p2c)) {
		fprintf(stderr, "Unable to create the parent-to-child communication pipe. (errno=%d) %s\n", errno, strerror(errno));
		return errno;
	}
	if (pipe(c2p)) {
		fprintf(stderr, "Unable to create the child-to-parent communication pipe. (errno=%d) %s\n", errno, strerror(errno));
		return errno;
	}

	// The child side of both pipes should be set to F_CLOEXEC
	int fd_flags;
	if ((fd_flags = fcntl(p2c[0], F_GETFD, NULL)) == -1) {
		fprintf(stderr, "Failed to get fd flags: (errno=%d) %s\n", errno, strerror(errno));
		return errno;
	}
	if (fcntl(p2c[0], F_SETFD, fd_flags | FD_CLOEXEC) == -1) {
		fprintf(stderr, "Failed to set new fd flags: (errno=%d) %s\n", errno, strerror(errno));
		return errno;
	}
	if ((fd_flags = fcntl(c2p[1], F_GETFD, NULL)) == -1) {
		fprintf(stderr, "Failed to get fd flags: (errno=%d) %s\n", errno, strerror(errno));
		return errno;
	}
	if (fcntl(c2p[1], F_SETFD, fd_flags | FD_CLOEXEC) == -1) {
		fprintf(stderr, "Failed to set new fd flags: (errno=%d) %s\n", errno, strerror(errno));
		return errno;
	}

}

#define SHELL_MAX 512
#define ADDR_MAX 32
char * create_outer_routing(const char * script, const char * jobid, const char * eth) {
	FILE * fp;
	char * addr = NULL;
	int rc = 0;
	int child_status = 0;

	char script_shell[SHELL_MAX];
	if (snprintf(script_shell, SHELL_MAX, "%s %s %s", script, jobid, eth) >= SHELL_MAX) {
		fprintf(stderr, "Too-long arguments for the routing script: %s %s %s\n", script, jobid, eth);
		return NULL;
	}

	// Execute the script to setup the NAT
	if (!(fp = popen(script_shell, "r"))) {
		fprintf(stderr, "Unable to execute the NAT script. (errno=%d) %s\n", errno, strerror(errno));
		goto finalize;
	}
	addr = (char *)malloc(ADDR_MAX);
	if (!addr) goto finalize;
	if (fgets(addr, ADDR_MAX, fp) == NULL) {
		fprintf(stderr, "Did not read an address from the NAT script.\n");
		rc = 1;
		goto finalize;
	}
	if ((child_status = pclose(fp)) == -1) {
		fprintf(stderr, "Unable to retrieve NAT script status. (errno=%d) %s\n", errno, strerror(errno));
		fp = NULL;
		rc = 1;
		goto finalize;
	}
	fp = NULL;
	if (WIFEXITED(child_status)) {
		if ((rc = WEXITSTATUS(child_status))) {
			fprintf(stderr, "NAT script returned non-zero status %d.\n", rc);
			rc = 1;
			goto finalize;
		}
	} else {
		fprintf(stderr, "Unable to understand child exit status %d.\n", child_status);
		rc = 1;
		goto finalize;
	}
	// inet_pton doesn't like newlines in the address.
	char *first_newline = strchr(addr, '\n');
	if (first_newline) {
		*first_newline = '\0';
	}

finalize:
	if (fp) {
		pclose(fp);
	}
	if (rc && addr) {
		free(addr);
		addr = NULL;
	}
	return addr;
}

int delete_outer_routing(const char * script, const char * jobid, const char * eth) {
        FILE * fp;
	int child_status = 0;
	int rc = 0;

	char script_shell[SHELL_MAX];
	if (snprintf(script_shell, SHELL_MAX, "%s %s %s", script, jobid, eth) >= SHELL_MAX) {
		fprintf(stderr, "Too-long arguments for the routing script: %s %s %s\n", script, jobid, eth);
		return 1;
	}

	// Execute the script to setup the NAT
	if (!(fp = popen(script_shell, "r"))) {
		fprintf(stderr, "Unable to execute the NAT delete script. (errno=%d) %s\n", errno, strerror(errno));
		rc = errno;
		goto finalize;
	}
	if ((child_status = pclose(fp)) == -1) {
		fprintf(stderr, "Unable to retrieve NAT delete script status. (errno=%d) %s\n", errno, strerror(errno));
		fp = NULL;
		rc = errno;
		goto finalize;
	}
	fp = NULL;
	if (WIFEXITED(child_status)) {
		if ((rc = WEXITSTATUS(child_status))) {
			fprintf(stderr, "NAT delete script returned non-zero status %d.\n", rc);
			goto finalize;
		}
	} else {
		fprintf(stderr, "Unable to understand child exit status %d.\n", child_status);
		rc = 1;
		goto finalize;
	}

finalize:
	if (fp) {
		pclose(fp);
	}
	return rc;
}

struct child_info {
	int p2c[2];
	int c2p[2];
	const char * addr;
	const char * eth;
};

int child_post_fork(void * info_ptr) {

	struct child_info *info = (struct child_info *)info_ptr;
	close(info->p2c[1]);
	close(info->c2p[0]);

	int rc = 0;
	// TODO: synchronize with parent, wait until it is finished with the socket.
	// Must know we are in our own NETNS first, otherwise there is no veth device!
	int parent_status;
	if (read(info->p2c[0], &parent_status, sizeof(int)) != sizeof(int)) { // TODO make EINTR safe
		fprintf(stderr, "Unable to read status from parent - probable parent failure.\n");
		rc = 1;
		goto finalize_child;
	}
	if (parent_status != 0) {
		fprintf(stderr, "Parent failed to setup the namespace.\n");
		rc = 1;
	}

	// Remount /sys and /proc
	if (mount("proc", "/proc", "proc", 0, 0) == -1) {
		rc = errno;
		fprintf(stderr, "Unable to remount /proc. (errno=%d) %s\n", errno, strerror(errno));
		goto finalize_child;
	}

	if (mount("sysfs", "/sys", "sysfs", 0, 0) == -1) {
		rc = errno;
		fprintf(stderr, "Unable to remount /sys. (errno=%d) %s\n", errno, strerror(errno));
		goto finalize_child;
	}

	// Manipulate our network configuration.
	// Notice that we open a new socket to the kernel - this is because the
	// other socket still talks to the original namespace.
	int sock;
	if ((sock = create_socket()) < 0) {
		fprintf(stderr, "Unable to create socket to talk to kernel for child.\n");
		rc = 1;
		goto finalize_child;
	}
	if (add_address(sock, info->addr, info->eth)) {
		fprintf(stderr, "Unable to add address %s to %s.\n", info->addr, info->eth);
		rc = 1;
		goto finalize_child;
	}
	if (set_status(sock, info->eth, IFF_UP)) {
		fprintf(stderr, "Unable to bring up interface %s.\n", info->eth);
		rc = 3;
		goto finalize_child;
	}
	if (add_local_route(sock, info->addr, info->eth, 24)) {
		fprintf(stderr, "Unable to add local route via %s\n", info->addr);
		rc = 4;
		goto finalize_child;
	}
	if (add_default_route(sock, info->addr)) {
		fprintf(stderr, "Unable to add default route via %s\n", info->addr);
		rc = 2;
		goto finalize_child;
	}
	close(sock);

	// Exec out.
	rc = execl("/bin/sh", "sh", "-c", "date; ifconfig -a; route -n; curl 129.93.1.141;", (char *)0);
	fprintf(stderr, "Failure to exec /bin/sh. (errno=%d) %s\n", errno, errno, strerror(errno));

finalize_child:
	// TODO: Inform parent we failed to exec.
	write(info->c2p[1], &rc, sizeof(int));
	close(info->c2p[0]);
	close(info->p2c[0]);
	_exit(rc);
}

#define NUMBER_PAGES 16
int main(int argc, char * argv[]) {

	int rc = 0, rc2;
	int sock = -1;
	int created = 0, routed = 0;
	int p2c[2] = {-1, -1};
	int c2p[2] = {-1, -1};
	int child_status = -1;
	char *addr = NULL;
	FILE * fp;
	char * child_stack_ptr, *child_stack = NULL;

	const char * veth0 = "v_external";
	const char * veth1 = "v_internal";

	child_stack = (char *)malloc(NUMBER_PAGES*getpagesize());
	if (!child_stack) {
		fprintf(stderr, "Unable to prepare child stack.\n");
		return 1;
	}
	child_stack_ptr = child_stack + NUMBER_PAGES*getpagesize();

	seq = time(NULL);

	if (setup_pipes(p2c, c2p)) {
		fprintf(stderr, "Unable to setup synchronization pipes.\n");
		rc = 1;
		goto finalize;
	}

	if ((sock = create_socket()) < 0) {
		fprintf(stderr, "Unable to create socket to talk to kernel.\n");
		rc = 1;
		goto finalize;
	}

	if ((rc = create_veth(sock, veth0, veth1))) {
		fprintf(stderr, "Failed to create veth devices %s/%s.\n", veth0, veth1);
		goto finalize;
	}
	created = 1;

	//printf("Created a new veth device.\n");
	routed = 1;
	if (!(addr = create_outer_routing("./nat_script.sh", "JOBID", veth0))) {
		fprintf(stderr, "Failed to create the routing.\n");
		goto finalize;
	}

	// fork/exec the child process (actually, clone/exec so we can manipulate the namespaces)
	struct child_info info = {
		.addr = addr,
		.eth = veth1,
	};
	info.p2c[0] = p2c[0]; info.p2c[1] = p2c[1];
	info.c2p[0] = c2p[0]; info.c2p[1] = c2p[1];
	// Note: only returns for the parent, not the child.
	pid_t fork_pid = clone(child_post_fork, (void *)child_stack_ptr,
		//CLONE_NEWNS|CLONE_NEWNET|CLONE_NEWPID|CLONE_VM|SIGCHLD,
		CLONE_NEWNS|CLONE_NEWNET|CLONE_NEWPID|SIGCHLD,
		(void *)&info);
	if (fork_pid == -1) {
		rc = 3;
		fprintf(stderr, "Failed to create a new process. (errno=%d) %s\n", errno, strerror(errno));
		goto finalize;
	}
	//fprintf(stderr, "Child PID %d\n", fork_pid);

	// Close out the child end of the pipes.
	close(p2c[0]); p2c[0] = -1;
	close(c2p[1]); c2p[1] = -1;

	if ((rc = set_netns(sock, veth1, fork_pid))) {
		fprintf(stderr, "Failed to set ns\n");
		write(p2c[1], &rc, sizeof(int));
		goto finalize;
	}
	write(p2c[1], &rc, sizeof(int));
	close(p2c[1]); p2c[1] = -1;

	if ((rc = read(c2p[0], &child_status, sizeof(int))) == sizeof(int)) {
		if (child_status) {
			fprintf(stderr, "Child failed to launch\n");
			rc = child_status;
			goto finalize;
		} else {
			fprintf(stderr, "Error: Child failed to launch, but set 0 status\n");
			rc = 1;
			goto finalize;
		}
	} else {
		//fprintf(stderr, "Child successfully launched (rc=%d)\n", rc);
	}
	close(c2p[0]); c2p[0]= -1;

	// Wait for the user to exit the child.
	if ((rc2 = waitpid(fork_pid, &child_status, 0)) == -1) {
		fprintf(stderr, "Unable to get child %d status. (errno=%d) %s\n", fork_pid, errno, strerror(errno));
		rc = errno;
		goto finalize;
	}
	if (WIFEXITED(child_status)) {
		if ((rc = WEXITSTATUS(child_status))) {
			fprintf(stderr, "Child returned non-zero status %d.\n", rc);
			goto finalize;
		}
		//fprintf(stderr, "Child finished (status=%d)\n", child_status);
	} else {
		fprintf(stderr, "Unable to understand child exit status %d.\n", child_status);
		goto finalize;
	}

	perform_accounting("JOBID", handle_match);

finalize:
	if (created) {
		//fprintf(stderr, "Trying to delete the created veth device.\n");
		if (delete_veth(sock, veth0)) {
			fprintf(stderr, "Unable to cleanup created device %s.\n", veth0);
			rc = 2;
		}
	}
	if (routed) {
		if (delete_outer_routing("./nat_delete_script.sh", "JOBID", veth0)) {
			fprintf(stderr, "Unable to successfully delete routes for %s\n", "JOBID");
		}
	}
	if (addr) {
		free(addr);
	}
	if (sock != -1) {
		close(sock);
	}
	if (p2c[0] != -1) {
		close(p2c[0]);
	}
	if (p2c[1] != -1) {
		close(p2c[1]);
	}
	if (c2p[0] != -1) {
		close(c2p[0]);
	}
	if (c2p[1] != -1) {
		close(c2p[1]);
	}
	if (child_stack) {
		free(child_stack);
	}
	return rc;
}
