// license:BSD-3-Clause
// copyright-holders:Kelvin Sherlock


/*
 https://developer.apple.com/documentation/vmnet

 A sandboxed user space process must have the com.apple.vm.networking entitlement
 in order to use vmnet API.

 clang -framework vmnet -framework Foundation
*/

#if defined(OSD_NET_USE_VMNET)



#include "emu.h"
#include "osdnet.h"
#include "modules/osdmodule.h"
#include "netdev_module.h"


#include <cstdint>
#include <cstdlib>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <string>

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <mach-o/dyld.h>


enum {
	MSG_QUIT,
	MSG_STATUS,
	MSG_READ,
	MSG_WRITE
};
#define MAKE_MSG(msg, extra) (msg | ((extra) << 8))

class vmnet_module : public osd_module, public netdev_module
{
public:

	vmnet_module() : osd_module(OSD_NETDEV_PROVIDER, "vmnet"), netdev_module()
	{
		fprintf(stderr, "%s\n", __func__);
	}
	virtual ~vmnet_module() {}

	virtual int init(const osd_options &options);
	virtual void exit();

	virtual bool probe() { 
		fprintf(stderr, "%s\n", __func__);
		return true;
	}
};

class netdev_vmnet : public osd_netdev
{
public:
	netdev_vmnet(const char *name, class device_network_interface *ifdev, int rate);
	~netdev_vmnet();

	int send(uint8_t *buf, int len) override;
	void set_mac(const char *mac) override;
protected:
	int recv_dev(uint8_t **buf) override;
private:

	void shutdown_child();
	bool check_child();

	int message_status();
	int message_write(void *buffer, uint32_t length);
	int message_read();

	ssize_t read(void *buffer, size_t size);
	ssize_t write(const void *buffer, size_t size);

	ssize_t readv(const struct iovec *iov, int iovcnt);
	ssize_t writev(const struct iovec *iov, int iovcnt);


	char m_vmnet_mac[6];
	uint32_t m_vmnet_mtu;
	uint32_t m_vmnet_packet_size;

	char m_mac[6];

	uint8_t *m_buffer = 0;
	pid_t m_child = -1;
	int m_pipe[2];
};


/* block the sigpipe signal */
static int block_pipe(struct sigaction *oact) {
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_handler = SIG_IGN;
	act.sa_flags = SA_RESTART;

	return sigaction(SIGPIPE, &act, oact);
}
static int restore_pipe(const struct sigaction *oact) {
	return sigaction(SIGPIPE, oact, NULL);
}

static std::string get_relative_path(std::string leaf) {

	uint32_t size = 0;
	char *buffer = 0;
	int ok;


	ok = _NSGetExecutablePath(NULL, &size);
	size += leaf.length() + 1;
	buffer = (char *)malloc(size);
	if (!buffer) return leaf;

	ok = _NSGetExecutablePath(buffer, &size);
	if (ok < 0) {
		free(buffer);
		return leaf;
	}

	std::string path(buffer);
	free(buffer);

	auto pos = path.rfind('/');
	if (pos == path.npos) return leaf;

	path.resize(pos + 1);
	path += leaf;
	return path;
}


enum {
  eth_dest  = 0,  // destination address
  eth_src   = 6,  // source address
  eth_type  = 12, // packet type
  eth_data  = 14, // packet data
};

enum {
  ip_ver_ihl  = 0,
  ip_tos    = 1,
  ip_len    = 2,
  ip_id   = 4,
  ip_frag   = 6,
  ip_ttl    = 8,
  ip_proto    = 9,
  ip_header_cksum = 10,
  ip_src    = 12,
  ip_dest   = 16,
  ip_data   = 20,
};

enum {
  udp_source = 0, // source port
  udp_dest = 2, // destination port
  udp_len = 4, // length
  udp_cksum = 6, // checksum
  udp_data = 8, // total length udp header
};

enum {
  bootp_op = 0, // operation
  bootp_hw = 1, // hardware type
  bootp_hlen = 2, // hardware len
  bootp_hp = 3, // hops
  bootp_transid = 4, // transaction id
  bootp_secs = 8, // seconds since start
  bootp_flags = 10, // flags
  bootp_ipaddr = 12, // ip address knwon by client
  bootp_ipclient = 16, // client ip from server
  bootp_ipserver = 20, // server ip
  bootp_ipgateway = 24, // gateway ip
  bootp_client_hrd = 28, // client mac address
  bootp_spare = 34,
  bootp_host = 44,
  bootp_fname = 108,
  bootp_data = 236, // total length bootp packet
};

enum {
  arp_hw = 14,    // hw type (eth = 0001)
  arp_proto = 16,   // protocol (ip = 0800)
  arp_hwlen = 18,   // hw addr len (eth = 06)
  arp_protolen = 19,  // proto addr len (ip = 04)
  arp_op = 20,    // request = 0001, reply = 0002
  arp_shw = 22,   // sender hw addr
  arp_sp = 28,    // sender proto addr
  arp_thw = 32,   // target hw addr
  arp_tp = 38,    // target protoaddr
  arp_data = 42,  // total length of packet
};

enum {
  dhcp_discover = 1,
  dhcp_offer = 2,
  dhcp_request = 3,
  dhcp_decline = 4,
  dhcp_pack = 5,
  dhcp_nack = 6,
  dhcp_release = 7,
  dhcp_inform = 8,
};

// static uint8_t oo[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static uint8_t ff[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static int is_arp(const uint8_t *packet, unsigned size) {
  return size == arp_data
    && packet[12] == 0x08 && packet[13] == 0x06 /* ARP */
    && packet[14] == 0x00 && packet[15] == 0x01 /* ethernet */
    && packet[16] == 0x08 && packet[17] == 0x00 /* ipv4 */
    && packet[18] == 0x06 /* hardware size */
    && packet[19] == 0x04 /* protocol size */
  ;
}

static int is_broadcast(const uint8_t *packet, unsigned size) {
  return !memcmp(packet + 0, ff, 6);
}

static int is_unicast(const uint8_t *packet, unsigned size) {
  return (*packet & 0x01) == 0;
}

#if 0
// unused.
static int is_multicast(const uint8_t *packet, unsigned size) {
  return (*packet & 0x01) == 0x01 && !is_broadcast(packet, size);
}
#endif

static int is_dhcp_out(const uint8_t *packet, unsigned size) {
  static uint8_t cookie[] = { 0x63, 0x82, 0x53, 0x63 };
  return size >= 282
    //&& !memcmp(&packet[0], ff, 6) /* broadcast */
    && packet[12] == 0x08 && packet[13] == 0x00
    && packet[14] == 0x45 /* version 4 */
    && packet[23] == 0x11 /* UDP */
    //&& !memcmp(&packet[26], oo, 4)  /* source ip */
    //&& !memcmp(&packet[30], ff, 4)  /* dest ip */
    && packet[34] == 0x00 && packet[35] == 0x44 /* source port */
    && packet[36] == 0x00 && packet[37] == 0x43 /* dest port */
    //&& packet[44] == 0x01 /* dhcp boot req */
    && packet[43] == 0x01 /* ethernet */
    && packet[44] == 0x06 /* 6 byte mac */
    && !memcmp(&packet[278], cookie, 4)
  ;
}


static int is_dhcp_in(const uint8_t *packet, unsigned size) {
  static uint8_t cookie[] = { 0x63, 0x82, 0x53, 0x63 };
  return size >= 282
    //&& !memcmp(&packet[0], ff, 6) /* broadcast */
    && packet[12] == 0x08 && packet[13] == 0x00
    && packet[14] == 0x45 /* version 4 */
    && packet[23] == 0x11 /* UDP */
    //&& !memcmp(&packet[26], oo, 4)  /* source ip */
    //&& !memcmp(&packet[30], ff, 4)  /* dest ip */
    && packet[34] == 0x00 && packet[35] == 0x43 /* source port */
    && packet[36] == 0x00 && packet[37] == 0x44 /* dest port */
    //&& packet[44] == 0x01 /* dhcp boot req */
    && packet[43] == 0x01 /* ethernet */
    && packet[44] == 0x06 /* 6 byte mac */
    && !memcmp(&packet[278], cookie, 4)
  ;
}

#if 0
// unused.
static unsigned ip_checksum(const uint8_t *packet) {
  unsigned x = 0;
  unsigned i;
  for (i = 0; i < ip_data; i += 2) {
    if (i == ip_header_cksum) continue;
    x += packet[eth_data + i + 0 ] << 8;
    x += packet[eth_data + i + 1];
  }

  /* add the carry */
  x += x >> 16;
  x &= 0xffff;
  return ~x & 0xffff;
}
#endif

static void fix_incoming_packet(uint8_t *packet, unsigned size, const char real_mac[6], const char fake_mac[6]) {

  if (memcmp(packet + 0, real_mac, 6) == 0)
    memcpy(packet + 0, fake_mac, 6);

  /* dhcp request - fix the hardware address */
  if (is_unicast(packet, size) && is_dhcp_in(packet, size)) {
    if (!memcmp(packet + 70, real_mac, 6))
      memcpy(packet + 70, fake_mac, 6);
    return;
  }

}

static void fix_outgoing_packet(uint8_t *packet, unsigned size, const char real_mac[6], const char fake_mac[6]) {



  if (memcmp(packet + 6, fake_mac, 6) == 0)
    memcpy(packet + 6, real_mac, 6);

  if (is_arp(packet, size)) {
    /* sender mac address */
    if (!memcmp(packet + 22, fake_mac, 6))
      memcpy(packet + 22, real_mac, 6);
    return;
  }

  /* dhcp request - fix the hardware address */
  if (is_broadcast(packet, size) && is_dhcp_out(packet, size)) {

    if (!memcmp(packet + 70, fake_mac, 6))
      memcpy(packet + 70, real_mac, 6);
    return;
  }

}

netdev_vmnet::netdev_vmnet(const char *name, class device_network_interface *ifdev, int rate)
	: osd_netdev(ifdev, rate) {

	int ok;

	const char *const argv[] = { "vmnet_helper", NULL };

	int pipe_stdin[2];
	int pipe_stdout[2];

	struct sigaction oldaction;


	/* fd[0] = read, fd[1] = write */
	ok = pipe(pipe_stdin);
	if (ok < 0) {
		osd_printf_verbose("vmnet: pipe failed %d\n", errno);
		return;
	}

	ok = pipe(pipe_stdout);
	if (ok < 0) {
		osd_printf_verbose("vmnet: pipe failed %d\n", errno);
		close(pipe_stdin[0]);
		close(pipe_stdin[1]);
		return;
	}


	std::string path = get_relative_path("vmnet_helper");

	m_child = fork();
	if (m_child < 0) {
		osd_printf_verbose("vmnet: pipe failed %d\n", errno);
		close(pipe_stdin[0]);
		close(pipe_stdin[1]);
		close(pipe_stdout[0]);
		close(pipe_stdout[1]);
		return;
	}

	if (m_child == 0) {
		extern char **environ;
		/* need to setsid() on the child */

		dup2(pipe_stdin[0], STDIN_FILENO);
		dup2(pipe_stdout[1], STDOUT_FILENO);

		close(pipe_stdin[0]);
		close(pipe_stdin[1]);
		close(pipe_stdout[0]);
		close(pipe_stdout[1]);

		setsid();
		execve(path.c_str(), (char *const *)argv, environ);
		::write(STDERR_FILENO, "execve failed\n", 14);
		_exit(1);
	}

	m_pipe[0] = pipe_stdout[0];
	m_pipe[1] = pipe_stdin[1];

	close(pipe_stdin[0]);
	close(pipe_stdout[1]);

	block_pipe(&oldaction);
	/* get the vmnet interface mtu, etc */
	ok = message_status();
	restore_pipe(&oldaction);
	if (ok < 0) {
		shutdown_child();
	}
}

int netdev_vmnet::message_status() {

	ssize_t ok;
	uint32_t msg = MAKE_MSG(MSG_STATUS, 0);
	ok = write(&msg, 4);
	if (ok != 4) return -1;

	ok = read(&msg, 4);
	if (ok != 4) return -1;

	if (msg != MAKE_MSG(MSG_STATUS, 6 + 4 + 4)) return -1;

	struct iovec iov[3];
	iov[0].iov_len = 6;
	iov[0].iov_base = m_vmnet_mac;
	iov[1].iov_len = 4;
	iov[1].iov_base = &m_vmnet_mtu;
	iov[2].iov_len = 4;
	iov[2].iov_base = &m_vmnet_packet_size;

	ok = readv(iov, 3);
	if (ok != 6 + 4 + 4) return -1;

	/* copy mac to fake mac */
	memcpy(m_mac, m_vmnet_mac, 6);

	/* sanity check */
	/* expect MTU = 1500, packet_size = 1518 */
	if (m_vmnet_packet_size < 256) {
		m_vmnet_packet_size = 1518;
	}
	m_buffer = (uint8_t *)malloc(m_vmnet_packet_size);
	if (!m_buffer) return -1;
	return 0;
}

int netdev_vmnet::message_write(void *buffer, uint32_t length) {
	ssize_t ok;
	uint32_t msg;
	struct iovec iov[2];


	msg = MAKE_MSG(MSG_WRITE, length);

	iov[0].iov_base = &msg;
	iov[0].iov_len = 4;
	iov[1].iov_base = buffer;
	iov[1].iov_len = length;

	ok = writev(iov, 2);
	if (!ok) return -1;
	ok = read(&msg, 4);
	if (ok != 4) return -1;
	//if (msg != MAKE_MSG(MSG_WRITE, length)) return -1;
	return msg;
}

int netdev_vmnet::message_read() {


	uint32_t msg;
	int ok;
	int xfer;

	msg = MAKE_MSG(MSG_READ, 0);

	ok = write(&msg, 4);
	if (ok != 4) return -1;

	if ((msg & 0xff) != MSG_READ) return -1;

	xfer = msg >> 8;
	if (xfer > m_vmnet_packet_size) {

		osd_printf_verbose("vmnet: packet size too big: %d\n", xfer);

		/* drain the message ... */
		while (xfer) {
			int count = m_vmnet_packet_size;
			if (count > xfer) count = xfer;
			ok = read(m_buffer, count);
			if (ok < 0) return -1;
			xfer -= ok;
		}
		return -1;
	}
	if (xfer == 0) return 0;
	ok = read(m_buffer, xfer);
	// if (ok != xfer) return -1;
	return ok;
}

void netdev_vmnet::shutdown_child() {
	if (m_child > 0) {
		close(m_pipe[0]);
		close(m_pipe[1]);
		for(;;) {
			int ok = waitpid(m_child, NULL, 0);
			if (ok < 0 && errno == EINTR) continue;
			break;
		}
		free(m_buffer);
		m_buffer = 0;
		m_child = -1;
	}
}

bool netdev_vmnet::check_child() {

	if (m_child < 0) return false;

	pid_t pid;
	int stat;
	for (;;) {
		pid = waitpid(m_child, &stat, WNOHANG);
		if (pid < 0 && errno == EINTR) continue;
		break;
	}
	if (pid < 0 && errno == ECHILD) {
		fprintf(stderr, "vmnet: child process does not exist\n");
		close(m_pipe[0]);
		close(m_pipe[1]);
		free(m_buffer);
		m_buffer = 0;
		m_child = -1;
		return false;
	}
	if (pid == m_child) {
		if (WIFEXITED(stat)) fprintf(stderr, "vmnet: child process exited.\n");
		if (WIFSIGNALED(stat)) fprintf(stderr, "vmnet: child process signalled.\n");

		close(m_pipe[0]);
		close(m_pipe[1]);
		free(m_buffer);
		m_buffer = 0;
		m_child = -1;
		return false;
	}
	return true;
}


netdev_vmnet::~netdev_vmnet() {
	shutdown_child();
}

void netdev_vmnet::set_mac(const char *mac)
{
	memcpy(m_mac, mac, 6);
}



int netdev_vmnet::send(uint8_t *buf, int len)
{
	int ok;
	struct sigaction oldaction;

	if (m_child <= 0) return 0;
	if (len <= 0) return 0;


	if (len > m_vmnet_packet_size) {
		osd_printf_verbose("vmnet: packed too big %d\n", len);
		return 0;
	}

	// copy to our buffer and fix the mac address...
	if (memcmp(m_mac, m_vmnet_mac, 6) != 0) {
		// nb - do we need 2 buffers, in case read recv buffer still in use?
		memcpy(m_buffer, buf, len);
		fix_outgoing_packet(m_buffer, len, m_vmnet_mac, m_mac);
		buf = m_buffer;
	}

	block_pipe(&oldaction);
	ok = message_write(buf, len);
	restore_pipe(&oldaction);
	if (ok < 0) {
		check_child();
		return 0;
	}
	return ok;
}

int netdev_vmnet::recv_dev(uint8_t **buf) {

	int ok;
	struct sigaction oldaction;

	if (m_child <= 0) return 0;

	block_pipe(&oldaction);
	ok = message_read();
	restore_pipe(&oldaction);

	if (ok < 0) {
		check_child();
		return 0;
	}
	if (memcmp(m_mac, m_vmnet_mac, 6) != 0) {
		fix_incoming_packet(m_buffer, ok, m_vmnet_mac, m_mac);
	}

	*buf = m_buffer;
	return ok;

}



ssize_t netdev_vmnet::read(void *data, size_t nbytes) {
	for (;;) {
		ssize_t rv = ::read(m_pipe[0], data, nbytes);
		if (rv < 0 && errno == EINTR) continue;
		return rv;
	}
}

ssize_t netdev_vmnet::readv(const struct iovec *iov, int iovcnt) {

	for(;;) {
		ssize_t rv = ::readv(m_pipe[0], iov, iovcnt);
		if (rv < 0 && errno == EINTR) continue;
		return rv;
	}
}

ssize_t netdev_vmnet::write(const void *data, size_t nbytes) {
	for (;;) {
		ssize_t rv = ::write(m_pipe[1], data, nbytes);
		if (rv < 0 && errno == EINTR) continue;
		return rv;
	}
}

ssize_t netdev_vmnet::writev(const struct iovec *iov, int iovcnt) {

	for(;;) {
		ssize_t rv = ::writev(m_pipe[1], iov, iovcnt);
		if (rv < 0 && errno == EINTR) continue;
		return rv;
	}
}

static CREATE_NETDEV(create_vmnet)
{
	fprintf(stderr, "%s\n", __func__);
	auto *dev = global_alloc(netdev_vmnet(ifname, ifdev, rate));
	return dynamic_cast<osd_netdev *>(dev);
}

int vmnet_module::init(const osd_options &options) {
	fprintf(stderr, "%s\n", __func__);
	add_netdev("vmnet", "VM Network Device", create_vmnet);
	return 0;
}

void vmnet_module::exit() {
	fprintf(stderr, "%s\n", __func__);
	clear_netdev();
}


#else
	#include "modules/osdmodule.h"
	#include "netdev_module.h"

	MODULE_NOT_SUPPORTED(vmnet_module, OSD_NETDEV_PROVIDER, "vmnet")
#endif


MODULE_DEFINITION(NETDEV_VMNET, vmnet_module)
