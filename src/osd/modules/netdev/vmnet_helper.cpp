// license:BSD-3-Clause
// copyright-holders:Kelvin Sherlock


/*
 https://developer.apple.com/documentation/vmnet

 A sandboxed user space process must have the com.apple.vm.networking entitlement
 in order to use vmnet API.

 clang -framework vmnet -framework Foundation
*/

#include "netdev_module.h"

#include "modules/osdmodule.h"

#if defined(OSD_NET_USE_VMNET_HELPER)

#include "netdev_common.h"
#include "emu.h"

#include <cstdint>
#include <cstdlib>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <cctype>

#include <algorithm>
#include <string>

#include <fcntl.h>
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

#include "vmnet_common.h"

extern char **environ;

namespace osd {

namespace {

class vmnet_helper_module : public osd_module, public netdev_module
{
public:

	vmnet_helper_module() : osd_module(OSD_NETDEV_PROVIDER, "vmnet_helper"), netdev_module()
	{
		// fprintf(stderr, "%s\n", __func__);
	}
	virtual ~vmnet_helper_module() {}

	virtual int init(osd_interface &osd, const osd_options &options) override;
	virtual void exit() override;

	virtual bool probe() override {
		// fprintf(stderr, "%s\n", __func__);
		return true;
	}

	virtual std::unique_ptr<network_device> open_device(int id, network_handler &handler) override;
	virtual std::vector<network_device_info> list_devices() override;

};

class netdev_vmnet_helper : public network_device_base
{
public:
	netdev_vmnet_helper(const char *name, network_handler &ifdev);
	~netdev_vmnet_helper();

	int send(void const *buf, int len) override;
	// void set_mac(const uint8_t *mac) override;

protected:
	int recv_dev(uint8_t **buf) override;

private:

	void shutdown_child();
	bool check_child();

	int message_status();
	int message_write(const void *buffer, uint32_t length);
	int message_read();

	ssize_t read(void *buffer, size_t size);
	ssize_t write(const void *buffer, size_t size);

	ssize_t readv(const struct iovec *iov, int iovcnt);
	ssize_t writev(const struct iovec *iov, int iovcnt);


	void dump(uint8_t *buf, int len);

	uint8_t m_vmnet_mac[6];
	uint32_t m_vmnet_mtu;
	uint32_t m_vmnet_packet_size;

	// uint8_t m_mac[6];
	network_handler &m_network_handler;

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

static int set_close_exec(int fd) {
	int flags;
	flags = fcntl(fd, F_GETFD, 0);
	return flags >= 0 ? fcntl(fd, F_SETFD, flags | FD_CLOEXEC) : -1;
}

netdev_vmnet_helper::netdev_vmnet_helper(const char *name, network_handler &handler)
	: network_device_base(handler), m_network_handler(handler) {

	// fprintf(stderr, "%s\n", __func__);

	int ok;

	const char *const argv[] = { "vmnet_helper", NULL };

	int pipe_stdin[2];
	int pipe_stdout[2];

	struct sigaction oldaction;


	/* fd[0] = read, fd[1] = write */
	ok = pipe(pipe_stdin);
	if (ok < 0) {
		osd_printf_verbose("vmnet_helper: pipe failed %d\n", errno);
		return;
	}

	ok = pipe(pipe_stdout);
	if (ok < 0) {
		osd_printf_verbose("vmnet_helper: pipe failed %d\n", errno);
		close(pipe_stdin[0]);
		close(pipe_stdin[1]);
		return;
	}


	std::string path = get_relative_path("vmnet_helper");

	m_child = fork();
	if (m_child < 0) {
		osd_printf_verbose("vmnet_helper: pipe failed %d\n", errno);
		close(pipe_stdin[0]);
		close(pipe_stdin[1]);
		close(pipe_stdout[0]);
		close(pipe_stdout[1]);
		return;
	}

	if (m_child == 0) {
		/* need to setsid() on the child */

		dup2(pipe_stdin[0], STDIN_FILENO);
		dup2(pipe_stdout[1], STDOUT_FILENO);

		// close-on-exec flag isn't set for any file descriptors.
		// and F_MAXFD fcntl isn't available on darwin.
		// /dev/fd/ is fake directory of open file descriptors but
		// that's too much work.  Use the highest pipe # as a proxy
		// for the max fd. as a bonus it will handle closing all pipes.

		#if 0
		close(pipe_stdin[0]);
		close(pipe_stdin[1]);
		close(pipe_stdout[0]);
		close(pipe_stdout[1]);
		#else
		int maxfd = 3;
		maxfd = std::max(maxfd, pipe_stdin[0]);
		maxfd = std::max(maxfd, pipe_stdin[1]);
		maxfd = std::max(maxfd, pipe_stdout[0]);
		maxfd = std::max(maxfd, pipe_stdout[1]);
		for (int fd = 3; fd <= maxfd; ++fd)
			close(fd);
		#endif
		setsid();
		execve(path.c_str(), (char *const *)argv, environ);
		::write(STDERR_FILENO, "vmnet_helper: execve failed\n", 14);
		::write(STDERR_FILENO, "path was: ", 10);
		::write(STDERR_FILENO, path.c_str(), path.length());
		::write(STDERR_FILENO, "\n", 1);
		_exit(1);
	}

	m_pipe[0] = pipe_stdout[0];
	m_pipe[1] = pipe_stdin[1];

	close(pipe_stdin[0]);
	close(pipe_stdout[1]);

	// explicitly mark as close-on-exec so they can't be inherited by a
	// child and keep the pipes open. This is not a theoretical problem.
	set_close_exec(m_pipe[0]);
	set_close_exec(m_pipe[1]);

	block_pipe(&oldaction);
	/* get the vmnet interface mtu, etc */
	ok = message_status();
	restore_pipe(&oldaction);
	if (ok < 0) {
		shutdown_child();
	}
}

int netdev_vmnet_helper::message_status() {

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
	// memcpy(m_mac, m_vmnet_mac, 6);

	/* sanity check */
	/* expect MTU = 1500, packet_size = 1518 */
	if (m_vmnet_packet_size < 256) {
		m_vmnet_packet_size = 1518;
	}
	/* add 4 extra bytes to append a crc */
	m_buffer = (uint8_t *)malloc(m_vmnet_packet_size + 4);
	if (!m_buffer) return -1;
	return 0;
}

int netdev_vmnet_helper::message_write(const void *buffer, uint32_t length) {
	ssize_t ok;
	uint32_t msg;
	struct iovec iov[2];


	msg = MAKE_MSG(MSG_WRITE, length);

	iov[0].iov_base = &msg;
	iov[0].iov_len = 4;
	iov[1].iov_base = (void *)buffer;
	iov[1].iov_len = length;

	ok = writev(iov, 2);
	if (!ok) return -1;
	ok = read(&msg, 4);
	if (ok != 4) return -1;
	//if (msg != MAKE_MSG(MSG_WRITE, length)) return -1;
	return length;
}

int netdev_vmnet_helper::message_read() {


	uint32_t msg;
	int ok;
	int xfer;

	msg = MAKE_MSG(MSG_READ, 0);

	ok = write(&msg, 4);
	if (ok != 4) return -1;

	ok = read(&msg, 4);
	if (ok != 4) return -1;

	if ((msg & 0xff) != MSG_READ) return -1;

	xfer = msg >> 8;
	if (xfer > m_vmnet_packet_size) {

		osd_printf_verbose("vmnet_helper: packet size too big: %d\n", xfer);

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

void netdev_vmnet_helper::shutdown_child() {
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

bool netdev_vmnet_helper::check_child() {

	if (m_child < 0) return false;

	pid_t pid;
	int stat;
	for (;;) {
		pid = waitpid(m_child, &stat, WNOHANG);
		if (pid < 0 && errno == EINTR) continue;
		break;
	}
	if (pid < 0 && errno == ECHILD) {
		fprintf(stderr, "vmnet_helper: child process does not exist\n");
		close(m_pipe[0]);
		close(m_pipe[1]);
		free(m_buffer);
		m_buffer = 0;
		m_child = -1;
		return false;
	}
	if (pid == m_child) {
		if (WIFEXITED(stat)) fprintf(stderr, "vmnet_helper: child process exited.\n");
		if (WIFSIGNALED(stat)) fprintf(stderr, "vmnet_helper: child process signalled.\n");

		close(m_pipe[0]);
		close(m_pipe[1]);
		free(m_buffer);
		m_buffer = 0;
		m_child = -1;
		return false;
	}

	// if pid == 0 should drain the pipe as well...
	return true;
}


netdev_vmnet_helper::~netdev_vmnet_helper() {
	// fprintf(stderr, "%s\n", __func__);
	shutdown_child();
}

#if 0
void netdev_vmnet_helper::set_mac(const uint8_t *mac)
{
	memcpy(m_mac, mac, 6);
}
#endif

int netdev_vmnet_helper::send(void const *buf, int len)
{
	int ok;
	struct sigaction oldaction;

	if (m_child <= 0) return 0;
	if (len <= 0) return 0;


	if (len > m_vmnet_packet_size) {
		osd_printf_verbose("vmnet_helper: packed too big %d\n", len);
		return 0;
	}

	std::array<u8, 6> my_mac = m_network_handler.get_mac();
	// copy to our buffer and fix the mac address...
	if (memcmp(&my_mac[0], m_vmnet_mac, 6) != 0) {
		// nb - do we need 2 buffers, in case read recv buffer still in use?
		memcpy(m_buffer, buf, len);
		fix_outgoing_packet(m_buffer, len, m_vmnet_mac, &my_mac[0]);
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

int netdev_vmnet_helper::recv_dev(uint8_t **buf) {

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
	if (ok == 0) return 0;

	std::array<u8, 6> my_mac = m_network_handler.get_mac();
	if (memcmp(&my_mac[0], m_vmnet_mac, 6) != 0) {
		fix_incoming_packet(m_buffer, ok, m_vmnet_mac, &my_mac[0]);
	}

	*buf = m_buffer;

	return finalize_frame(m_buffer, ok);
}



ssize_t netdev_vmnet_helper::read(void *data, size_t nbytes) {
	for (;;) {
		ssize_t rv = ::read(m_pipe[0], data, nbytes);
		if (rv < 0 && errno == EINTR) continue;
		return rv;
	}
}

ssize_t netdev_vmnet_helper::readv(const struct iovec *iov, int iovcnt) {

	for(;;) {
		ssize_t rv = ::readv(m_pipe[0], iov, iovcnt);
		if (rv < 0 && errno == EINTR) continue;
		return rv;
	}
}

ssize_t netdev_vmnet_helper::write(const void *data, size_t nbytes) {
	for (;;) {
		ssize_t rv = ::write(m_pipe[1], data, nbytes);
		if (rv < 0 && errno == EINTR) continue;
		return rv;
	}
}

ssize_t netdev_vmnet_helper::writev(const struct iovec *iov, int iovcnt) {

	for(;;) {
		ssize_t rv = ::writev(m_pipe[1], iov, iovcnt);
		if (rv < 0 && errno == EINTR) continue;
		return rv;
	}
}

void netdev_vmnet_helper::dump(uint8_t *buf, int len) {

  static const char hex[] = "0123456789abcdef";
  char buffer1[16 * 3 + 1];
  char buffer2[16 + 1];
  unsigned offset;
  uint8_t *cp = buf;


  offset = 0;
  while (len > 0) {
    unsigned char x = *cp++;

    buffer1[offset * 3] = hex[x >> 4];
    buffer1[offset * 3 + 1] = hex[x & 0x0f];
    buffer1[offset * 3 + 2] = ' ';

    buffer2[offset] = (x < 0x80) && std::isprint(x) ? x : '.';

    --len;
    ++offset;
    if (offset == 16 || len == 0) {
      buffer1[offset * 3] = 0;
      buffer2[offset] = 0;
      fprintf(stderr, "%-50s %s\n", buffer1, buffer2);
      offset = 0;
    }
  }

}


std::unique_ptr<network_device> vmnet_helper_module::open_device(int id, network_handler &handler)
{
	return std::make_unique<netdev_vmnet_helper>("vmnet_helper", handler);
}

std::vector<network_device_info> vmnet_helper_module::list_devices()
{
	std::vector<network_device_info> result;
	result.emplace_back(network_device_info{ 0, "VM Network Device (H)" });
	return result;
}


int vmnet_helper_module::init(osd_interface &osd, const osd_options &options) {
	// fprintf(stderr, "%s\n", __func__);
	return 0;
}

void vmnet_helper_module::exit() {
	// fprintf(stderr, "%s\n", __func__);
}

} // anonymous namespace

} // namespace osd


#else

namespace osd { namespace { MODULE_NOT_SUPPORTED(vmnet_helper_module, OSD_NETDEV_PROVIDER, "vmnet_helper") } }

#endif


MODULE_DEFINITION(NETDEV_VMNET_HELPER, osd::vmnet_helper_module)
