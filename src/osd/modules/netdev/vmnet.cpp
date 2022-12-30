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
#include <cstdio>

#include <sys/types.h>
#include <sys/uio.h>
#include <vmnet/vmnet.h>

#include "vmnet_common.h"

static int classify_mac(uint8_t *mac) {
	if ((mac[0] & 0x01) == 0) return 1; /* unicast */
	if (memcmp(mac, "\xff\xff\xff\xff\xff\xff", 6) == 0) return 0xff; /* broadcast */
	return 2; /* multicast */
}

class vmnet_module : public osd_module, public netdev_module
{
public:

	vmnet_module() : osd_module(OSD_NETDEV_PROVIDER, "vmnet"), netdev_module()
	{
	}
	virtual ~vmnet_module() {}

	virtual int init(const osd_options &options);
	virtual void exit();

	virtual bool probe() { 
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


	interface_ref m_interface = 0;
	char m_vmnet_mac[6];
	long m_vmnet_mtu;
	long m_vmnet_packet_size;

	char m_mac[6];

	uint8_t *m_buffer = 0;
};


netdev_vmnet::netdev_vmnet(const char *name, class device_network_interface *ifdev, int rate)
	: osd_netdev(ifdev, rate) {


	xpc_object_t dict;
	dispatch_queue_t q;
	dispatch_semaphore_t sem;

	__block vmnet_return_t interface_status;

	dict = xpc_dictionary_create(NULL, NULL, 0);
	xpc_dictionary_set_uint64(dict, vmnet_operation_mode_key, VMNET_SHARED_MODE);
	sem = dispatch_semaphore_create(0);
	q = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);

	m_interface = vmnet_start_interface(dict, q, ^(vmnet_return_t status, xpc_object_t params){
		interface_status = status;
		if (status == VMNET_SUCCESS) {
			const char *cp;
			cp = xpc_dictionary_get_string(params, vmnet_mac_address_key);
			fprintf(stderr, "vmnet mac: %s\n", cp);
			sscanf(cp, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				&m_vmnet_mac[0],
				&m_vmnet_mac[1],
				&m_vmnet_mac[2],
				&m_vmnet_mac[3],
				&m_vmnet_mac[4],
				&m_vmnet_mac[5]
			);

			m_vmnet_mtu = xpc_dictionary_get_uint64(params, vmnet_mtu_key);
			m_vmnet_packet_size =  xpc_dictionary_get_uint64(params, vmnet_max_packet_size_key);

			fprintf(stderr, "vmnet mtu: %u\n", (unsigned)m_vmnet_mtu);
			fprintf(stderr, "vmnet packet size: %u\n", (unsigned)m_vmnet_packet_size);

		}
		dispatch_semaphore_signal(sem);
	});
	dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

	if (interface_status == VMNET_SUCCESS) {
		long buffer_size = (m_vmnet_packet_size * 2 + 1023) & ~1023;
		m_buffer = (uint8_t *)malloc(buffer_size);

		// could use vmnet_interface_set_event_callback to set up a callback when data is available.

	} else {
		if (m_interface) {
			vmnet_stop_interface(m_interface, q, ^(vmnet_return_t status){
				dispatch_semaphore_signal(sem);
			});
			dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
			m_interface = NULL;
		}
		fprintf(stderr, "vmnet_start_interface failed: %d\n", interface_status);
	}

	dispatch_release(sem);
	xpc_release(dict);
}

netdev_vmnet::~netdev_vmnet() {
	vmnet_return_t st;
	dispatch_queue_t q;
	dispatch_semaphore_t sem;

	if (m_interface) {
		sem = dispatch_semaphore_create(0);
		q = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);

		st = vmnet_stop_interface(m_interface, q, ^(vmnet_return_t status){
			dispatch_semaphore_signal(sem);
		});
		if (st == VMNET_SUCCESS) {
			dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
		}
		dispatch_release(sem);
	}
	free(m_buffer);
}

void netdev_vmnet::set_mac(const char *mac)
{
	memcpy(m_mac, mac, 6);
}


int netdev_vmnet::send(uint8_t *buf, int len)
{
	int count = 1;
	vmnet_return_t st;
	struct vmpktdesc v;
	struct iovec iov;

	if (!m_interface) return 0;


	if (len > m_vmnet_packet_size) {
		fprintf(stderr, "vmnet: packet too big (%d)\n", len);
		return 0;
	}

	if (memcmp(m_mac, m_vmnet_mac, 6) != 0) {
		// nb - do we need 2 buffers, in case read recv buffer still in use?
		memcpy(m_buffer, buf, len);
		fix_outgoing_packet(m_buffer, len, m_vmnet_mac, m_mac);
		buf = m_buffer;
	}

	iov.iov_base = buf;
	iov.iov_len = len;

	v.vm_pkt_size = len;
	v.vm_pkt_iov = &iov;
	v.vm_pkt_iovcnt = 1;
	v.vm_flags = 0;

	st = vmnet_write(m_interface, &v, &count);

	if (st != VMNET_SUCCESS) {
		fprintf(stderr, "vmnet_write: %d\n", st);
		return 0;
	}

	return count;
}

int netdev_vmnet::recv_dev(uint8_t **buf) {

	int count = 1;
	vmnet_return_t st;
	struct vmpktdesc v;
	struct iovec iov[2];

	if (!m_interface) return 0;


	for(;;) {
		int type;

		iov[0].iov_base = m_buffer;
		iov[0].iov_len = m_vmnet_packet_size;

		v.vm_pkt_size = m_vmnet_packet_size;
		v.vm_pkt_iov = iov;
		v.vm_pkt_iovcnt = 1;
		v.vm_flags = 0;

		count = 1;
		st = vmnet_read(m_interface, &v, &count);
		if (st != VMNET_SUCCESS) {
			fprintf(stderr, "vmnet_read: %d\n", st);
			return 0;
		}

		if (count < 1) break;
		/* todo -- skip multicast messages based on flag? */
		type = classify_mac(m_buffer);
		if (type == 2) continue; /* multicast */
		break;
	}

	if (count < 1) return 0;

	if (memcmp(m_mac, m_vmnet_mac, 6) != 0) {
		fix_incoming_packet(m_buffer, v.vm_pkt_size, m_vmnet_mac, m_mac);
	}

	*buf = m_buffer;
	return v.vm_pkt_size;
}

static CREATE_NETDEV(create_vmnet)
{
	auto *dev = global_alloc(netdev_vmnet(ifname, ifdev, rate));
	return dynamic_cast<osd_netdev *>(dev);
}

int vmnet_module::init(const osd_options &options) {
	add_netdev("vmnet", "VM Network Device", create_vmnet);
	return 0;
}

void vmnet_module::exit() {
	clear_netdev();
}

#else
	#include "modules/osdmodule.h"
	#include "netdev_module.h"

	MODULE_NOT_SUPPORTED(vmnet_module, OSD_NETDEV_PROVIDER, "vmnet")
#endif


MODULE_DEFINITION(NETDEV_VMNET, vmnet_module)