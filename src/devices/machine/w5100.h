
#ifndef MAME_MACHINE_W5100_H
#define MAME_MACHINE_W5100_H

#include "machine/tcpip.h"



class w5100_device : public device_t, public device_network_interface
{
public:


	uint8_t read(uint16_t address);
	void write(uint16_t address, uint8_t data);

	auto irq_handler() { return m_irq_handler.bind(); }

	w5100_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock);

protected:

	enum class dev_type {
		W5100,
		W5100S
	};

	//w5100_device_base(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock);

	w5100_device(const machine_config &mconfig, device_type type, const char *tag, device_t *owner, uint32_t clock, dev_type device_type);

	virtual void device_start() override;
	virtual void device_reset() override;
	virtual void device_add_mconfig(machine_config &config) override;

	virtual void device_timer(emu_timer &timer, device_timer_id id, int param) override;
	virtual void device_post_load() override;



	virtual void recv_cb(u8 *buffer, int length) override;
	// virtual void send_complete_cb(int result) override;
	// virtual int recv_start_cb(u8 *buf, int length) override;
	// virtual void recv_complete_cb(int result) override;

	const dev_type m_device_type;

private:

	void write_socket_register(int sn, int offset, uint8_t value);
	void write_general_register(int offset, uint8_t value);

	void update_rmsr(uint8_t value);
	void update_tmsr(uint8_t value);

	void update_ethernet_irq();


	void socket_command(int sn, int command);
	void socket_open(int sn);
	void socket_close(int sn);
	void socket_recv(int sn);
	void socket_send(int sn);
	void socket_send_mac(int sn);
	void socket_send_keep(int sn);
	void socket_connect(int sn, bool arp=true);
	void socket_disconnect(int sn);

	void socket_send_common(int sn);

	void sl_command(int command);
	void send_icmp_request();

	bool socket_arp(int sn);
	bool ip_arp(int sn, uint32_t dest, int rtr);
	void send_arp_request(uint32_t ip);

	void handle_arp_request(const uint8_t *buffer, int length);
	void handle_arp_reply(const uint8_t *buffer, int length);
	void handle_icmp_request(uint8_t *buffer, int length);
	void send_icmp_unreachable(uint8_t *buffer, int length);
	void send_igmp(int sn, bool connect);

	void receive(int sn, const uint8_t *buffer, int length);

	void build_ethernet_header(int sn, uint8_t *buffer, int length);
	void build_ipraw_header(int sn, uint8_t *buffer, int length);
	void build_udp_header(int sn, uint8_t *buffer, int length);

	void tcp_state_change(int sn, tcpip_device::tcp_state new_state, tcpip_device::tcp_state old_state);
	// void tcp_event(int sn, tcpip_device::tcp_event event);
	void tcp_receive(int sn);
	void tcp_send_complete(int sn);
	void tcp_receive_ready(int sn);

	void dump_bytes(const uint8_t *buffer, int length);

	uint16_t m_idm = 0;
	uint16_t m_identification = 0;
	uint32_t m_irq_state = 0;

	required_device_array<tcpip_device, 4> m_tcp;
	devcb_write_line m_irq_handler;

	emu_timer *m_timers[5]{};

	uint8_t m_memory[0x8000]{};


	//struct socket_info *m_socket_info = nullptr;

	struct socket_info
	{
		int proto;
		int rx_buffer_offset;
		int rx_buffer_size;
		int tx_buffer_offset;
		int tx_buffer_size;

		// arp/tcp retry count
		int retry;

		// arp variables.
		uint32_t arp_ip_address;
		int command;
		bool arp_ok;

		void reset() {
			retry = 0;
			arp_ip_address = 0;
			command = 0;
			arp_ok = false;
		}
	};

	socket_info m_sockets[5];


};


class w5100s_device : public w5100_device
{
public:
	w5100s_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock);
};


DECLARE_DEVICE_TYPE(W5100, w5100_device)
DECLARE_DEVICE_TYPE(W5100S, w5100s_device)

#endif
