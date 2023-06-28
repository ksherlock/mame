
#ifndef MAME_MACHINE_W5100_H
#define MAME_MACHINE_W5100_H

#pragma once

#include "dinetwork.h"
#include "util/tcp_sequence.h"

#include <queue>

class w5100_base_device : public device_t, public device_network_interface, public device_memory_interface
{
public:


	uint8_t read(uint16_t address);
	void write(uint16_t address, uint8_t data);

	auto irq_handler() { return m_irq_handler.bind(); }

protected:

	enum class dev_type {
		W5100,
		W5100S
	};


	w5100_base_device(const machine_config &mconfig, device_type type, const char *tag, device_t *owner, uint32_t clock, dev_type device_type);

	virtual void device_start() override;
	virtual void device_reset() override;
	virtual void device_add_mconfig(machine_config &config) override;


	TIMER_CALLBACK_MEMBER(interrupt_timer);
	TIMER_CALLBACK_MEMBER(delayed_ack_timer);
	TIMER_CALLBACK_MEMBER(keep_alive_timer);
	TIMER_CALLBACK_MEMBER(retry_timer);


	virtual void recv_cb(u8 *buffer, int length) override;
	virtual void recv_complete_cb(int result) override;
	virtual void send_complete_cb(int result) override;

	const dev_type m_device_type;


	virtual space_config_vector memory_space_config() const override;

private:
	struct ip_info;

	uint8_t read_socket_register(offs_t offset) const;
	uint8_t read_socket_register_3(offs_t offset) const;

	void write_socket_register(offs_t offset, uint8_t value);
	void write_socket_register_3(offs_t offset, uint8_t value);
	void write_common_register(offs_t offset, uint8_t value);

	void update_rmsr(uint8_t value);
	void update_tmsr(uint8_t value);

	void update_socket_tx_bufsize();
	void update_socket_rx_bufsize();

	void update_ethernet_irq();

	int register_bank(uint16_t offset);


	void socket_command(int sn, int command);
	void socket_open(int sn);
	void socket_close(int sn, unsigned irqs = 0);
	void socket_recv(int sn);
	void socket_send(int sn);
	void socket_send_mac(int sn);
	void socket_send_keep(int sn);
	void socket_connect(int sn, bool arp=true);
	void socket_disconnect(int sn);
	void socket_listen(int sn);

	void socket_send_common(int sn);

	void sl_command(int command);
	void send_icmp_request();

	bool socket_arp(int sn);
	bool ip_arp(int sn, uint32_t dest, int rtr, int rcr);
	void send_arp_request(uint32_t ip);

	void handle_arp_request(const uint8_t *buffer, int length);
	void handle_arp_reply(const uint8_t *buffer, int length);
	void send_icmp_reply(const uint8_t *buffer, int length);
	void send_icmp_unreachable(uint8_t *buffer, int length);
	void send_igmp(int sn, bool connect);

	void send_or_queue(uint8_t *buffer, int length);

	int receive(int sn, const uint8_t *buffer, int length);

	uint8_t *build_eth_ip_header(const ip_info &info, uint8_t *frame, unsigned length);
	void build_ipraw_header(int sn, uint8_t *frame, int data_length);
	void build_udp_header(int sn, uint8_t *frame, int data_length);
	void build_tcp_header(int sn, uint8_t *frame, int data_length, int flags, util::tcp_sequence seq, util::tcp_sequence ack);
	void dump_bytes(const uint8_t *buffer, int length);
	void dump_socket(int sn);


	/* tcp functions */
	uint32_t tcp_generate_iss(void);
	void tcp_segment(int sn, const uint8_t *buffer, int length);
	void tcp_send_segment(int sn, int flags, util::tcp_sequence, util::tcp_sequence);
	void tcp_reset(const uint8_t *buffer, int length);
	void tcp_send(int sn, bool retransmit);
	void tcp_send_keep(int sn, bool retransmit);

	void tcp_parse_options(int sn, const uint8_t *options, int length);

	void socket_repeat_timer(int sn, int param);
	void socket_tcp_timer(int sn, bool requeue = false);
	void read_timeout_registers(int sn, unsigned &rcr, unsigned &rtr);
	void reset_socket_timers(int sn);

	uint16_t m_idm = 0;
	uint16_t m_identification = 0;
	uint32_t m_irq_state = 0;

	devcb_write_line m_irq_handler;

	emu_timer *m_interrupt_timer = nullptr;
	emu_timer *m_delayed_ack_timers[4]{};
	emu_timer *m_keep_alive_timers[4]{};
	emu_timer *m_retry_timers[5]{};

	uint8_t m_tx_buffer[0x2000]{};
	uint8_t m_rx_buffer[0x2000]{};

	uint8_t m_common_registers[0x100]{};
	uint8_t m_socket_registers[4][0x100]{};

	struct socket_info
	{
		int proto;
		int rx_buffer_offset;
		int rx_buffer_size;
		int tx_buffer_offset;
		int tx_buffer_size;

		// arp/tcp retry count
		int rcr;
		unsigned rtr;

		// arp variables.
		uint32_t arp_ip_address;
		int command;
		bool arp_valid;
		bool arp_in_progress;
		bool send_in_progress;
		bool resend_in_progress;

		void reset()
		{
			proto = 0;
			rcr = 0;
			rtr = 0;
			arp_ip_address = 0;
			command = 0;
			arp_valid = false;
			arp_in_progress = false;
			send_in_progress = false;
			resend_in_progress = false;
		}
	};


	struct tcp_info
	{
		util::tcp_sequence snd_una; // oldest unack seq number
		util::tcp_sequence snd_nxt; // next seq number to send
		util::tcp_sequence rcv_nxt; // receive next

		util::tcp_sequence irs;     // initial recv seq number
		util::tcp_sequence iss;     // initial send seq

		util::tcp_sequence snd_wl1; // seg seq of last window update
		util::tcp_sequence snd_wl2; // seg ack of last window update

		util::tcp_sequence resend_seq;

		uint32_t snd_wnd; // send window
		uint32_t rcv_wnd; // receive window

		void reset()
		{
			snd_una = 0;
			snd_nxt = 0;
			snd_wnd = 0;
			snd_wl1 = 0;
			snd_wl2 = 0;
			iss = 0;
			rcv_nxt = 0;
			rcv_wnd = 0;
			irs = 0;
			resend_seq = 0;	
		}
	};


	socket_info m_sockets[5]; // +1 for socket-less
	tcp_info m_tcp[4];

	std::queue<std::vector<uint8_t>> m_queue;

	bool busy(void)
	{
		return m_send_timer->enabled();
	}

	address_space_config m_address_space_config;
	address_space *m_address_space;
};

class w5100_device : public w5100_base_device
{
public:
	w5100_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock);
};


class w5100s_device : public w5100_base_device
{
public:
	w5100s_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock);
};


DECLARE_DEVICE_TYPE(W5100, w5100_device)
DECLARE_DEVICE_TYPE(W5100S, w5100s_device)

#endif
