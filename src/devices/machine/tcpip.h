// license:BSD-3-Clause
// copyright-holders:
/***************************************************************************

    tcpip.h

    TCP IP v4 device

***************************************************************************/

#ifndef MAME_MACHINE_TCPIP_H
#define MAME_MACHINE_TCPIP_H

#pragma once

class tcpip_device : public device_t
{
public:

	tcpip_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock = 0);

	enum class tcp_state {
		TCPS_CLOSED,		/* closed */
		TCPS_LISTEN,		/* listening for connection */
		TCPS_SYN_SENT,		/* active, have sent syn */
		TCPS_SYN_RECEIVED,	/* have sent and received syn */
		/* states < TCPS_ESTABLISHED are those where connections not established */
		TCPS_ESTABLISHED,	/* established */
		TCPS_CLOSE_WAIT,	/* rcvd fin, waiting for close */
		/* states > TCPS_CLOSE_WAIT are those where user has closed */
		TCPS_FIN_WAIT_1,	/* have closed, sent fin */
		TCPS_CLOSING,		/* closed xchd FIN; await FIN ACK */
		TCPS_LAST_ACK,		/* had fin and close; await FIN ACK */
		/* states > TCPS_CLOSE_WAIT && < TCPS_FIN_WAIT_2 await ACK of FIN */
		TCPS_FIN_WAIT_2,	/* have closed, fin is acked */
		TCPS_TIME_WAIT,		/* in 2*msl quiet wait after close */
	};

	enum class tcp_error {
		ok = 0,
		connection_already_exists,
		connection_does_not_exist,
		foreign_socket_unspecified,
		insufficient_resources,
		connection_closing,
		connection_reset,
	};

	enum class disconnect_type {
		none,
		active,
		passive,
		rst,
	};

	enum class connect_type {
		none,
		active,
		passive
	};

#if 0
	enum class tcp_event {
		state_change,
		fin_received,
		rst_received,
		send_complete,
	};
#endif

	// TCP user commands.
	tcp_error open(uint32_t ip, uint16_t port);
	tcp_error listen(uint16_t port);

	tcp_error close();
	tcp_error send(const void *buffer, unsigned length, bool push = false, bool urgent = false);
	tcp_error receive(void *buffer, unsigned &length, bool *urgent = nullptr, bool *push = nullptr); // should indicate back urgent + push flags
	tcp_error abort();

	tcp_state status() { return m_state; }

	void force_close();

	void segment(const void *buffer, int length);
	bool check_segment(const void *buffer, int length);

	void set_local_ip(uint32_t ip) { m_local_ip = ip; }
	void set_local_port(uint16_t port) { m_local_port = port; }
	void set_local_mac(const uint8_t *);

	uint32_t get_local_ip() const { return m_local_ip; }
	uint16_t get_local_port() const { return m_local_port; }
	const uint8_t *get_local_mac() const { return m_local_mac; }

	void set_remote_mac(const uint8_t *);

	uint32_t get_remote_ip() const { return m_remote_ip; }
	uint16_t get_remote_port() const { return m_remote_port; }
	const uint8_t *get_remote_mac() const { return m_remote_mac; }

	disconnect_type get_disconnect_type() const { return m_disconnect_type; }

	void set_send_buffer_size(int);
	void set_receive_buffer_size(int);

	void set_keep_alive_timer(int seconds) { m_keep_alive = seconds; }
	void set_param(int param) { m_param = param; }

	// event callbacks
	// data available, send finished, state change, rst recvd, fin recvd

	// need amt of recv data, amt of pending send data.

	void set_on_state_change(std::function<void(tcp_state, tcp_state)> fx) { m_on_state_change = fx; }
	void set_send_function(std::function<void(void *, int)> fx) { m_send_function = fx; }


protected:

	tcpip_device(const machine_config &mconfig, device_type type, const char *tag, device_t *owner, uint32_t clock);


	virtual void device_start() override;
	virtual void device_reset() override;
	virtual void device_timer(emu_timer &timer, device_timer_id id, int param) override;


private:

	void disconnect(disconnect_type dt, tcp_state new_state = tcp_state::TCPS_CLOSED);

	uint32_t generate_iss(void) const;

	void set_state(tcp_state new_state);


	void rst_closed_socket(const void *buffer, int flags, uint32_t ack, uint32_t seq_end);
	void send_segment(int flags, uint32_t seq, uint32_t ack);
	void send_segment(const uint8_t *src, int flags, uint32_t seq, uint32_t ack);
	void send_data_segment(const uint8_t *data, int length, int flags, uint32_t seq, uint32_t ack);


	void recv_data(const uint8_t *data, int length, uint32_t seg_seq, bool push);
	void send_data(bool flush);

	tcp_state m_state = tcp_state::TCPS_CLOSED;
	int m_param = 0;

	uint16_t m_local_port = 0;
	uint16_t m_remote_port = 0;
	uint32_t m_local_ip = 0;
	uint32_t m_remote_ip = 0;

	uint8_t m_local_mac[6]{};
	uint8_t m_remote_mac[6]{};

	int m_ttl = 64;
	int m_mss = 536;
	int m_keep_alive = 0;


	// tcp variables.
	uint32_t m_snd_una = 0; // oldest unack seq number
	uint32_t m_snd_nxt = 0; // next seq number to send
	uint32_t m_snd_wnd = 0; // send window
	uint32_t m_snd_up = 0; // send urgent pointer
	uint32_t m_snd_wl1 = 0; // seg seq of last window update
	uint32_t m_snd_wl2 = 0; // seg ack of last window update
	uint32_t m_iss = 0; // initial send seq

	uint32_t m_rcv_nxt = 0; // receive next
	uint32_t m_rcv_wnd = 0; // receive window
	uint32_t m_rcv_up = 0; // receive urgent ptr
	uint32_t m_irs = 0; // initial recv seq number

	bool m_fin_pending = false;

	connect_type m_connect_type = connect_type::none;
	disconnect_type m_disconnect_type = disconnect_type::none;

	// bool m_syn_send = false;

	uint8_t *m_recv_buffer = nullptr;
	uint8_t *m_send_buffer = nullptr;

	int m_recv_buffer_capacity = 0;
	int m_recv_buffer_size = 0;
	int m_recv_buffer_psh_offset = 0;

	int m_send_buffer_capacity = 0;
	int m_send_buffer_size = 0;
	int m_send_buffer_psh_offset = 0;


	struct fragment;
	std::vector<fragment> m_fragments;

	emu_timer *m_timer = nullptr;


	// callbacks
	std::function<void(tcp_state, tcp_state)> m_on_state_change;
	std::function<void()> m_on_data_available;
	std::function<void()> m_on_send_complete;

	std::function<void(void *buffer, int size)> m_send_function;


};

DECLARE_DEVICE_TYPE(TCPIP, tcpip_device)

#endif