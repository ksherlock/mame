
#include "tcpip.h"



DEFINE_DEVICE_TYPE(TCPIP, tcpip_device, "tcpip", "TCP/IP")

#if 0
/* tcp sequence comparisons. */
// a <= b <= c
inline static bool ack_valid_le_le(uint32_t a, uint32_t b, uint32_t c)
{
	if (a <= c) return (a <= b) && (b <= c);
	return (a <= b) || (b <= c);
}

// a <= b < c
inline static bool ack_valid_le_lt(uint32_t a, uint32_t b, uint32_t c)
{
	if (a < c) return (a <= b) && (b < c);
	return (a <= b) || (b < c);

}

// a < b <= c
inline static bool ack_valid_lt_le(uint32_t a, uint32_t b, uint32_t c)
{
	if (a < c) return (a < b) && (b <= c);
	return (a < b) || (b <= c);
}
#endif

#if 0
/* sequence comparisons */
inline bool seq_lt(uint32_t a, uint32_t b)
{
	return static_cast<int32_t>(a - b) < 0; 
}
inline bool seq_le(uint32_t a, uint32_t b)
{
	return static_cast<int32_t>(a - b) <= 0; 
}
inline bool seq_gt(uint32_t a, uint32_t b)
{
	return static_cast<int32_t>(a - b) > 0; 
}
inline bool seq_ge(uint32_t a, uint32_t b)
{
	return static_cast<int32_t>(a - b) >= 0; 
}
#endif


tcpip_device::tcpip_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock):
	tcpip_device(mconfig, TCPIP, tag, owner, clock)
{ }

tcpip_device::tcpip_device(const machine_config &mconfig, device_type type, const char *tag, device_t *owner, uint32_t clock):
	device_t(mconfig, type, tag, owner, clock)
{ }


void tcpip_device::device_start()
{
	m_timer = timer_alloc(0);
}

void tcpip_device::device_reset()
{
	m_state = tcp_state::TCPS_CLOSED;

	m_recv_buffer.clear();
	m_send_buffer.clear();

}

void tcpip_device::device_timer(emu_timer &timer, device_timer_id id, int param)
{

}

bool tcpip_device::check_segment(const void *buffer, int length)
{
	if (m_state == tcp_state::TCPS_CLOSED) return false;
	if (m_state == tcp_state::TCPS_LISTEN)
	{

	}
	return false;

}

void tcpip_device::segment(const void *buffer, int length)
{
}


uint32_t tcpip_device::generate_iss(void) const
{
	/* The generator is bound to a (possibly fictitious) 32 bit clock
	   whose low order bit is incremented roughly every 4 microseconds.
	 */

	// 1 microsecond = 1e-6 seconds
	return machine().time().as_ticks(1e6 / 4);

}

void tcpip_device::set_state(tcp_state new_state)
{
	tcp_state old_state = m_state;

	if (new_state == m_state) return;
	m_state = new_state;
	if (m_on_state_change) m_on_state_change(new_state, old_state);
}

void tcpip_device::set_local_mac(const uint8_t *mac)
{
	memcpy(m_local_mac, mac, 6);
}

void tcpip_device::set_remote_mac(const uint8_t *mac)
{
	memcpy(m_remote_mac, mac, 6);
}


/*
pp 44, TCP User Commands:

OPEN (local port, foreign socket, active/passive [, timeout] [, precedence] [, security/compartment] [, options])
        -> local connection name

SEND (local connection name, buffer address, byte count, PUSH flag, URGENT flag [,timeout])

RECEIVE (local connection name, buffer address, byte count) -> byte count, urgent flag, push flag

CLOSE (local connection name)

STATUS (local connection name) -> status data

ABORT (local connection name)

*/

tcpip_device::tcp_error tcpip_device::open(uint32_t ip, uint16_t port)
{
	// pp 54 

	if (m_state != tcp_state::TCPS_CLOSED) return tcp_error::connection_already_exists;

	m_remote_ip = ip;
	m_remote_port = port;

	m_fin_pending = false;
	m_syn_send = false;

	m_iss = generate_iss();
	m_snd_una = m_iss;
	m_snd_nxt = m_iss + 1;


	// generate segment - <SEQ=ISS><CTL=SYN>
	set_state(tcp_state::TCPS_SYN_SENT);
	return tcp_error::ok;
}

tcpip_device::tcp_error tcpip_device::listen(uint16_t port)
{
	// pp 54

	if (m_state != tcp_state::TCPS_CLOSED) return tcp_error::connection_already_exists;

	m_remote_ip = 0;
	m_remote_port = 0;
	memset(m_remote_mac, 0, 6);

	m_local_port = port;

	m_fin_pending = false;
	m_syn_send = false;


	set_state(tcp_state::TCPS_LISTEN);

	return tcp_error::ok;
}


tcpip_device::tcp_error tcpip_device::send(const void *buffer, unsigned length, bool push, bool urgent)
{
	// pp 56

	switch(m_state)
	{
		case tcp_state::TCPS_CLOSED:
		case tcp_state::TCPS_LISTEN:
			return tcp_error::connection_does_not_exist; // tcp says to open active as passive and queue data for later.

		case tcp_state::TCPS_SYN_SENT:
		case tcp_state::TCPS_SYN_RECEIVED:
			if (m_fin_pending) return tcp_error::connection_closing;

			m_syn_send = true;
			if (length + m_send_buffer.size() > m_send_buffer_capacity) return tcp_error::insufficient_resources;
			m_send_buffer.insert(m_send_buffer.end(), (const uint8_t *)buffer, (const uint8_t *)buffer + length);
			// set push / urgent...
			return tcp_error::ok;

		case tcp_state::TCPS_ESTABLISHED:
		case tcp_state::TCPS_CLOSE_WAIT:

			if (length + m_send_buffer.size() > m_send_buffer_capacity) return tcp_error::insufficient_resources;

			if (urgent)
				m_snd_up = m_snd_nxt - 1;

			m_send_buffer.insert(m_send_buffer.end(), (const uint8_t *)buffer, (const uint8_t *)buffer + length);
			// start sending it...
			return tcp_error::ok;

		case tcp_state::TCPS_FIN_WAIT_1:
		case tcp_state::TCPS_FIN_WAIT_2:
		case tcp_state::TCPS_CLOSING:
		case tcp_state::TCPS_LAST_ACK:
		case tcp_state::TCPS_TIME_WAIT:
			return tcp_error::connection_closing;

	}

}


// returns error, read-length, push, urgent
tcpip_device::tcp_error tcpip_device::receive(void *buffer, unsigned &length, bool *push, bool *urgent)
{
	// pp 56

	switch (m_state)
	{
		case tcp_state::TCPS_CLOSED:
			return tcp_error::connection_does_not_exist;

		case tcp_state::TCPS_LISTEN:
		case tcp_state::TCPS_SYN_SENT:
		case tcp_state::TCPS_SYN_RECEIVED:
			return tcp_error::insufficient_resources;

		case tcp_state::TCPS_CLOSE_WAIT:
			if (m_recv_buffer.empty()) return tcp_error::connection_closing;
			/* drop through */

		case tcp_state::TCPS_ESTABLISHED:
		case tcp_state::TCPS_FIN_WAIT_1:
		case tcp_state::TCPS_FIN_WAIT_2:

			length = std::min(length, static_cast<unsigned>(m_recv_buffer.size()));
			if (length > 0)
			{
				memcpy(buffer, m_recv_buffer.data(), length);
				m_recv_buffer.erase(m_recv_buffer.begin(), m_recv_buffer.begin() + length);	
				// todo -- urg, push
			}
			else
				length = 0;

			return tcp_error::ok;

		case tcp_state::TCPS_CLOSING:
		case tcp_state::TCPS_LAST_ACK:
		case tcp_state::TCPS_TIME_WAIT:
			return tcp_error::connection_closing;
	}

}

tcpip_device::tcp_error tcpip_device::close()
{
	// pp 60

	switch (m_state)
	{
		case tcp_state::TCPS_CLOSED:
			return tcp_error::connection_does_not_exist;

		case tcp_state::TCPS_LISTEN:
		case tcp_state::TCPS_SYN_SENT:
			set_state(tcp_state::TCPS_CLOSED);
			return tcp_error::ok;

		case tcp_state::TCPS_SYN_RECEIVED:

			if (m_send_buffer.empty())
			{
				// generate FIN
				set_state(tcp_state::TCPS_FIN_WAIT_1);
			}
			else
				m_fin_pending = true; // handle AFTER connection established and all data sent.
			return tcp_error::ok;

		case tcp_state::TCPS_ESTABLISHED:
			if (m_send_buffer.empty())
			{
				// send FIN...
			}
			else
				m_fin_pending = true;
			set_state(tcp_state::TCPS_FIN_WAIT_1);
			return tcp_error::ok;


		case tcp_state::TCPS_FIN_WAIT_1:
		case tcp_state::TCPS_FIN_WAIT_2:
			return tcp_error::ok;

		case tcp_state::TCPS_CLOSE_WAIT:
			if (m_send_buffer.empty())
			{
				// generate fin
				set_state(tcp_state::TCPS_LAST_ACK);
			}
			else
				// once all data is sent, generate a FIN segment and -> CLOSING.
				m_fin_pending = true;
			return tcp_error::ok;


		case tcp_state::TCPS_CLOSING:
		case tcp_state::TCPS_LAST_ACK:
		case tcp_state::TCPS_TIME_WAIT:
			return tcp_error::connection_closing;
	}
}

void tcpip_device::force_close()
{
	// set_state(tcp_state::TCPS_CLOSED);
	// invalidate timers, etc.
	m_state = tcp_state::TCPS_CLOSED;
	m_timer->reset();
	m_recv_buffer.clear();
	m_send_buffer.clear();
}

tcpip_device::tcp_error tcpip_device::abort()
{
	// pp 62
	switch (m_state)
	{
		case tcp_state::TCPS_CLOSED:
			return tcp_error::connection_does_not_exist;
		case tcp_state::TCPS_LISTEN:
		case tcp_state::TCPS_SYN_SENT:
			set_state(tcp_state::TCPS_CLOSED);
			return tcp_error::ok;

		case tcp_state::TCPS_SYN_RECEIVED:
		case tcp_state::TCPS_ESTABLISHED:
		case tcp_state::TCPS_FIN_WAIT_1:
		case tcp_state::TCPS_FIN_WAIT_2:
		case tcp_state::TCPS_CLOSE_WAIT:
			// todo
			// <SEQ=SND.NXT><CTL=RST>
			set_state(tcp_state::TCPS_CLOSED);
			return tcp_error::ok;

		case tcp_state::TCPS_CLOSING:
		case tcp_state::TCPS_LAST_ACK:
		case tcp_state::TCPS_TIME_WAIT:
			set_state(tcp_state::TCPS_CLOSED);
			return tcp_error::ok;
	}

}
