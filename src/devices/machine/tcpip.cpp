
#include "emu.h"
#include "tcpip.h"
#include "util/internet_checksum.h"


/*
  RFC 793: TCP Functional Specification
  RFC 1122: Requirements for Internet Hosts -- Communication Layers

  TCP/IP Illustrated, Volume 1: The Protocols
  TCP/IP Illustrated, Volume 2: The Implementation
*/










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


static uint32_t read32(const uint8_t *p)
{
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static uint16_t read16(const uint8_t *p)
{
	return (p[0] << 8) | p[1];
}

#if 0
static void write32(uint8_t *p, uint32_t x)
{
	p[0] = x >> 24;
	p[1] = x >> 16;
	p[2] = x >> 8;
	p[3] = x >> 0;
}
#endif

static void write16(uint8_t *p, uint16_t x)
{
	p[0] = x >> 8;
	p[1] = x >> 0;
}

enum {
	o_ETHERNET_DEST = 0,
	o_ETHERNET_SRC = 6,
	o_ETHERNET_TYPE = 12,

	ETHERTYPE_IP = 0x0800,
	ETHERTYPE_ARP = 0x0806,
	ETHERTYPE_IPV6 = 0x86dd,
};

enum {
	o_IP_IHL = 0, // version + header length
	o_IP_TOS = 1,
	o_IP_LENGTH = 2,
	o_IP_IDENTIFICATION = 4,
	o_IP_FLAGS = 6, // flags + fragment
	o_IP_TTL = 8,
	o_IP_PROTOCOL = 9,
	o_IP_CHECKSUM = 10,
	o_IP_SRC_ADDRESS = 12,
	o_IP_DEST_ADDRESS = 16,

	IP_PROTOCOL_TCP = 6,
};

enum {
	o_TCP_SRC_PORT = 0,
	o_TCP_DEST_PORT = 2,
	o_TCP_SEQ_NUMBER = 4,
	o_TCP_ACK_NUMBER = 8,
	o_TCP_DATA_OFFSET = 12,
	o_TCP_FLAGS = 13,
	o_TCP_WINDOW_SIZE = 14,
	o_TCP_CHECKUSM = 16,
	o_TCP_URGENT = 18,

	TCP_FIN = 0x01,
	TCP_SYN = 0x02,
	TCP_RST = 0x04,
	TCP_PSH = 0x08,
	TCP_ACK = 0x10,
	TCP_URG = 0x20,
	TCP_ECE = 0x40,
	TCP_CWR = 0x80,

};




static bool verify_segment(const uint8_t *segment, int length, int &ip_header_length, int &tcp_header_length, uint32_t &data_length)
{
	if (length < 14 + 20 + 20) return false;

	if (read16(segment + o_ETHERNET_TYPE) != ETHERTYPE_IP) return false;

	segment += 14;
	length -= 14;

	int ip_length = read16(segment + o_IP_LENGTH);
	int ihl = segment[o_IP_IHL];
	int version = ihl >> 4;
	ihl = (ihl & 0x0f) << 2;

	if (version != 4) return false;
	if (ihl < 20) return false;
	if (ip_length < ihl) return false;
	if (length < ip_length) return false;
	length = ip_length;

	if (util::internet_checksum_creator::simple(segment, ihl) != 0)
		return false;

	if (segment[o_IP_PROTOCOL] != IP_PROTOCOL_TCP) return false;


	uint8_t pseudo_header[12];
	memcpy(pseudo_header + 0, segment + o_IP_SRC_ADDRESS, 4);
	memcpy(pseudo_header + 4, segment + o_IP_DEST_ADDRESS, 4);


	ip_header_length = ihl;

	segment += ihl;
	length -= ihl;

	pseudo_header[8] = 0;
	pseudo_header[9] = IP_PROTOCOL_TCP;
	pseudo_header[10] = length >> 8;
	pseudo_header[11] = length;


	if (length < 20) return false;
	int data_offset = (segment[o_TCP_DATA_OFFSET] >> 4) << 2;
	if (data_offset < 20) return false;
	tcp_header_length = data_offset;

	if (length < data_offset) return false;

	int tcp_length = length;

	util::internet_checksum_creator cr;
	cr.append(pseudo_header, sizeof(pseudo_header));
	cr.append(segment, tcp_length);
	if (cr.finish() != 0) return false;

	data_length = ip_length - ip_header_length - tcp_header_length;

	return true;
}

DEFINE_DEVICE_TYPE(TCPIP, tcpip_device, "tcpip", "TCP/IP")

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
	if (length < 14 + 20 + 20) return false;

	const uint8_t *ether_ptr = static_cast<const uint8_t *>(buffer);

	if (read16(ether_ptr + 12) != ETHERTYPE_IP) return false;

	const uint8_t *ip_ptr = static_cast<const uint8_t *>(buffer) + length;
	int ip_length = (ip_ptr[0] & 0x0f) << 2;

	if (ip_length < 20) return false;

	const uint8_t *tcp_ptr = ip_ptr + ip_length;
	int tcp_length = (tcp_ptr[12] >> 4) << 2;
	if (tcp_length < 20) return false;

	uint16_t sport = read16(tcp_ptr + o_TCP_SRC_PORT);
	uint16_t dport = read16(tcp_ptr + o_TCP_DEST_PORT);

	uint32_t sip = read32(ip_ptr + o_IP_SRC_ADDRESS);
	uint32_t dip = read32(ip_ptr + o_IP_DEST_ADDRESS);


	if (m_state == tcp_state::TCPS_CLOSED) return false;
	if (m_state == tcp_state::TCPS_LISTEN)
	{
		return (dip == m_local_ip && dport == m_local_port);
	}

	return (dip == m_local_ip && dport == m_local_port && sip == m_remote_ip && sport == m_remote_port);
}

void tcpip_device::segment(const void *buffer, int length)
{
	int ip_header_length = 0;
	int tcp_header_length = 0;
	uint32_t seg_len = 0;

	if (!verify_segment(static_cast<const uint8_t *>(buffer), length,
		ip_header_length, tcp_header_length, seg_len))
		return;

	const uint8_t *ip_ptr = static_cast<const uint8_t *>(buffer) + 14;
	const uint8_t *tcp_ptr = ip_ptr + ip_header_length;
	//const uint8_t *data_ptr = tcp_ptr + tcp_header_length;

	int flags = tcp_ptr[o_TCP_FLAGS];
	uint32_t seg_ack = read32(tcp_ptr + o_TCP_ACK_NUMBER);
	uint32_t seg_seq = read32(tcp_ptr + o_TCP_SEQ_NUMBER);
	uint32_t seg_wnd = read16(tcp_ptr + o_TCP_WINDOW_SIZE);
	//uint32_t seg_up = read16(tcp_ptr + o_TCP_URGENT);
	// seg_prc ignored.

	uint16_t sport = read16(tcp_ptr + o_TCP_SRC_PORT);
	uint16_t dport = read16(tcp_ptr + o_TCP_DEST_PORT);

	uint32_t sip = read32(ip_ptr + o_IP_SRC_ADDRESS);
	uint32_t dip = read32(ip_ptr + o_IP_DEST_ADDRESS);

	if (m_state == tcp_state::TCPS_CLOSED)
	{
		//pp 65
		if (flags & TCP_RST) return;
		if (flags & TCP_ACK)
			send_segment(TCP_RST | TCP_ACK, 0, seg_seq + seg_len);
		else
			send_segment(TCP_RST, seg_ack, 0);

		return;
	}

	if (m_state == tcp_state::TCPS_LISTEN)
	{
		// rst?
		if (dport != m_local_port || dip != m_local_ip) return;


		// pp 65
		if (flags & TCP_RST) return;
		if (flags & TCP_ACK)
		{
			send_segment(TCP_RST, seg_ack, 0);
			return;
		}
		if (flags & TCP_SYN)
		{
			m_disconnect_type = disconnect_type::none;

			m_rcv_nxt = seg_seq + 1;
			m_irs = seg_seq;
			m_iss = generate_iss();
			send_segment(TCP_SYN|TCP_ACK, m_iss, m_rcv_nxt);
			m_snd_nxt = m_iss + 1;
			m_snd_una = m_iss;
			m_remote_port = read16(tcp_ptr + o_TCP_SRC_PORT);
			m_remote_ip = read32(ip_ptr + o_IP_SRC_ADDRESS);
			memcpy(m_remote_mac, static_cast<const uint8_t *>(buffer) + o_IP_SRC_ADDRESS, 6);
			set_state(tcp_state::TCPS_SYN_RECEIVED);
		}
		return;
	}

	// rst?
	if (dport != m_local_port || dip != m_local_ip || sport != m_remote_port || sip != m_remote_ip)
		return;

	if (m_state == tcp_state::TCPS_SYN_SENT)
	{
		// pp 66

		// note - snd.una = iss, snd.nxt = iss + 1
		if (flags & TCP_ACK)
		{
			// If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send a reset (unless
          	// the RST bit is set, if so drop the segment and return)
			// If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is acceptable.
			// n.b. = snd.una = iss, snd.next = iss + 1
			// errata: In practice today, much code seems to be simplifying further and checking that
			// SEG.ACK == SND.NXT, for stacks that are not sending data on the SYN, ...

			if (!ack_valid_le_le(m_snd_una, seg_ack, m_snd_nxt))
			{
				if (flags & TCP_RST) return;
				send_segment(TCP_RST, seg_ack, 0);
				return;
			}
		}
		if (flags & TCP_RST)
		{
			if (flags & TCP_ACK)
			{
				disconnect(disconnect_type::rst);
				return;
			}
			return;
		}

		if (flags & TCP_SYN)
		{
			m_rcv_nxt = seg_seq + 1;
			m_irs = seg_seq;
			if (flags & TCP_ACK)
				m_snd_una = seg_seq;
			// segments on tx queue now acknowedged should be removed.
			m_timer->reset();

			// If SND.UNA > ISS (our SYN has been ACKed)
			if (m_snd_una != m_iss)
			{
				m_snd_wnd = seg_wnd;
				m_snd_wl1 = seg_seq;
				m_snd_wl2 = seg_ack;

				// if data queued, may start sending it now...

				send_segment(TCP_ACK, m_snd_nxt, m_rcv_nxt);
				set_state(tcp_state::TCPS_ESTABLISHED);

				// TODO - if other controls or text, continue processing.
			}
			else
			{
				send_segment(TCP_SYN|TCP_ACK, m_iss, m_rcv_nxt);
				set_state(tcp_state::TCPS_SYN_RECEIVED);

				// TODO - if other controls or text, queue for after established.
				return;
			}

		}
		return;
	}

	// pp 69

	// sequence # check
	bool seq_ok = false;

	if (seg_len > 0 && m_rcv_wnd == 0)
	{
		// TODO -
		/* special allowance for ACKs, URGs, RST. */
	}

	switch (((seg_len > 0) << 1) | (m_rcv_wnd > 0))
	{
		case 0b00:
			seq_ok = seg_seq == m_rcv_nxt;
			break;
		case 0b01:
			seq_ok = ack_valid_le_lt(m_rcv_nxt, seg_seq, m_rcv_nxt + m_rcv_wnd);
			break;
		case 0b10:
			seq_ok = false;
			break;
		case 0b11:
			seq_ok = ack_valid_le_lt(m_rcv_nxt, seg_seq, m_rcv_nxt + m_rcv_wnd)
				|| ack_valid_le_lt(m_rcv_nxt, seg_seq + seg_len - 1, m_rcv_nxt + m_rcv_wnd);
	}



	if (!seq_ok)
	{
		if (flags & TCP_RST) return;
		send_segment(TCP_ACK, m_snd_nxt, m_rcv_nxt);
		return;
	}
	if (flags & TCP_RST)
	{
		// pp 70
		m_timer->reset();
		switch(m_state)
		{
			case tcp_state::TCPS_SYN_RECEIVED:
				disconnect(disconnect_type::rst, m_passive ? tcp_state::TCPS_LISTEN : tcp_state::TCPS_CLOSED);
				return;
			case tcp_state::TCPS_ESTABLISHED:
			case tcp_state::TCPS_FIN_WAIT_1:
			case tcp_state::TCPS_FIN_WAIT_2:
			case tcp_state::TCPS_CLOSE_WAIT:
			case tcp_state::TCPS_CLOSING:
			case tcp_state::TCPS_LAST_ACK:
			case tcp_state::TCPS_TIME_WAIT:

				disconnect(disconnect_type::rst);
				return;

			default:
				return;
		}
	}
	if (flags & TCP_SYN)
	{
		// pp 71
		// TODO - if the SYN is in the window it is an error; reset.

		return;
	}

	if (flags & TCP_ACK)
	{
		switch(m_state)
		{
			case tcp_state::TCPS_SYN_RECEIVED:
				if (ack_valid_le_le(m_snd_una, seg_ack, m_snd_nxt))
				{
					m_snd_wnd <- seg_wnd;
					m_snd_wl1 <- seg_seq;
					m_snd_wl2 <- seg_ack;

					set_state(tcp_state::TCPS_ESTABLISHED);
				}
				else
				{
					send_segment(TCP_RST, seg_ack, 0);
					return;
				}
				/* drop through */

			case tcp_state::TCPS_ESTABLISHED:
			case tcp_state::TCPS_FIN_WAIT_1:
			case tcp_state::TCPS_FIN_WAIT_2:
			case tcp_state::TCPS_CLOSE_WAIT:
			case tcp_state::TCPS_CLOSING:

				if (ack_valid_lt_le(m_snd_una, seg_ack, m_snd_nxt))
				{
					m_snd_una = seg_ack;
					// TODO - update tx queue
				}
				// if seg_ack <= m_snd_una -> duplicate, ignore
				// if seg_ack > m_snd_nxt, send ack, drop the segment, return;
				if (ack_valid_le_le(m_snd_una, seg_ack, m_snd_nxt))
				{
					// TODO -- update send window.

				}

				// fin-wait1 - go to fin-wait-2 if fin acknowledged.
				// closing - go to time wait if fin acknowledged.
				break;

			case tcp_state::TCPS_LAST_ACK:
				// if FIN acknowledged, go to closed state.
				break;
			case tcp_state::TCPS_TIME_WAIT:
				//  re-transmit of remote FIN? acknowledge and restart timer.
				break;

			default:
				break;
		}
	}
	else return; // no ack.

	if (flags & TCP_URG)
	{
		// pp 73
		switch(m_state)
		{
			case tcp_state::TCPS_ESTABLISHED:
			case tcp_state::TCPS_FIN_WAIT_1:
			case tcp_state::TCPS_FIN_WAIT_2:
				break;
			default: break;
		}
	}

	// segment text
	if (seg_len)
	{
		// pp 74
	}

	if (flags & TCP_FIN)
	{
		// pp 75
		m_rcv_nxt += 1;
		// ack it .
		switch(m_state)
		{
			case tcp_state::TCPS_SYN_RECEIVED:
			case tcp_state::TCPS_ESTABLISHED:
				m_disconnect_type = disconnect_type::passive;
				set_state(tcp_state::TCPS_CLOSE_WAIT);
				break;

			case tcp_state::TCPS_FIN_WAIT_1:
				// if our FIN acked, -> time wait.
				// otherwise -> CLOSING.
				break;
			case tcp_state::TCPS_FIN_WAIT_2:
				set_state(tcp_state::TCPS_TIME_WAIT);
				break;

			case tcp_state::TCPS_CLOSE_WAIT:
			case tcp_state::TCPS_CLOSING:
			case tcp_state::TCPS_LAST_ACK:
				break;
			case tcp_state::TCPS_TIME_WAIT:
				// restart the 2msl timer
				break;

			default: break;
		}

	}
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

n.b. open split into separate listen command for passive connections.
*/

tcpip_device::tcp_error tcpip_device::open(uint32_t ip, uint16_t port)
{
	// pp 54 

	if (m_state != tcp_state::TCPS_CLOSED) return tcp_error::connection_already_exists;

	m_passive = false;
	m_disconnect_type = disconnect_type::none;

	m_remote_ip = ip;
	m_remote_port = port;

	m_fin_pending = false;
	// m_syn_send = false;

	m_iss = generate_iss();
	m_snd_una = m_iss;
	m_snd_nxt = m_iss + 1;


	// generate segment - <SEQ=ISS><CTL=SYN>
	send_segment(TCP_SYN, m_iss, 0);
	set_state(tcp_state::TCPS_SYN_SENT);
	return tcp_error::ok;
}

tcpip_device::tcp_error tcpip_device::listen(uint16_t port)
{
	// pp 54

	if (m_state != tcp_state::TCPS_CLOSED) return tcp_error::connection_already_exists;

	m_passive = true;
	m_disconnect_type = disconnect_type::none;

	m_remote_ip = 0;
	m_remote_port = 0;
	memset(m_remote_mac, 0, 6);

	m_local_port = port;

	m_fin_pending = false;
	// m_syn_send = false;


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

			// m_syn_send = true;
			if (length + m_send_buffer.size() > m_send_buffer_capacity) return tcp_error::insufficient_resources;
			m_send_buffer.insert(m_send_buffer.end(), (const uint8_t *)buffer, (const uint8_t *)buffer + length);
			m_psh_pending |= push;

			if (urgent)
				m_snd_up = m_snd_nxt - 1;
			return tcp_error::ok;

		case tcp_state::TCPS_ESTABLISHED:
		case tcp_state::TCPS_CLOSE_WAIT:

			if (m_fin_pending) return tcp_error::connection_closing;

			if (length + m_send_buffer.size() > m_send_buffer_capacity) return tcp_error::insufficient_resources;

			m_send_buffer.insert(m_send_buffer.end(), (const uint8_t *)buffer, (const uint8_t *)buffer + length);
			m_psh_pending |= push;

			if (urgent)
				m_snd_up = m_snd_nxt - 1;

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
			disconnect(disconnect_type::active);
			return tcp_error::ok;

		case tcp_state::TCPS_SYN_RECEIVED:

			m_disconnect_type = disconnect_type::active;
			if (m_send_buffer.empty())
			{
				send_segment(TCP_FIN|TCP_ACK, m_snd_nxt, m_rcv_nxt);
				m_snd_nxt += 1;
				set_state(tcp_state::TCPS_FIN_WAIT_1);
			}
			else
				m_fin_pending = true; // handle AFTER connection established and all data sent.
			return tcp_error::ok;

		case tcp_state::TCPS_ESTABLISHED:
			m_disconnect_type = disconnect_type::active;
			if (m_send_buffer.empty())
			{
				send_segment(TCP_FIN|TCP_ACK, m_snd_nxt, m_rcv_nxt);
				m_snd_nxt += 1;
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
				send_segment(TCP_FIN|TCP_ACK, m_snd_nxt, m_rcv_nxt);
				m_snd_nxt += 1;
				set_state(tcp_state::TCPS_LAST_ACK);
			}
			else
				// once all data is sent, generate a FIN segment and -> LAST-ACK.
				m_fin_pending = true;
			return tcp_error::ok;


		case tcp_state::TCPS_CLOSING:
		case tcp_state::TCPS_LAST_ACK:
		case tcp_state::TCPS_TIME_WAIT:
			return tcp_error::connection_closing;
	}
}

void tcpip_device::disconnect(disconnect_type dt, tcp_state new_state)
{
	if (m_disconnect_type == disconnect_type::none) m_disconnect_type = dt;
	m_send_buffer.clear();
	m_recv_buffer.clear();
	m_timer->reset();

	set_state(new_state);
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

	m_timer->reset();
	switch (m_state)
	{
		case tcp_state::TCPS_CLOSED:
			return tcp_error::connection_does_not_exist;
		case tcp_state::TCPS_LISTEN:
		case tcp_state::TCPS_SYN_SENT:
			break;

		case tcp_state::TCPS_SYN_RECEIVED:
		case tcp_state::TCPS_ESTABLISHED:
		case tcp_state::TCPS_FIN_WAIT_1:
		case tcp_state::TCPS_FIN_WAIT_2:
		case tcp_state::TCPS_CLOSE_WAIT:
			// <SEQ=SND.NXT><CTL=RST>
			send_segment(TCP_RST, m_snd_nxt, 0);
			break;

		case tcp_state::TCPS_CLOSING:
		case tcp_state::TCPS_LAST_ACK:
		case tcp_state::TCPS_TIME_WAIT:
			break;
	}

	disconnect(disconnect_type::active);
	return tcp_error::ok;

}


void tcpip_device::send_segment(int flags, uint32_t seq, uint32_t ack)
{
	if (!m_send_function) return;

	static const int SEGMENT_SIZE = 54;
	uint8_t segment[SEGMENT_SIZE];

	uint8_t *ptr = segment;

	memcpy(ptr, m_remote_mac, 6);
	memcpy(ptr + 6, m_local_mac, 6);
	write16(ptr + 12, ETHERTYPE_IP);
	ptr += 14;


	m_send_function(segment, SEGMENT_SIZE);
}
