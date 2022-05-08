// license:BSD-3-Clause
// copyright-holders: Kelvin Sherlock

#include "emu.h"
#include "machine/w5100.h"

#include "util/internet_checksum.h"

/*
  0x0000-0x0012f - common registers
  0x0030-0x03ff - reserved
  0x0400-0x7fff - socket registers
  0x0800-0x3fff - reserved
  0x4000-0x5fff - tx memory
  0x6000-0x7fff - rx memory

  Based on:
  W5100 datasheet
  W5200 datasheet (occasionally better explanations)
  W5500 datasheet (occasionally better explanations)
  WIZNet ioLibrary Driver (https://github.com/Wiznet/ioLibrary_Driver)

 */


/* indirect mode addresses */
enum {
	IDM_OR = 0x00,
	IDM_AR0 = 0x01,
	IDM_AR1 = 0x02,
	IDM_DR = 0x03
};

/* Common registers */
enum {
	MR = 0x00,
	GAR0,
	GAR1,
	GAR2,
	GAR3,
	SUBR0,
	SUBR1,
	SUBR2,
	SUBR3,
	SHAR0,
	SHAR1,
	SHAR2,
	SHAR3,
	SHAR4,
	SHAR5,
	SIPR0,
	SIPR1,
	SIPR2,
	SIPR3,
	/* 0x13-0x14 reserved */
	IR = 0x15,
	IMR,
	RTR0,
	RTR1,
	RCR,
	RMSR,
	TMSR,
	PATR0,
	PATR1,
	/* 0x1e-0x27 reserved */
	PTIMER = 0x28,
	PMAGIC,
	UIPR0,
	UIPR1,
	UIPR2,
	UIPR3,
	UPORT0,
	UPORT1,
	/* 0x30-0x3ff reserved */
};

/* Socket Registers */
enum {
	Sn_MR = 0x00,
	Sn_CR,
	Sn_IR,
	Sn_SR,
	Sn_PORT0,
	Sn_PORT1,
	Sn_DHAR0,
	Sn_DHAR1,
	Sn_DHAR2,
	Sn_DHAR3,
	Sn_DHAR4,
	Sn_DHAR5,
	Sn_DIPR0,
	Sn_DIPR1,
	Sn_DIPR2,
	Sn_DIPR3,
	Sn_DPORT0,
	Sn_DPORT1,
	Sn_MSSR0,
	Sn_MSSR1,
	Sn_PROTO,
	Sn_TOS,
	Sn_TTL,
	/* 0x17-0x1f reserved */
	Sn_TX_FSR0 = 0x20,
	Sn_TX_FSR1,
	Sn_TX_RD0,
	Sn_TX_RD1,
	Sn_TX_WR0,
	Sn_TX_WR1,
	Sn_RX_RSR0,
	Sn_RX_RSR1,
	Sn_RX_RD0,
	Sn_RX_RD1,
	Sn_RX_WR0,
	Sn_RX_WR1,
	/* 0x042c-0x04ff reserved */

	/* internal variables used in emulation. */
	Sn_XX_ARP_IP_ADDRESS = 0x00f0,
	Sn_XX_ARP_OK = 0xf4,
	Sn_XX_RETRY,
};

/* Mode Register bits */
enum {
	MR_RST = 0x80,
	MR_PB = 0x10,
	MT_PPPoE = 0x08,
	MR_AI = 0x02,
	MR_IND = 0x01
};

/* Interrupt Register bits */
enum {
	IR_CONFLICT = 0x80,
	IR_UNREACH = 0x40,
	IR_PPPoE = 0x20,
	IR_S3_INT = 0x08,
	IR_S2_INT = 0x04,
	IR_S1_INT = 0x02,
	IR_S0_INT = 0x01
};

/* Socket Mode Register */
enum {
	Sn_MR_MULT = 0x80,
	Sn_MR_MF = 0x40,
	Sn_MR_ND = 0x20,
	Sn_MR_MC = 0x20,

	Sn_MR_CLOSED = 0x00,
	Sn_MR_TCP = 0x01,
	Sn_MR_UDP = 0x02,
	Sn_MR_IPRAW = 0x03,
	Sn_MR_MACRAW = 0x04,
	Sn_MR_PPPoE = 0x05
};


/* SocketCommand Register */
enum {
	Sn_CR_OPEN = 0x01,
	Sn_CR_LISTEN = 0x02,
	Sn_CR_CONNECT = 0x04,
	Sn_CR_DISCON = 0x08,
	Sn_CR_CLOSE = 0x10,
	Sn_CR_SEND = 0x20,
	Sn_CR_SEND_MAC = 0x21,
	Sn_CR_SEND_KEEP = 0x22,
	Sn_CR_RECV = 0x40,
};


/* Socket Status Register */
enum {
	Sn_SR_CLOSED = 0x00,
	Sn_SR_INIT = 0x13,
	Sn_SR_LISTEN = 0x14,
	Sn_SR_ESTABLISHED = 0x17,
	Sn_SR_CLOSE_WAIT = 0x1c,
	Sn_SR_UDP = 0x22,
	Sn_SR_IPRAW = 0x32,
	Sn_SR_MACRAW = 0x42,
	Sn_SR_PPPOE = 0x5f,

	Sn_SR_SYNSENT = 0x15,
	Sn_SR_SYNRECV = 0x16,
	Sn_SR_FIN_WAIT = 0x18,
	Sn_SR_CLOSING = 0x1a,
	Sn_SR_TIME_WAIT = 0x18,
	Sn_SR_LAST_ACK = 0x1d,
	Sn_SR_ARP = 0x01,
};

/* Socket Interrupt Register */
enum {
	Sn_IR_SEND_OK = 0x10,
	Sn_IR_TIMEOUT = 0x08,
	Sn_IR_RECV = 0x04,
	Sn_IR_DISCON = 0x02,
	Sn_IR_CON = 0x01,
};


enum {
	Sn_BASE = 0x0400,
	Sn_SIZE = 0x0100,
	IO_TXBUF = 0x4000,
	IO_RXBUF = 0x6000
};


/* MISC IP, ARP, etc constants */
enum {
	ETHERTYPE_IP = 0x0800,
	ETHERTYPE_ARP = 0x0806,

	ARP_REQUEST = 0x01, // rfc 826
	ARP_REPLY = 0x02,
	ICMP_ECHO_REPLY = 0x00, // rfc 792
	ICMP_DESTINATION_UNREACHABLE = 0x03,
	ICMP_ECHO_REQUEST = 0x8,

	IP_ICMP = 1,
	IP_IGMP = 2,
	IP_TCP = 6,
	IP_UDP = 17,

};


/*
 Timeouts:
 RTR- retry timeout register - is in units of 100us. Default value (2000) is 200ms
 Sn_MR_ND - No Delayed Ack (TCP only) - 
 Sn_IR_TIMEOUT 0

*/


static uint8_t ETH_BROADCAST[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };



static uint32_t read32(const uint8_t *p)
{
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static uint16_t read16(const uint8_t *p)
{
	return (p[0] << 8) | p[1];
}

w5100_device::w5100_device(machine_config const& mconfig, char const *tag, device_t *owner, u32 clock)
	: w5100_device(mconfig, W5100, tag, owner, clock)
{}

w5100_device::w5100_device(const machine_config &mconfig, device_type type, const char *tag, device_t *owner, uint32_t clock)
	: device_t(mconfig, type, tag, owner, clock)
	, device_network_interface(mconfig, *this, 10.0f)
	, m_irq_handler(*this)
{
}

void w5100_device::device_start()
{

	save_item(NAME(m_idm));
	save_item(NAME(m_irq_state));



	for (int sn = 0; sn < 4; ++ sn)
		m_timers[sn] = timer_alloc(sn);

	device_reset();
}


void w5100_device::device_reset()
{
	memset(m_memory, 0, sizeof(m_memory));

	memset(m_sockets, 0, sizeof(m_sockets));

	m_memory[RTR0] = 0x07;
	m_memory[RTR1] = 0xd0;
	m_memory[RCR] = 0x08;
	m_memory[RMSR] = 0x55;
	m_memory[TMSR] = 0x55;
	m_memory[PTIMER] = 0x28;

	update_tmsr(0x55);
	update_rmsr(0x55);

	for (int sn = 0; sn < 4; ++sn)
	{
		uint8_t *socket = m_memory + Sn_BASE + sn * Sn_SIZE;

		for (int i = 0; i < 6; ++i)
		{
			socket[Sn_DHAR0+i] = 0xff;
		}

		socket[Sn_TTL] = 0x80;

		// socket[Sn_TX_FSR0] = 0x08;
		// socket[Sn_TX_FSR1] = 0x00;
	}



	if (m_irq_state)
		m_irq_handler(CLEAR_LINE);
	m_irq_state = 0;

	set_mac(reinterpret_cast<char *>(&m_memory[SHAR0]));
	set_promisc(false);
}


void w5100_device::device_post_load()
{
	memset(m_sockets, 0, sizeof(m_sockets));
	update_tmsr(m_memory[TMSR]);
	update_rmsr(m_memory[RMSR]);
}


/*
 * timer callback.
 * re-sends timed out ARP and TCP messages.
 * id is the socket #
 */
void w5100_device::device_timer(emu_timer &timer, device_timer_id id, int param)
{
	#if 0
	attotime now = machine().time();
	for (int sn = 0; sn < 4; ++sn)
	{
		uint8_t *socket = m_memory[Sn_BASE + sn * Sn_SIZE];
		uint8_t &sr = socket[Sn_SR];
		if (sr == Sn_SR_ARP)
		{
			if (m_sockets[sn].start + m_timeout > now)
			{
				// change sr back to UDP/IPRAW/OPEN(tcp)
				socket[Sn_IR] | Sn_IR_TIMEOUT;
				update_ethernet_irq();
			}
			else
			{
				/* TODO re-send ARP request */
			}
		}
		// TODO -- TCP stuff
	}
	#endif

}


void w5100_device::update_ethernet_irq()
{
	uint8_t ir = m_memory[IR] & 0b11100000;

	for (int sn = 0, bit = IR_S0_INT; sn < 4; ++sn, bit <<= 1)
	{
		const uint8_t *socket = m_memory + Sn_BASE + sn * Sn_SIZE;
		if (socket[Sn_IR]) ir |= bit;
	}

	m_memory[IR] = ir;

	uint8_t new_state = ir & m_memory[IMR];

	if (new_state ^ m_irq_state)
	{
		m_irq_state = new_state;
		m_irq_handler(m_irq_state ? ASSERT_LINE : CLEAR_LINE);		
	}

}

/*
 * Direct bus interface: 15-bit address, 8-bit data bus
 * Indirect bus interface: 2-bit address, 8-bit data bus
 */
void w5100_device::write(uint16_t offset, uint8_t data)
{
	if (m_memory[0] & MR_IND)
	{
		switch(offset & 0x03)
		{
			case IDM_OR:
				offset = 0;
				break;
			case IDM_AR0:
				m_idm = (m_idm & 0x00ff) | (data << 8);
				return;
				break;
			case IDM_AR1:
				m_idm = (m_idm & 0xff00) | data;
				return;
				break;
			case IDM_DR:
				offset = m_idm;
				if (m_memory[0] & MR_AI)
				{
					m_idm++;
					if (m_idm == 0x6000) m_idm = 0x4000;
					if (m_idm == 0x8000) m_idm = 0x6000;
					if (m_idm == 0x0000) m_idm = 0xe000;
				}
				break;
		}
	}

	offset &= 0x7fff;

	switch(offset)
	{
		case IR:
			/* interrupt bits 5-7 cleared by writing 1 to them; bits 0-3 cleared via Sn_IR register */
			m_memory[IR] &= ~(data & 0b11100000);
			update_ethernet_irq();
			return;

		case Sn_IR + Sn_BASE + (Sn_SIZE * 0):
		case Sn_IR + Sn_BASE + (Sn_SIZE * 1):
		case Sn_IR + Sn_BASE + (Sn_SIZE * 2):
		case Sn_IR + Sn_BASE + (Sn_SIZE * 3):
			m_memory[offset] &= ~(data & 0b00011111);
			update_ethernet_irq();
			return;

		case Sn_CR + Sn_BASE + (Sn_SIZE * 0):
		case Sn_CR + Sn_BASE + (Sn_SIZE * 1):
		case Sn_CR + Sn_BASE + (Sn_SIZE * 2):
		case Sn_CR + Sn_BASE + (Sn_SIZE * 3):
			socket_command((offset - Sn_BASE) / Sn_SIZE, data);
			return;
	}

	m_memory[offset] = data;

	switch(offset)
	{
		case MR:
			if (data & MR_RST)
				device_reset();
			break;

		case SHAR0:
		case SHAR1:
		case SHAR2:
		case SHAR3:
		case SHAR4:
		case SHAR5:
			set_mac(reinterpret_cast<char *>(&m_memory[SHAR0]));
			break;

		case IMR:
			update_ethernet_irq();
			break;

		case RMSR:
			update_rmsr(data);
			break;

		case TMSR:
			update_tmsr(data);
			break;

		case Sn_MR + Sn_BASE:
			// promisc bit only valid for socket 0.
			// enabled when macraw socket is opened.
			if ((data & Sn_MR_MF) == Sn_MR_MF)
				set_promisc(false);
			break;
	}

}


uint8_t w5100_device::read(uint16_t offset)
{
	if (m_memory[0] & MR_IND)
	{
		switch(offset & 0x03)
		{
			case IDM_OR:
				return m_memory[0];
				break;
			case IDM_AR0:
				return m_idm >> 8;
				break;
			case IDM_AR1:
				return m_idm & 0xff;
				break;
			case IDM_DR:
				offset = m_idm;

				if ((m_memory[0] & MR_AI) && !machine().side_effects_disabled())
				{
					m_idm++;
					if (m_idm == 0x6000) m_idm = 0x4000;
					if (m_idm == 0x8000) m_idm = 0x6000;
					if (m_idm == 0x0000) m_idm = 0xe000;
				}
				break;
		}
	}

	offset &= 0x7fff;

	return m_memory[offset];
}



void w5100_device::update_rmsr(uint8_t value)
{

	int offset = IO_RXBUF;
	for (int sn = 0; sn < 4; ++sn, value >>= 2)
	{
		int size = 1024 << (value & 0x3);
		m_sockets[sn].rx_buffer_size = size;
		m_sockets[sn].rx_buffer_offset = offset;
		offset += size;
	}
	// TODO - if offset > IO_RXBUF + 0x2000 ....
}

void w5100_device::update_tmsr(uint8_t value)
{

	int offset = IO_TXBUF;
	for (int sn = 0; sn < 4; ++sn, value >>= 2)
	{
		int size = 1024 << (value & 0x3);
		m_sockets[sn].tx_buffer_size = size;
		m_sockets[sn].tx_buffer_offset = offset;
		offset += size;

		/* also update FSR ... */
		uint8_t *socket = m_memory + Sn_BASE + sn * Sn_SIZE;
		uint16_t read_ptr = read16(&socket[Sn_TX_RD0]);
		uint16_t write_ptr = read16(&socket[Sn_TX_WR0]);


		//
		//  |--free--|--used--|--free--|
		//           rd       wr
		//
		//  |--used--|--free--|--used--|
		//           wr       rd
		//
		read_ptr &= (size - 1);
		write_ptr &= (size - 1);
		int fsr = size + read_ptr - write_ptr;
		if (fsr > size) fsr -= size;
		socket[Sn_TX_FSR0] = fsr >> 8;
		socket[Sn_TX_FSR1] = fsr;
	}

	// TODO - if offset > IO_TXBUF + 0x2000 ....

}

#if 0
void w5100_device::get_tmsr(int sn, int &offset, int &size) const
{
	int tmsr = m_memory[TMSR];
	offset = IO_TXBUF;
	for (int i = 0; i < sn; ++i, tmsr >>= 2)
	{
		int tmp = 1024 << (tmsr & 0x03);
		offset += tmp;
	}
	size = 1024 << (tmsr & 0x03);
}

void w5100_device::get_rmsr(int sn, int &offset, int &size) const
{
	int rmsr = m_memory[RMSR];
	offset = IO_RXBUF;
	for (int i = 0; i < sn; ++i, rmsr >>= 2)
	{
		int tmp = 1024 << (rmsr & 0x03);
		offset += tmp;
	}
	size = 1024 << (rmsr & 0x03);
}
#endif

void w5100_device::socket_command(int sn, int command)
{
	if (sn < 0 || sn > 3) return;

	uint8_t *socket = m_memory + Sn_BASE + (Sn_SIZE * sn);
	//unsigned proto = socket[Sn_MR] & 0x0f;
	uint8_t &sr = socket[Sn_SR];

	switch(command)
	{
		case Sn_CR_OPEN:
			if (sr == Sn_SR_CLOSED)
				socket_open(sn);
			break;

		case Sn_CR_LISTEN:
			if (sr == Sn_SR_INIT)
				sr = Sn_SR_LISTEN;
			break;

		case Sn_CR_CONNECT:
			if (sr == Sn_SR_INIT)
				socket_connect(sn);
			break;

		case Sn_CR_DISCON:
			if (sr == Sn_SR_ESTABLISHED || sr == Sn_SR_CLOSE_WAIT)
				socket_disconnect(sn);
			break;

		case Sn_CR_CLOSE:
			sr = Sn_SR_CLOSED;
			/* TODO - if UDP Multicast, send IGMP leave message */
			/* also reset interrupts? */
			break;

		case Sn_CR_RECV:
			if (sr == Sn_SR_UDP || sr == Sn_SR_IPRAW || sr == Sn_SR_MACRAW || sr == Sn_SR_ESTABLISHED || sr == Sn_SR_CLOSE_WAIT)
				socket_recv(sn);
			break;

		case Sn_CR_SEND:
			if (sr == Sn_SR_UDP || sr == Sn_SR_IPRAW || sr == Sn_SR_MACRAW || sr == Sn_SR_ESTABLISHED || sr == Sn_SR_CLOSE_WAIT)
				socket_send(sn);
			break;

		case Sn_CR_SEND_MAC:
			if (sr == Sn_SR_UDP || sr == Sn_SR_IPRAW)
				socket_send_mac(sn);
			break;

		case Sn_CR_SEND_KEEP:
			if (sr == Sn_SR_ESTABLISHED || sr == Sn_SR_CLOSE_WAIT)
				socket_send_keep(sn);
			break;
	}
}

void w5100_device::socket_open(int sn)
{
	uint8_t *socket = m_memory + Sn_BASE + (Sn_SIZE * sn);
	unsigned proto = socket[Sn_MR] & 0x0f;
	uint8_t &sr = socket[Sn_SR];

	// reset read/write pointers
	socket[Sn_RX_RD0] = 0;
	socket[Sn_RX_RD1] = 0;
	socket[Sn_RX_WR0] = 0;
	socket[Sn_RX_WR1] = 0;

	socket[Sn_TX_RD0] = 0;
	socket[Sn_TX_RD1] = 0;
	socket[Sn_TX_WR0] = 0;
	socket[Sn_TX_WR1] = 0;

	m_sockets[sn].reset();

	switch (proto)
	{
		case Sn_MR_TCP:
			sr = Sn_SR_INIT;
			break;
		case Sn_MR_UDP:
			/* TODO -- if multicast bit is set, generate IGMP register message */
			sr = Sn_SR_UDP;
			break;
		case Sn_MR_IPRAW:
			sr = Sn_SR_IPRAW;
			break;

		case Sn_MR_MACRAW:
			if (sn == 0)
			{
				sr = Sn_SR_MACRAW;
				if ((socket[Sn_MR] & Sn_MR_MF) == 0)
					set_promisc(true);
			}
			break;

		case Sn_MR_PPPoE: /* pppoe */
			if (sn == 0)
				sr = Sn_SR_PPPOE;
			break;

		case Sn_MR_CLOSED: /* closed */
			break;
	}
}

static int proto_header_size(int proto)
{
	switch(proto)
	{
		case Sn_MR_MACRAW:
			return 0;
			break;
		case Sn_MR_IPRAW:
			return 14 + 20;
			break;
		case Sn_MR_UDP:
			return 14 + 20 + 8;
			break;
		case Sn_MR_TCP:
			return 14 + 20 + 32; // TCP header is variable
			break;
		default:
			return 0;
	}	
}


void copy_in(uint8_t *dest, const uint8_t *src, int length, int src_offset, int bank_size)
{
	int avail = bank_size - src_offset;

	if (avail >= length)
		memcpy(dest, src + src_offset, length);
	else
	{
		memcpy(dest, src + src_offset, avail);
		memcpy(dest + avail, src, length - avail);
	}
}

void copy_out(uint8_t *dest, const uint8_t *src, int length, int dest_offset, int bank_size)
{
	int avail = bank_size - dest_offset;

	if (avail >= length)
		memcpy(dest + dest_offset, src, length);
	else
	{
		memcpy(dest + dest_offset, src, avail);
		memcpy(dest, src + avail, length - avail);
	}

}

void w5100_device::socket_send(int sn)
{
	static const int BUFFER_SIZE = 1514;
	uint8_t buffer[BUFFER_SIZE];

	uint8_t *socket = m_memory + Sn_BASE + (Sn_SIZE * sn);
	// uint8_t sr = socket[Sn_SR];
	unsigned proto = socket[Sn_MR] & 0x0f;


	// if this is a UDP or IPRAW socket, possibly send an ARP
	// and perform send once resolved...

	if (proto == Sn_MR_UDP || proto == Sn_MR_IPRAW)
	{
		if (!find_mac(sn)) return;
	}


	int tx_buffer_offset = m_sockets[sn].tx_buffer_offset;
	int tx_buffer_size = m_sockets[sn].tx_buffer_size;

	uint16_t read_ptr = (socket[Sn_TX_RD0] << 8) |  socket[Sn_TX_RD1];
	uint16_t write_ptr = (socket[Sn_TX_WR0] << 8) |  socket[Sn_TX_WR1];

	read_ptr &= (tx_buffer_size - 1);
	write_ptr &= (tx_buffer_size - 1);


	int size = read_ptr - write_ptr;
	if (size < 0) size += tx_buffer_size;

	int header = proto_header_size(proto);
	int mss = 1514;

	switch(proto)
	{
		case Sn_MR_UDP:
		case Sn_MR_TCP:
			// n.b. - this mss does not include the ethernet header (14 bytes)
			mss = (socket[Sn_MSSR0] << 8) | socket[Sn_MSSR1];
			mss += 14;
			break;
	}
	mss = std::min(mss, BUFFER_SIZE);

	int tx_size = std::min(size, mss - header);

	// TODO -- size logic is not correct.


	/* for MACRAW/IPRAW  limit to 1514 bytes (w/ header)*/

	memset(buffer, 0, header);
	copy_in(buffer + header, m_memory + tx_buffer_offset, tx_size, read_ptr, tx_buffer_size);

	// ipraw, udp, tcp - add headers.

	if (proto == Sn_MR_IPRAW)
		build_ipraw_header(sn, buffer, size);


	if (proto == Sn_MR_MACRAW || proto == Sn_MR_IPRAW)
	{
		send(buffer, size);
		socket[Sn_TX_RD0] = write_ptr >> 8;
		socket[Sn_TX_RD1] = write_ptr;
		socket[Sn_TX_FSR0] = tx_buffer_size >> 8;
		socket[Sn_TX_FSR1] = tx_buffer_size;
		socket[Sn_IR] |= Sn_IR_SEND_OK;
		update_ethernet_irq();
		return;
	}

	// for UDP, break up large packets...


	// for TCP, break up large packets, don't set SEND_OK until all are acked.

}

void w5100_device::socket_send_mac(int sock)
{
}

void w5100_device::socket_send_keep(int sn)
{
}

void w5100_device::socket_connect(int sn)
{
}

void w5100_device::socket_disconnect(int sn)
{
}

void w5100_device::socket_recv(int sn)
{
	/* this just bumps pointers */

	#if 0

	uint8_t *base = m_socket_registers + (sock << 8);
	uint16_t read_ptr = (base[Sn_RX_RD0 + offset] << 8) |  base[Sn_RX_RD1 + offset];
	uint16_t write_ptr = (base[Sn_RX_WR0 + offset] << 8) |  base[Sn_RX_WR1 + offset];

	uint16_t mask = m_receive_size[sock] - 1;

	read_ptr &= mask;
	write_ptr &= mask;

	int size = read_ptr - write_ptr;
	if (size < 0) size += m_receive_size[sock];

	// update RSR and trigger a RECV interrupt if data still pending.
	base[Sn_RX_RSR0] = size >> 8;
	base[Sn_RX_RSR1] = size & 0xff;
	if (size)
	{
		base[Sn_IR] |= IR_RECV;
		update_ethernet_irq();
	}
	#endif
}




void w5100_device::recv_cb(u8 *buffer, int length)
{
	/* If this is an ARP, it may need to be handled and/or passed to MACRAW socket */
	/* If this is a ping, it may need to be handled or passed to an IPRAW or MACRAW socket */

	bool is_multicast = false;
	bool is_broadcast = false;
	bool is_unicast = false;
	bool is_tcp = false;
	bool is_udp = false;
	bool is_icmp = false;
	int ethertype = -1; // 0x0806 = arp, 0x0800 = ip */
	int ip_proto = -1;
	int ip_port = 0;
	bool macraw = m_memory[Sn_MR + Sn_BASE] == Sn_MR_MACRAW;

	//int sn = -1;

	if (length < 14) return;

	ethertype = (buffer[12] << 8) | buffer[13];

	if (buffer[0] & 0x01)
	{
		if (!memcmp(buffer, ETH_BROADCAST, 6)) is_broadcast = true;
		else is_multicast = true;
	}
	if (!memcmp(buffer, &m_memory[SHAR0], 6)) is_unicast = true;

	// promiscuous packets only allowed for macraw socket.
	if (!is_unicast && !is_broadcast && !is_multicast)
	{
		int mr = m_memory[Sn_MR + Sn_BASE];
		if (macraw && !(mr & Sn_MR_MF))
		{
			receive(0, buffer, length);
		}
		return;
	}

	if (ethertype == ETHERTYPE_ARP)
	{
		if (length < 16) return;
		int arp_op = (buffer[0x14] << 8) | buffer[0x15];

		if (arp_op == ARP_REPLY && is_unicast)
		{
			handle_arp_response(buffer, length);
		}
		if (arp_op == ARP_REQUEST && (is_broadcast || is_unicast) && !macraw)
		{
			handle_arp_request(buffer, length);
		}
		if (!macraw) return;
	}
	if (ethertype == ETHERTYPE_IP)
	{
		if (length < 34) return;
		ip_proto = buffer[14 + 9];
		if (ip_proto == IP_ICMP) is_icmp = true;
		if (ip_proto == IP_TCP) is_tcp = true;
		if (ip_proto == IP_UDP) is_udp = true;
		if (is_udp || is_tcp) ip_port = (buffer[34 + 2] << 8) | buffer[34 + 3];

	}

	// find a matching socket
	for (int sn = 0; sn < 4; ++sn)
	{
		const uint8_t *socket = m_memory + Sn_BASE + sn * Sn_SIZE;
		int sr = socket[Sn_SR];
		//int mr = socket[Sn_MR];
		int port = (socket[Sn_PORT0] << 8) | socket[Sn_PORT1];

		if (sr == Sn_SR_IPRAW && ip_proto == socket[Sn_PROTO])
		{
			receive(sn, buffer, length);
			return;
		}

		if (sr == Sn_SR_UDP && is_udp && ip_port == port)
		{
			receive(sn, buffer, length);
			return;
		}

		// todo -- TCP...
	}



	/* if socket 0 is an open macraw socket, it can accept anything. */
	if (macraw)
	{
		receive(0, buffer, length);
		return;
	}

	// a ICMP destination unreachable message from a UDP will
	// generate an unreachable interrupt and set unreachable ip/port registers.

	if (is_icmp && is_unicast && buffer[0x22] == ICMP_DESTINATION_UNREACHABLE && buffer[51] == IP_UDP)
	{
		/* check for an open udp port matching the source/destination port? */
		memcpy(m_memory + UIPR0, buffer + 58, 4); 
		memcpy(m_memory + UPORT0, buffer + 64, 2);
		m_memory[IR] | IR_UNREACH;
		update_ethernet_irq();
		return;
	}


	// respond to ICMP ping
	if (is_icmp && is_unicast && (m_memory[MR] & MR_PB) == 0 && buffer[0x22] == ICMP_ECHO_REQUEST)
	{
		handle_ping_response(buffer, length);
		return;
	}

}





/* returns true if Sn_DHAR is valid, false (and ARP request sent) otherwise */
bool w5100_device::find_mac(int sn)
{
	/* find the mac address for the destination ip and store as DHAR*/
	/* if not local, use the gateway mac address */

	/* UDP/IPRAW - if broadcast ip, (255.255.255.255) or (local | ~subnet) */
	/* use broadcast ethernet */

	uint8_t *socket = m_memory + Sn_BASE + sn * Sn_SIZE;

	uint32_t gateway = read32(&m_memory[GAR0]);
	uint32_t subnet = read32(&m_memory[SUBR0]);
	uint32_t dest = read32(&socket[Sn_DIPR0]);
	uint32_t ip = read32(&m_memory[SIPR0]);


	if (m_sockets[sn].arp_ok && m_sockets[sn].arp_ip_address == dest)
		return true;

	if (dest == 0xffffffff || dest == (ip | ~subnet))
	{
		/* broadcast ip address */
		memcpy(&socket[Sn_DHAR0], ETH_BROADCAST, 6);
		m_sockets[sn].arp_ok = true;
		m_sockets[sn].arp_ip_address = dest;
		return true;
	}

	// multi-cast logic here?

	if ((dest & subnet) == (ip & subnet))
	{
		dest = gateway;
		if (m_sockets[sn].arp_ok && m_sockets[sn].arp_ip_address == dest)
			return true;
	}

	m_sockets[sn].arp_ip_address = dest;
	m_sockets[sn].arp_ok = false;
	m_sockets[sn].retry = 0;

	// TODO -- timer...

	send_arp_request(dest);
	return false;
}

void w5100_device::handle_arp_response(uint8_t *buffer, int length)
{
	/* if this is an ARP response, possibly update all the Sn_SR_ARP */
	/* keep a separate mac for the gateway instead of re-checking every time? */
	/* remove retry/timeout timers */
	/* queue up the send/synsent */
	/* if another device claims our MAC address, need to generate a CONFLICT interrupt */
	/* TODO - comparing IP is not correct when it's a gateway lookup */
	for (int sn = 0; sn < 4; ++sn)
	{
		uint8_t *socket = m_memory + Sn_BASE + sn * Sn_SIZE;
		uint8_t &sr = socket[Sn_SR];
		int proto = socket[Sn_MR] & 0x0f;
		if (sr == Sn_SR_ARP)
		{
			if (!memcmp(socket + Sn_XX_ARP_IP_ADDRESS, buffer + 0x26 ,4))
			{
				memcpy(socket + Sn_DHAR0, buffer + 0x20, 6);
				socket[Sn_XX_ARP_OK] = 1;
				switch(proto)
				{
					case Sn_MR_IPRAW:
						sr = Sn_SR_IPRAW;
						socket_send(sn);
						break;
					case Sn_MR_UDP:
						sr = Sn_SR_UDP;
						socket_send(sn);
						break;
					case Sn_MR_TCP:
						sr = Sn_SR_SYNSENT;
						// TODO
						break;
				}
			}
		}
	}
}

void w5100_device::handle_arp_request(uint8_t *buffer, int length)
{
	/* reply to (broadcast) request for our mac address */

	if (length < 42 || memcmp(buffer + 39, &m_memory[SIPR0], 4)) return;

	static const int MESSAGE_SIZE = 42;
	uint8_t message[MESSAGE_SIZE];

	// memset(message, 0, sizeof(message));

	memcpy(message, buffer + 6, 6);
	memcpy(message + 6, &m_memory[SHAR0], 6);
	message[12] = ETHERTYPE_ARP >> 8;
	message[13] = ETHERTYPE_ARP;

	message[14] = 1 >> 8; // hardware type = ethernet
	message[15] = 1;
	message[16] = ETHERTYPE_IP >> 8;
	message[17] = ETHERTYPE_IP;
	message[18] = 6; // hardware size
	message[19] = 4; // protocol size
	message[20] = ARP_REPLY >> 8;
	message[21] = ARP_REPLY;
	memcpy(message + 22, &m_memory[SHAR0], 6); //sender mac
	memcpy(message + 28, &m_memory[SIPR0], 4); // sender ip
	memcpy(message + 32, buffer + 22, 10); // dest mac + ip.

	send(message, MESSAGE_SIZE);
}


void w5100_device::send_arp_request(uint32_t ip)
{
	static const int MESSAGE_SIZE = 42;
	uint8_t message[MESSAGE_SIZE];

	// memset(message, 0, sizeof(message));

	memcpy(message, ETH_BROADCAST, 6);
	memcpy(message + 6, &m_memory[SHAR0], 6);
	message[12] = ETHERTYPE_ARP >> 8;
	message[13] = ETHERTYPE_ARP;

	message[14] = 1 >> 8; // hardware type = ethernet
	message[15] = 1;
	message[16] = ETHERTYPE_IP >> 8;
	message[17] = ETHERTYPE_IP;
	message[18] = 6; // hardware size
	message[19] = 4; // protocol size
	message[20] = ARP_REQUEST >> 8;
	message[21] = ARP_REQUEST;
	memcpy(message + 22, &m_memory[SHAR0], 6); //sender mac
	memcpy(message + 28, &m_memory[SIPR0], 4); // sender ip
	memset(message + 32, 0, 6); // target mac
	// memcpy(message + 38, ip, 4); // target ip
	message[38] = ip >> 24;
	message[39] = ip >> 16;
	message[40] = ip >> 8;
	message[41] = ip >> 0;

	send(message, MESSAGE_SIZE);

}


/* length includes the 34-byte ethernet/ip header */
void w5100_device::build_ipraw_header(int sn, uint8_t *buffer, int length)
{
	uint8_t *socket = m_memory + Sn_BASE + Sn_SIZE * sn;

	//ethernet header
	memcpy(buffer + 0, &socket[Sn_DHAR0], 6);
	memcpy(buffer + 6, &m_memory[SHAR0], 6);
	buffer[12] = ETHERTYPE_IP >> 8;
	buffer[13] = ETHERTYPE_IP;

	length -= 14;

	// ip header
	buffer[14] = 0x45; // IPv4, length = 5*4
	buffer[15] = socket[Sn_TOS];
	buffer[16] = length >> 8; // total length
	buffer[17] = length;
	buffer[18] = 0; // identification
	buffer[19] = 0;
	buffer[20] = 0x40; // flags - don't fragment
	buffer[21] = 0x00;
	buffer[22] = socket[Sn_TTL];
	buffer[23] = socket[Sn_PROTO];
	buffer[24] = 0; // checksum...
	buffer[25] = 0;
	memcpy(buffer + 26, m_memory + SIPR0, 4); // source ip
	memcpy(buffer + 30, socket + Sn_DIPR0, 4); // destination ip

	uint16_t crc = util::internet_checksum_creator::simple(buffer + 14, 20);
	buffer[24] = crc >> 8;
	buffer[25] = crc;
}

/* length includes the 42-byte ethernet/ip/udp header */
void w5100_device::build_udp_header(int sn, uint8_t *buffer, int length)
{
	uint8_t *socket = m_memory + Sn_BASE + Sn_SIZE * sn;

	//ethernet header
	memcpy(buffer + 0, &socket[Sn_DHAR0], 6);
	memcpy(buffer + 6, &m_memory[SHAR0], 6);
	buffer[12] = ETHERTYPE_IP >> 8;
	buffer[13] = ETHERTYPE_IP;

	length -= 14;

	// ip header
	buffer[14] = 0x45; // IPv4, length = 5*4
	buffer[15] = socket[Sn_TOS];
	buffer[16] = length >> 8; // total length
	buffer[17] = length;
	buffer[18] = 0; // identification
	buffer[19] = 0;
	buffer[20] = 0x40; // flags - don't fragment
	buffer[21] = 0x00;
	buffer[22] = socket[Sn_TTL];
	buffer[23] = IP_UDP;
	buffer[24] = 0; // checksum...
	buffer[25] = 0;
	memcpy(buffer + 26, m_memory + SIPR0, 4); // source ip
	memcpy(buffer + 30, socket + Sn_DIPR0, 4); // destination ip


	length -= 20;

	// udp header
	buffer[34] = socket[Sn_PORT0]; // source port
	buffer[35] = socket[Sn_PORT1];
	buffer[36] = socket[Sn_DPORT0]; // dest port
	buffer[37] = socket[Sn_DPORT0];
	buffer[38] = length >> 8; // length
	buffer[39] = length;
	buffer[40] = 0; // checksum - optional
	buffer[41] = 0;


	uint16_t crc = util::internet_checksum_creator::simple(buffer + 14, 20);
	buffer[24] = crc >> 8;
	buffer[25] = crc;
}

void w5100_device::handle_ping_response(uint8_t *buffer, int length)
{
	uint16_t crc;

	/* swap the src/dest ip, src/dest mac, change the response type,
	   update the crc and resend.
	 */

	for (int i = 0; i < 6; ++i)
		std::swap(buffer[i], buffer[6 + i]);
	for (int i = 0; i < 4; ++i)
		std::swap(buffer[0x1a + i], buffer[0x1e + i]);

	buffer[0x22] = ICMP_ECHO_REPLY;

	// ip crc
	buffer[0x18] = 0;
	buffer[0x19] = 0;
	crc = util::internet_checksum_creator::simple(buffer + 14, 20);
	buffer[0x18] = crc >> 8;
	buffer[0x19] = crc;

	// icmp crc
	buffer[0x24] = 0;
	buffer[0x25] = 0;
	crc = util::internet_checksum_creator::simple(buffer + 34, length - 34);
	buffer[0x24] = crc >> 8;
	buffer[0x25] = crc;

	send(buffer, length);
}


/* store UDP, IPRAW, and MACRAW data into the receive buffer */
/* TCP not handled here!!! */
void w5100_device::receive(int sn, const uint8_t *buffer, int length)
{
	uint8_t *socket = m_memory + Sn_BASE + sn * Sn_SIZE;

	int offset = 0;
	int header = 0;

	int rx_buffer_offset = m_sockets[sn].rx_buffer_offset;
	int rx_buffer_size = m_sockets[sn].rx_buffer_size;

	uint16_t write_ptr = (socket[Sn_RX_WR0] << 8) | socket[Sn_RX_WR1];
	uint16_t read_ptr = (socket[Sn_RX_RD0] << 8) | socket[Sn_RX_RD1];
	int sr = socket[Sn_SR];
	int proto = socket[Sn_MR] & 0x0f;

	int mask = rx_buffer_size - 1;
	write_ptr &= mask;
	read_ptr &= mask;

	int used = write_ptr - read_ptr;
	if (used < 0) used += rx_buffer_size;

	switch(proto)
	{
		case Sn_MR_MACRAW:
			offset = 0x00;
			header = 2;
			break;
		case Sn_MR_IPRAW:
			offset = 0x22;
			header = 6;
			break;
		case Sn_MR_UDP:
			offset = 0x30;
			header = 8;
			break;
		case Sn_MR_TCP:
			offset = 34 + (buffer[46] >> 2) & 0xfc; // data offset = tcp header size, in 32-bit words.
			header = 0;
	}

	// drop the packet if no room.
	if (length + header - offset <= 0) return;
	if (used + length + header - offset > rx_buffer_size) return;


	if (sr == Sn_SR_MACRAW)
	{
		// 2-byte size header
		m_memory[rx_buffer_offset + (write_ptr++ & mask)] = length >> 8;
		m_memory[rx_buffer_offset + (write_ptr++ & mask)] = length;
	}

	if (sr == Sn_SR_UDP)
	{
		// 8-byte dest-ip, dest-port, size header

		m_memory[rx_buffer_offset + (write_ptr++ & mask)] = buffer[0x1e];
		m_memory[rx_buffer_offset + (write_ptr++ & mask)] = buffer[0x1f];
		m_memory[rx_buffer_offset + (write_ptr++ & mask)] = buffer[0x20];
		m_memory[rx_buffer_offset + (write_ptr++ & mask)] = buffer[0x21];

		m_memory[rx_buffer_offset + (write_ptr++ & mask)] = buffer[0x24];
		m_memory[rx_buffer_offset + (write_ptr++ & mask)] = buffer[0x25];

		m_memory[rx_buffer_offset + (write_ptr++ & mask)] = length >> 8;
		m_memory[rx_buffer_offset + (write_ptr++ & mask)] = length;
	}

	if (sr == Sn_SR_IPRAW)
	{
		// 6-byte dest-ip, size header

		m_memory[rx_buffer_offset + (write_ptr++ & mask)] = buffer[0x1e];
		m_memory[rx_buffer_offset + (write_ptr++ & mask)] = buffer[0x1f];
		m_memory[rx_buffer_offset + (write_ptr++ & mask)] = buffer[0x20];
		m_memory[rx_buffer_offset + (write_ptr++ & mask)] = buffer[0x21];

		m_memory[rx_buffer_offset + (write_ptr++ & mask)] = length >> 8;
		m_memory[rx_buffer_offset + (write_ptr++ & mask)] = length;
	}

	length -= offset;
	write_ptr &= mask;

	copy_out(m_memory + rx_buffer_offset, buffer + offset, length, write_ptr, rx_buffer_size);

	/* update pointers and available */
	length += header;
	write_ptr = (write_ptr + length) & mask;
	used += length;

	socket[Sn_RX_WR0] = write_ptr >> 8;
	socket[Sn_RX_WR1] = write_ptr;

	socket[Sn_RX_RSR0] = used >> 8;
	socket[Sn_RX_RSR1] = used;

	socket[Sn_IR] |= Sn_IR_RECV;
	update_ethernet_irq();
}


#if 0

/*
 * since there are potentially 4 open sockets and the send/recieve callbacks
 * only returns the size, we need a flag for the active send / receive socket.
 * Additionally, if socket 2 sends while socket 1 is in progress, we need to
 * delay socket 2 until later
 */

void w5100_device::send_complete_cb(int result)
{
	/* result is length of the packet sent */
	if (m_tx_socket < 0) return;
	int sn = m_tx_socket;

	uint8_t *socket = m_memory + Sn_BASE + (Sn_SIZE * sn);
	unsigned proto = socket[Sn_MR] & 0x0f;
	int header = proto_header_size(proto);

	uint16_t read_ptr = (socket[Sn_TX_RD0] << 8) |  socket[Sn_TX_RD1];
	uint16_t write_ptr = (socket[Sn_TX_WR0] << 8) |  socket[Sn_TX_WR1];
	uint16_t fsr = (socket[Sn_TX_FSR0] << 8) | socket[Sn_TX_FSR1];

	int tx_buffer_offset;
	int tx_buffer_size;
	get_tmsr(sn, tx_buffer_offset, tx_buffer_size);

	read_ptr &= (tx_buffer_size - 1);
	write_ptr &= (tx_buffer_size - 1);

	// if this is a macraw, ipraw, or UDP, set the send-ok bit.
	result -= header;
	// macraw has a 2-byte header with the size.
	// udp strips the ethernet, ip, and udp header and adds dest ip[4] + data size[2]
	// ipraw strips the ethernet, ip and adds dest ip[4] + data size[2]
	switch(proto)
	{
		case Sn_MR_MACRAW:
		case Sn_MR_IPRAW:
		case Sn_MR_UDP:
			fsr += result;
			read_ptr = (read_ptr + result) & (tx_buffer_size - 1);
			socket[Sn_TX_FSR0] = fsr >> 8;
			socket[Sn_TX_FSR1] = fsr;
			socket[Sn_TX_RD0] = read_ptr >> 8;
			socket[Sn_TX_RD1] = read_ptr;

			socket[Sn_IR] |= Sn_IR_SEND_OK;
			update_ethernet_irq();
			break;
	}

	// if this is TCP, need to wait for ACK before flagging SEND_OK and bumping ptrs.
	// (sigh... which might have already happened in the recv callback...)
	// if this is UDP or TCP, may be more data queued up.

	m_tx_socket = -1;
	// check queue for pending send transactions.
}


void w5100_device::recv_complete_cb(int result)
{}
void w5100_device::send_complete_cb(int result)
{}
#endif


DEFINE_DEVICE_TYPE(W5100, w5100_device, "w5100", "WIZNet W5100 Ethernet Controller")
