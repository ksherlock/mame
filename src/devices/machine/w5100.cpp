// license:BSD-3-Clause
// copyright-holders: Kelvin Sherlock


/*
  WIZnet W5100

  Used in: Uthernet II (Apple II), Spectranet (ZX Spectrum)

  Based on:
  W5100, W5100S, W5200, W5500 datasheets
  WIZnet ioLibrary Driver (https://github.com/Wiznet/ioLibrary_Driver)
  https://docs.wiznet.io/Product/iEthernet/W5100/
  Uthernet II User's and Programmer's Manual


  0x0000-0x012f - common registers
  0x0030-0x03ff - reserved
  0x0400-0x7fff - socket registers
  0x0800-0x3fff - reserved
  0x4000-0x5fff - tx memory
  0x6000-0x7fff - rx memory

 */

/*
TODO:
- full W5100s support
*/

#include "emu.h"
#include "machine/w5100.h"
#include "util/internet_checksum.h"

#define LOG_GENERAL (1U << 0)
#define LOG_COMMAND (1U << 1)
#define LOG_FILTER  (1U << 2)
#define LOG_PACKETS (1U << 3)
#define LOG_ARP     (1U << 4)
#define LOG_WRITE   (1U << 5)
#define LOG_TCP     (1U << 6)

#define VERBOSE (LOG_GENERAL|LOG_COMMAND|LOG_FILTER|LOG_PACKETS|LOG_ARP|LOG_TCP)
#include "logmacro.h"



using connect_type = tcpip_device::connect_type;
using disconnect_type = tcpip_device::disconnect_type;
using tcp_error = tcpip_device::tcp_error;
using tcp_event = tcpip_device::tcp_event;
using tcp_state = tcpip_device::tcp_state;

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
	INTPTMR0, // w5100s only
	INTPTMR1, // w5100s only
	IR,
	IMR = 0x16,
	RTR0,
	RTR1,
	RCR,
	RMSR,
	TMSR,
	PATR0, // w5100 only
	PATR1, // w5100 only
	/* 0x1c-0x1f reserved */
	IR2 = 0x20, // w5100s only
	IMR2, // w5100s only
	/* 0x22-0x27 reserved */
	PTIMER = 0x28,
	PMAGIC,
	UIPR0,
	UIPR1,
	UIPR2,
	UIPR3,
	UPORT0,
	UPORT1,


	/* 0x30+ are w5100s only */ 
	MR2 = 0x30,
	/* 0x31 reserved */
	PHAR0 = 0x32,
	PHAR1,
	PHAR2,
	PHAR3,
	PHAR4,
	PHAR5,
	PSIDR0,
	PSIDR1,
	PMRUR0,
	PMRUR1,
	PHYSR0,
	PHYSR1,
	PHYAR,
	PHYRAR,
	PHYDIR0,
	PHYDIR1,
	PHYDOR0,
	PHYDOR1,
	PHYACR,
	PHYDIVR,
	PHYCR0,
	PHYCR1,
	/* 0x48-0x4b reserved */
	SLCR = 0x4c,
	SLRTR0,
	SLRTR1,
	SLRCR,
	SLIPR0,
	SLIPR1,
	SLIPR2,
	SLIPR3,
	SLPHAR0,
	SLPHAR1,
	SLPHAR2,
	SLPHAR3,
	SLPHAR4,
	SLPHAR5,
	PINGSEQR0,
	PINGSEQR1,
	PINGIDR0,
	PINGIDR1,
	SLIMR,
	SLIR,
	/* 0x60-0x6a reserved */
	CLKCKR = 0x70,
	NETLCKR,
	PHYLCKR,
	/* 0x73-0x7f reserved */
	VERR = 0x80,
	/* 0x81 reserved */
	TCNTR0 = 0x82,
	TCNTR1,
	/* 0x84-0x87 reserved */
	TCNTCLR = 0x88
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
	Sn_RX_BUF_SIZE = 0x1e, // w5100s only
	Sn_TX_BUF_SIZE, // w5100s only
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

	/* everything below w5100s only */
	Sn_IMR,
	Sn_FRAGR0,
	Sn_FRAGR1,
	Sn_MR2,
	Sn_KPALVTR,
	/* 0x31 reserved */
	Sn_RTR0 = 0x32,
	Sn_RTR1,
	Sn_RCR,
	/* 0x35-0xff reserved */

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
	IR_PPPTERM = 0x20,
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

/* w5100s below */

/* Interrupt Register 2 */
enum {
	IR2_WOL = 0x01
};

/* Mode Register 2 bits */
enum {
	MR2_CLKSEL = 0x80,
	MR2_IEN = 0x40,
	MR2_NOTCPRST = 0x20,
	MR2_UDPURB = 0x10,
	MR2_WOL = 0x08,
	MR2_FARP = 0x02,
};

/* PHY Status Register 0 */
enum {
	PHYSR0_CABOFF = 0x80,
	PHYSR0_AUTO = 0x40,
	PHYSR0_SPD = 0x20,
	PHYSR0_DPX = 0x10,
	PHYSR0_FDPX = 0x04,
	PHYSR0_FSPD = 0x02,
	PHYSR0_LINK = 0x01,
};

/* PHY Status Register 1 */
enum {
	PHYSR1_ACT = 0x80,
	PHYSR1_RXP = 0x04,
	PHYSR1_LPI = 0x02,
	PHYSR1_CAL = 0x01,
};

/* PHY Register Address Register */
enum {
	PHYRAR_A4 = 0x10,
	PHYRAR_A3 = 0x08,
	PHYRAR_A2 = 0x04,
	PHYRAR_A1 = 0x02,
	PHYRAR_A0 = 0x01,
};

/* PHY Access Control Register */
enum {
	PHYACR_WRITE = 0x01,
	PHYACR_READ = 0x03,
};

/* PHY Control Register 0 */
enum {
	PHYCR0_MODE2 = 0x04,
	PHYCR0_MODE1 = 0x02,
	PHYCR0_MODE0 = 0x01,
};

/* PHY Control Register 1 */
enum {
	PHYCR1_WOL = 0x80,
	PHYCR1_PWDN = 0x20,
	PHYCR1_RST = 0x01,
};

/* Socket-less Command Register */
enum {
	SLCR_ARP = 0x02,
	SLCR_PING = 0x01,
};

/* Socket-less Interrupt Register */
enum {
	SLIR_TIMEOUT = 0x04,
	SLIR_ARP = 0x02,
	SLIR_PING = 0x01,
};

/* Socket Mode Register 2 */
enum {
	Sn_MR2_MBBLK = 0x40,
	Sn_MR2_MMBLK = 0x20,
	Sn_MR2_IPV6BLK = 0x10,
	Sn_MR2_BRDB = 0x02, // TCP - force PSH
	Sn_MR2_UNIB = 0x01,
};

enum {
	Sn_BASE = 0x0400,
	Sn_SIZE = 0x0100,
	IO_TXBUF = 0x4000,
	IO_RXBUF = 0x6000
};



/* IP, ARP, etc offsets and constants */

enum {
	o_ETHERNET_DEST = 0,
	o_ETHERNET_SRC = 6,
	o_ETHERNET_TYPE = 12,

	ETHERNET_TYPE_IP = 0x0800,
	ETHERNET_TYPE_ARP = 0x0806,
	ETHERNET_TYPE_IPV6 = 0x86dd,
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

	IP_ICMP = 1,
	IP_IGMP = 2,
	IP_TCP = 6,
	IP_UDP = 17,
};

enum {
	o_UDP_SRC_PORT = 0,
	o_UDP_DEST_PORT = 2,
	o_UDP_LENGTH = 4,
	o_UDP_CHECKSUM = 6,
};



enum {
	o_ICMP_TYPE = 0,
	o_ICMP_CODE = 1,
	o_ICMP_CHECKSUM = 2,

	ICMP_ECHO_REPLY = 0x00, // rfc 792
	ICMP_DESTINATION_UNREACHABLE = 0x03,
	ICMP_ECHO_REQUEST = 0x8,
};

enum {
	o_IGMP_TYPE = 0,
	o_IGMP_MAX_RESP_TIME = 1,
	o_IGMP_CHECKSUM = 2,
	o_IGMP_GROUP_ADDRESS = 4,

	IGMP_TYPE_MEMBERSHIP_QUERY = 0x11,
	IGMP_TYPE_MEMBERSHIP_REPORT_V1 = 0x12,
	IGMP_TYPE_MEMBERSHIP_REPORT_V2 = 0x16,
	IGMP_TYPE_LEAVE_GROUP = 0x17
};


enum {
	// offsets.  assumes 4-byte PLEN, 6-byte HLEN
	o_ARP_HTYPE = 0,
	o_ARP_PTYPE = 2,
	o_ARP_HLEN = 4,
	o_ARP_PLEN = 5,
	o_ARP_OPCODE = 6,
	o_ARP_SHA = 8,
	o_ARP_SPA = 14,
	o_ARP_THA = 18,
	o_ARP_TPA = 24,


	ARP_OPCODE_REQUEST = 0x01, // rfc 826
	ARP_OPCODE_REPLY = 0x02,
	ARP_HTYPE_ETHERNET = 1,

};



/*
 Timeouts:
 RTR- retry timeout register - is in units of 100us. Default value (2000) is 200ms
 Sn_MR_ND - No Delayed Ack (TCP only) - 
 Sn_IR_TIMEOUT 0

*/


static uint8_t ETHERNET_BROADCAST[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };



static uint32_t read32(const uint8_t *p)
{
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static uint16_t read16(const uint8_t *p)
{
	return (p[0] << 8) | p[1];
}


static void write32(uint8_t *p, uint32_t x)
{
	p[0] = x >> 24;
	p[1] = x >> 16;
	p[2] = x >> 8;
	p[3] = x >> 0;
}

static void write16(uint8_t *p, uint16_t x)
{
	p[0] = x >> 8;
	p[1] = x >> 0;
}


static bool verify_arp(const uint8_t *buffer, int length)
{
	const uint8_t *arp = buffer + 14;
	if (length < 14 + 28) return false;
	if (read16(buffer + o_ETHERNET_TYPE) != ETHERNET_TYPE_ARP) return false;
	if (read16(arp + o_ARP_HTYPE) != ARP_HTYPE_ETHERNET) return false;
	if (arp[o_ARP_HLEN] != 6 || arp[o_ARP_PLEN] != 4) return false;
	return true;
}

/* returns ip header length if ok */
static int verify_ip(const uint8_t *buffer, int length)
{
	if (length < 14 + 20) return false;
	if (read16(buffer + o_ETHERNET_TYPE) != ETHERNET_TYPE_IP) return false;

	const uint8_t *ip = buffer + 14;
	length -= 14;

	int ihl = (ip[o_IP_IHL] & 0x0f) << 2;
	if (ihl < 20) return false;

	if (util::internet_checksum_creator::simple(ip, ihl)) return false;

	int proto = ip[o_IP_PROTOCOL];

	const uint8_t *data = ip + ihl;
	int ip_length = read16(ip + o_IP_LENGTH);

	if (length < ip_length) return false;

	length = ip_length - ihl;	

	if (proto == IP_ICMP || proto == IP_IGMP)
	{
		if (!util::internet_checksum_creator::simple(data, length)) return false;
	}
	else if (proto == IP_UDP)
	{
		if (length < read16(data + o_UDP_LENGTH)) return false;

		uint16_t crc = read16(data + o_UDP_CHECKSUM);
		if (crc)
		{
			uint8_t pheader[12];
			memcpy(pheader + 0, ip + o_IP_SRC_ADDRESS, 4);
			memcpy(pheader + 4, ip + o_IP_DEST_ADDRESS, 4);
			write16(pheader + 8, IP_UDP);
			write16(pheader + 10, length);

			util::internet_checksum_creator cr;
			cr.append(pheader, sizeof(pheader));
			cr.append(data, length);
			uint16_t xcrc = cr.finish();
			if (xcrc == 0) xcrc = 0xffff;
			if (crc != xcrc) return false;
		}
	}

	return ihl;
}


w5100_device::w5100_device(const machine_config &mconfig, device_type type, const char *tag, device_t *owner, uint32_t clock, dev_type device_type)
	: device_t(mconfig, type, tag, owner, clock)
	, device_network_interface(mconfig, *this, 10)
	, m_device_type(device_type)
	, m_tcp(*this, "tcp%u", 0U)
	, m_irq_handler(*this)
{
}

void w5100_device::device_start()
{
	save_pointer(&m_memory[0], "General Registers", 0x400);
	save_pointer(&m_memory[0x400], "Socket 0 Registers", 0x100);
	save_pointer(&m_memory[0x500], "Socket 1 Registers", 0x100);
	save_pointer(&m_memory[0x600], "Socket 2 Registers", 0x100);
	save_pointer(&m_memory[0x700], "Socket 3 Registers", 0x100);
	save_pointer(&m_memory[0x4000], "TX Memory", 0x2000);
	save_pointer(&m_memory[0x6000], "RX Memory", 0x2000);
	// save_item(NAME(m_memory));

	save_item(NAME(m_idm));
	save_item(NAME(m_identification));
	save_item(NAME(m_irq_state));

	m_irq_handler.resolve_safe();

	// 1 extra timer for w5100s socket-less commmand.
	for (int sn = 0; sn < 5; ++ sn)
		m_timers[sn] = timer_alloc(sn);
}


void w5100_device::device_add_mconfig(machine_config &config)
{
	for (int sn = 0; sn < 4; ++sn)
	{
		auto &tcp = m_tcp[sn];
		TCPIP(config, tcp, clock());
		tcp->set_param(sn);

		tcp->set_on_state_change([this,sn](tcp_state new_state, tcp_state old_state){
			tcp_state_change(sn, new_state, old_state);
		});
		tcp->set_send_function([this](void *buffer, int length){
			send(static_cast<u8 *>(buffer), length);
		});
		tcp->set_event_function([this, sn](tcp_event event){
			switch(event)
			{
				case tcp_event::receive_ready:
					tcp_receive(sn);
					break;
				case tcp_event::send_complete:
					tcp_send_complete(sn);
					break;
				default: break;
			}
		});
	}
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

		if (m_device_type == dev_type::W5100S)
		{
			socket[Sn_IMR] = 0xff;
			socket[Sn_FRAGR0] = 0x40;
		}

		m_timers[sn]->reset();
		// m_sockets[sn].reset();
		m_tcp[sn]->force_close();
	}


	if (m_device_type == dev_type::W5100S)
	{
		m_memory[MR] = 0x03;
		m_memory[MR2] = 0x40;
		m_memory[PMRUR0] = 0xff;
		m_memory[PMRUR1] = 0xff;
		m_memory[PHYSR1] = 0x81;
		m_memory[PHYDIVR] = 0x01;
		m_memory[PHYCR1] = 0x41;
		m_memory[SLRTR0] = 0x07;
		m_memory[SLRTR1] = 0xd0;
		m_memory[VERR] = 0x51;
		m_memory[PHYSR0] = PHYSR0_LINK;
	}


	m_identification = 0;

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
 * id is the socket #. 5 indicates a socketless connection.
 * TODO - param indicates ARP vs TCP, etc
 * W5100s also has socketless connection for ARP/PING
 */

#if 0
struct retransmit_item {
	int sn; // 0-3 = arp for sn #, 4 = socket-less arp, 5 = socket-less ping
	int time;
	int proto;

};
#endif

void w5100_device::device_timer(emu_timer &timer, device_timer_id id, int param)
{

	int sn = id;


	uint32_t ip = m_sockets[sn].arp_ip_address;

	if (sn == 4)
	{
		// w5100s socket-less arp/ping
		int rcr = m_memory[SLRCR];

		if (++m_sockets[sn].retry > rcr)
		{
			LOGMASKED(LOG_ARP, "ARP timeout for %d.%d.%d.%d\n",
				(ip >> 24) & 0xff, (ip >> 16) & 0xff,
				(ip >> 8) & 0xff, (ip >> 0) & 0xff
			);

			timer.reset();
			m_memory[SLIR] |= SLIR_TIMEOUT;
			update_ethernet_irq();
			return;
		}
		switch (m_sockets[sn].command)
		{
			case SLCR_ARP:
				send_arp_request(ip);
				break;
			case SLCR_PING:
				if (m_sockets[sn].arp_ok)
					send_icmp_request();
				else
					send_arp_request(ip);
				break;
		}
	}
	else
	{

		int rcr = m_memory[RCR];
		uint8_t *socket = m_memory + Sn_BASE + sn * Sn_SIZE;

		if (++m_sockets[sn].retry > rcr)
		{
			int proto = socket[Sn_MR] & 0x0f;
			uint8_t &sr = socket[Sn_SR];
			switch(proto)
			{
				case Sn_MR_UDP:
					sr = Sn_SR_UDP;
					break;
				case Sn_MR_IPRAW:
					sr = Sn_SR_IPRAW;
					break;
				case Sn_MR_TCP:
					sr = Sn_SR_CLOSED;
					break;
			}

			LOGMASKED(LOG_ARP, "ARP timeout for %d.%d.%d.%d\n",
				(ip >> 24) & 0xff, (ip >> 16) & 0xff,
				(ip >> 8) & 0xff, (ip >> 0) & 0xff
			);

			timer.reset();
			socket[Sn_IR] |= Sn_IR_TIMEOUT;
			update_ethernet_irq();
		}
		else
		{
			send_arp_request(ip);
		}
	}
}


void w5100_device::update_ethernet_irq()
{
	int ir = m_memory[IR] & 0b11100000;
	int ir2 = 0;
	int slir = 0;

	for (int sn = 0, bit = IR_S0_INT; sn < 4; ++sn, bit <<= 1)
	{
		const uint8_t *socket = m_memory + Sn_BASE + sn * Sn_SIZE;
		int sir = socket[Sn_IR] & 0b00011111;

		if (m_device_type == dev_type::W5100S)
			sir &= socket[Sn_IMR];

		if (sir) ir |= bit;
	}

	m_memory[IR] = ir;
	ir &= m_memory[IMR];

	if (m_device_type == dev_type::W5100S)
	{
		ir2 = m_memory[IR2] & 0b00000001;
		ir2 &= m_memory[IMR2];
		slir = m_memory[SLIR] & 0b00000111;
		slir &= m_memory[SLIMR];

		if ((m_memory[MR2] & MR2_IEN) == 0)
		{
			ir = 0;
			ir2 = 0;
			slir = 0;
		}
	}

	uint32_t new_state = (slir << 16) | (ir2 << 8) | (ir);


	if (new_state ^ m_irq_state)
	{
		m_irq_state = new_state;
		m_irq_handler(m_irq_state ? ASSERT_LINE : CLEAR_LINE);		
	}

}

/*
 * Direct bus interface: 15-bit address, 8-bit data bus
 * Indirect bus interface: 2-bit address, 8-bit data bus
 * W5100s is always indirect w/ auto-increment
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
					if (m_device_type == dev_type::W5100)
					{
						if (m_idm == 0x6000) m_idm = 0x4000;
						if (m_idm == 0x8000) m_idm = 0x6000;
						if (m_idm == 0x0000) m_idm = 0xe000;
					}
				}
				break;
		}
	}

	offset &= 0x7fff;
	if (offset < 0x4000)
	{
		offset &= 0x7ff;
		if (offset < 0x400)
			offset &= 0xff;
	}

	LOGMASKED(LOG_WRITE, "write(0x%04x, 0x%02x)\n", offset, data);

	int sn = -1;
	if (offset >= Sn_BASE && offset < Sn_BASE + Sn_SIZE * 4)
		sn = (offset - Sn_BASE) / Sn_SIZE;

	switch(offset)
	{
		case MR:
			if (m_device_type == dev_type::W5100S)
				data |= MR_AI | MR_IND;
			break;

		case IR:
			/* interrupt bits 5-7 cleared by writing 1 to them; bits 0-3 cleared via Sn_IR register */
			m_memory[IR] &= ~data;
			update_ethernet_irq();
			return;

		case IR2:
			if (m_device_type == dev_type::W5100S)
			{
				m_memory[IR2] &= ~data;
				update_ethernet_irq();
			}
			return;

		case SLIR:
			if (m_device_type == dev_type::W5100S)
			{
				m_memory[SLIR] &= ~data;
				update_ethernet_irq();
			}
			return;

		case SLCR:
			if (m_device_type == dev_type::W5100S)
			{
				sl_command(data);
				return;
			}
			break;

		case Sn_IR + Sn_BASE + (Sn_SIZE * 0):
		case Sn_IR + Sn_BASE + (Sn_SIZE * 1):
		case Sn_IR + Sn_BASE + (Sn_SIZE * 2):
		case Sn_IR + Sn_BASE + (Sn_SIZE * 3):
			m_memory[offset] &= ~data;
			update_ethernet_irq();
			return;

		case Sn_CR + Sn_BASE + (Sn_SIZE * 0):
		case Sn_CR + Sn_BASE + (Sn_SIZE * 1):
		case Sn_CR + Sn_BASE + (Sn_SIZE * 2):
		case Sn_CR + Sn_BASE + (Sn_SIZE * 3):
			socket_command(sn, data);
			return;

	}

	m_memory[offset] = data;

	switch(offset)
	{
		case MR:
			if (data & MR_RST)
			{
				LOGMASKED(LOG_COMMAND, "software reset\n");
				device_reset();
			}
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

		case MR2:
		case IMR2:
		case SLIMR:
		case Sn_IMR + Sn_BASE + (Sn_SIZE * 0):
		case Sn_IMR + Sn_BASE + (Sn_SIZE * 1):
		case Sn_IMR + Sn_BASE + (Sn_SIZE * 2):
		case Sn_IMR + Sn_BASE + (Sn_SIZE * 3):
			if (m_device_type == dev_type::W5100S)
				update_ethernet_irq();
			break;

		case Sn_KPALVTR + Sn_BASE + (Sn_SIZE * 0):
		case Sn_KPALVTR + Sn_BASE + (Sn_SIZE * 1):
		case Sn_KPALVTR + Sn_BASE + (Sn_SIZE * 2):
		case Sn_KPALVTR + Sn_BASE + (Sn_SIZE * 3):
			if (m_device_type == dev_type::W5100S)
				m_tcp[sn]->set_keep_alive_timer(5 * data);
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
					if (m_device_type == dev_type::W5100)
					{
						if (m_idm == 0x6000) m_idm = 0x4000;
						if (m_idm == 0x8000) m_idm = 0x6000;
						if (m_idm == 0x0000) m_idm = 0xe000;
					}
				}
				break;
		}
	}

	offset &= 0x7fff;

	if (offset < 0x4000)
	{
		offset &= 0x7ff;
		if (offset < 0x400)
			offset &= 0xff;
	}

	return m_memory[offset];
}


/*
 * w5100s defines Sn_TXBUF_SIZE / Sn_RXBUF_SIZE as alternates for TMSR / RMSR
 * 0, 1, 2, 4, or 8 for 0k, 1k, 2k, 4k, 8k, respectively.
 * w5200+ eliminates TMSR/RMSR 
 */

void w5100_device::update_rmsr(uint8_t value)
{

	int offset = IO_RXBUF;
	uint8_t *socket = m_memory + Sn_BASE;
	for (int sn = 0; sn < 4; ++sn, value >>= 2, socket += Sn_SIZE)
	{
		int size = 1024 << (value & 0x3);
		m_sockets[sn].rx_buffer_size = size;
		m_sockets[sn].rx_buffer_offset = offset;
		offset += size;
		// flag as invalid if offset invalid?
		socket[Sn_RX_BUF_SIZE] = size >> 10;
	}

}

void w5100_device::update_tmsr(uint8_t value)
{

	int offset = IO_TXBUF;
	uint8_t *socket = m_memory + Sn_BASE;
	for (int sn = 0; sn < 4; ++sn, value >>= 2, socket += Sn_SIZE)
	{
		int size = 1024 << (value & 0x3);
		m_sockets[sn].tx_buffer_size = size;
		m_sockets[sn].tx_buffer_offset = offset;
		offset += size;

		socket[Sn_TX_BUF_SIZE] = size >> 10;
		// flag as invalid if offset invalid?


		/* also update FSR ... */
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
		LOG("socket %d free size = %d\n", sn, fsr);
	}

}

void w5100_device::sl_command(int command)
{

	uint8_t &cr = m_memory[SLRCR];

	if (cr) return;

	switch(command)
	{
		case SLCR_ARP:
		case SLCR_PING:
			LOGMASKED(LOG_COMMAND, "Socket-Less %s\n", command == SLCR_ARP ? "ARP" : "PING");
			cr = command;
			m_sockets[4].command = command;
			m_sockets[4].arp_ok = false;
			find_mac(4, read32(m_memory + SLIPR0), read16(m_memory + SLRTR0));
			break;

		default:
			LOGMASKED(LOG_COMMAND, "Socket-Less Unknown command (0x%02x)\n", command);
			break;

	}

}


void w5100_device::socket_command(int sn, int command)
{
	if (sn < 0 || sn > 3) return;

	uint8_t *socket = m_memory + Sn_BASE + (Sn_SIZE * sn);
	//unsigned proto = socket[Sn_MR] & 0x0f;
	uint8_t &sr = socket[Sn_SR];

	switch(command)
	{
		case Sn_CR_OPEN:
			// a2stream re-opens CR_MACRAW as TCP w/o closing.
			LOGMASKED(LOG_COMMAND, "Socket: %d: open\n", sn);
			// if (sr == Sn_SR_CLOSED)
			socket_open(sn);
			break;

		case Sn_CR_LISTEN:
			LOGMASKED(LOG_COMMAND, "Socket: %d: listen\n", sn);
			if (sr == Sn_SR_INIT)
				sr = Sn_SR_LISTEN;
			break;

		case Sn_CR_CONNECT:
			LOGMASKED(LOG_COMMAND, "Socket: %d: connect\n", sn);
			if (sr == Sn_SR_INIT)
				socket_connect(sn);
			break;

		case Sn_CR_DISCON:
			LOGMASKED(LOG_COMMAND, "Socket: %d: disconnect\n", sn);
			socket_disconnect(sn);
			break;

		case Sn_CR_CLOSE:
			LOGMASKED(LOG_COMMAND, "Socket: %d: close\n", sn);
			socket_close(sn);
			break;

		case Sn_CR_RECV:
			LOGMASKED(LOG_COMMAND, "Socket: %d: receive\n", sn);
			if (sr == Sn_SR_UDP || sr == Sn_SR_IPRAW || sr == Sn_SR_MACRAW || sr == Sn_SR_ESTABLISHED || sr == Sn_SR_CLOSE_WAIT || sr == Sn_SR_FIN_WAIT)
				socket_recv(sn);
			break;

		case Sn_CR_SEND:
			LOGMASKED(LOG_COMMAND, "Socket: %d: send\n", sn);
			if (sr == Sn_SR_UDP || sr == Sn_SR_IPRAW || sr == Sn_SR_MACRAW || sr == Sn_SR_ESTABLISHED || sr == Sn_SR_CLOSE_WAIT)
				socket_send(sn);
			break;

		case Sn_CR_SEND_MAC:
			LOGMASKED(LOG_COMMAND, "Socket: %d: send mac\n", sn);
			if (sr == Sn_SR_UDP || sr == Sn_SR_IPRAW)
				socket_send_mac(sn);
			break;

		case Sn_CR_SEND_KEEP:
			LOGMASKED(LOG_COMMAND, "Socket: %d: send keep alive\n", sn);
			if (sr == Sn_SR_ESTABLISHED || sr == Sn_SR_CLOSE_WAIT)
				socket_send_keep(sn);
			break;
		default:
			LOGMASKED(LOG_COMMAND, "Socket: %d: unknown command (0x%02x)\n", sn, command);

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
			return 14 + 20 + 32;
			break;
		default:
			return 0;
	}	
}


static const char *proto_name(int proto)
{
	switch(proto)
	{
		case Sn_MR_CLOSED: return "CLOSED";
		case Sn_MR_UDP: return "UDP";
		case Sn_MR_TCP: return "TCP";
		case Sn_MR_IPRAW: return "IPRAW";
		case Sn_MR_MACRAW: return "MACRAW";
		case Sn_MR_PPPoE: return "PPPoE";
		default: return "???";
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

	socket[Sn_TX_FSR0] = m_sockets[sn].tx_buffer_size >> 8;
	socket[Sn_TX_FSR1] = m_sockets[sn].tx_buffer_size;

	socket[Sn_RX_RSR0] = 0;
	socket[Sn_RX_RSR1] = 0;

	m_timers[sn]->reset();
	m_sockets[sn].reset();
	m_tcp[sn]->abort();

	if (VERBOSE & LOG_COMMAND)
	{
		char extra[32];
		switch(proto)
		{
			#if 0
			case Sn_MR_TCP:
				sprintf(extra, 32, "ip = %d.%d.%d.%d:%d",
					socket[Sn_DIPR0],
					socket[Sn_DIPR1],
					socket[Sn_DIPR2],
					socket[Sn_DIPR3],
					read16(socket + Sn_DPORT0])
				);
				break;
			case Sn_MR_UDP:
				snprintf(extra, 32, "port = %d",
					(socket[Sn_DPORT0] << 8) | socket[Sn_DPORT1]
				);
				break;
			#endif
			case Sn_MR_IPRAW:
				snprintf(extra, 32, "proto = %d", socket[Sn_PROTO]);
				break;
			default:
				extra[0] = 0;
		}
		LOGMASKED(LOG_COMMAND, "Opening socket %d as %s tx = %04x/%04x, rx=%04x/%04x %s\n",
			sn, proto_name(proto),
			m_sockets[sn].tx_buffer_offset,
			m_sockets[sn].tx_buffer_size,
			m_sockets[sn].rx_buffer_offset,
			m_sockets[sn].rx_buffer_size,
			extra

		);
	}

	switch (proto)
	{
		case Sn_MR_TCP:
			sr = Sn_SR_INIT;
			break;
		case Sn_MR_UDP:
			sr = Sn_SR_UDP;
			if (socket[Sn_MR] & Sn_MR_MULT)
				send_igmp(sn, true);
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
			#if 0
			if (sn == 0)
				sr = Sn_SR_PPPOE;
			#endif
			break;

		case Sn_MR_CLOSED: /* closed */
			break;
	}
}

void w5100_device::socket_close(int sn)
{
	uint8_t *socket = m_memory + Sn_BASE + (Sn_SIZE * sn);

	int mr = socket[Sn_MR];

	if ((mr & (Sn_MR_MULT | 0x0f)) == (Sn_MR_UDP | Sn_MR_MULT))
		send_igmp(sn, false);

	socket[Sn_SR] = Sn_SR_CLOSED;
	m_timers[sn]->reset();
	/* also reset interrupts? */
	// socket[Sn_IR] = 0;
	m_tcp[sn]->force_close();


}


static void copy_in(uint8_t *dest, const uint8_t *src, int length, int src_offset, int bank_size)
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

static void copy_out(uint8_t *dest, const uint8_t *src, int length, int dest_offset, int bank_size)
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
	uint8_t *socket = m_memory + Sn_BASE + (Sn_SIZE * sn);
	unsigned proto = socket[Sn_MR] & 0x0f;


	// if this is a UDP or IPRAW socket, possibly send an ARP
	// and perform send once resolved...

	if (proto == Sn_MR_UDP || proto == Sn_MR_IPRAW)
	{
		if (!find_mac(sn)) return;
		socket_send_mac(sn);
	}

	if (proto == Sn_MR_MACRAW)
	{
		socket_send_mac(sn);
		return;
	}

	int tx_buffer_offset = m_sockets[sn].tx_buffer_offset;
	int tx_buffer_size = m_sockets[sn].tx_buffer_size;

	uint16_t read_ptr = (socket[Sn_TX_RD0] << 8) |  socket[Sn_TX_RD1];
	uint16_t write_ptr = (socket[Sn_TX_WR0] << 8) |  socket[Sn_TX_WR1];

	read_ptr &= (tx_buffer_size - 1);
	write_ptr &= (tx_buffer_size - 1);


	int size = write_ptr - read_ptr;
	if (size < 0) size += tx_buffer_size;

	// LOG("send rd=%04x wr=%04x size=%d\n", read_ptr, write_ptr, size);

	if (proto == Sn_MR_TCP)
	{
		bool push = m_device_type == dev_type::W5100S ? socket[Sn_MR2] & Sn_MR2_BRDB : false; 
		if (read_ptr + size > tx_buffer_size)
		{
			int len = tx_buffer_size - read_ptr;
			m_tcp[sn]->send(m_memory + tx_buffer_offset + read_ptr, len, false, false);
			read_ptr = 0;
			size -= len;
		}
		m_tcp[sn]->send(m_memory + tx_buffer_offset + read_ptr, size, push, false);
		return;
	}


}

void w5100_device::socket_send_mac(int sn)
{

	static const int BUFFER_SIZE = 1514;
	uint8_t buffer[BUFFER_SIZE];

	uint8_t *socket = m_memory + Sn_BASE + (Sn_SIZE * sn);
	// uint8_t sr = socket[Sn_SR];
	unsigned proto = socket[Sn_MR] & 0x0f;


	int tx_buffer_offset = m_sockets[sn].tx_buffer_offset;
	int tx_buffer_size = m_sockets[sn].tx_buffer_size;

	uint16_t read_ptr = (socket[Sn_TX_RD0] << 8) |  socket[Sn_TX_RD1];
	uint16_t write_ptr = (socket[Sn_TX_WR0] << 8) |  socket[Sn_TX_WR1];

	read_ptr &= (tx_buffer_size - 1);
	write_ptr &= (tx_buffer_size - 1);


	int size = write_ptr - read_ptr;
	if (size < 0) size += tx_buffer_size;

	int header_size = proto_header_size(proto);
	int mss = 1514;

	if (proto == Sn_MR_UDP)
	{
		mss = std::min(static_cast<int>(read16(socket + Sn_MSSR0)), 1472);
		if (mss) mss += header_size;
		else mss = BUFFER_SIZE;
	}


	if (proto == Sn_MR_UDP)
	{
		// UDP needs to be split into multiple chunks 
		while (size)
		{
			int msize = std::min(size, mss - header_size);
			memset(buffer, 0, header_size);
			copy_in(buffer + header_size, m_memory + tx_buffer_offset, msize, read_ptr, tx_buffer_size);
			build_udp_header(sn, buffer, msize);
			dump_bytes(buffer, msize);
			send(buffer, msize);
			msize -= header_size;
			size -= msize;
		}

	}
	else if (proto == Sn_MR_MACRAW || proto == Sn_MR_IPRAW)
	{
		// MACRAW/IPRAW truncate if too big

		int msize = std::min(size, mss - header_size);

		memset(buffer, 0, header_size);
		copy_in(buffer + header_size, m_memory + tx_buffer_offset, msize, read_ptr, tx_buffer_size);

		msize += header_size;

		if (proto == Sn_MR_IPRAW)
			build_ipraw_header(sn, buffer, msize);

		dump_bytes(buffer, msize);
		send(buffer, msize);
	}

	socket[Sn_TX_RD0] = write_ptr >> 8;
	socket[Sn_TX_RD1] = write_ptr;
	socket[Sn_TX_FSR0] = tx_buffer_size >> 8;
	socket[Sn_TX_FSR1] = tx_buffer_size;
	socket[Sn_IR] |= Sn_IR_SEND_OK;
	update_ethernet_irq();
}

void w5100_device::socket_send_keep(int sn)
{
	// manual keepalive.  ignored on w5100s if Sn_KPALVTR > 0

	if (m_device_type == dev_type::W5100S && m_memory[Sn_BASE + sn * Sn_SIZE + Sn_KPALVTR])
		return;

	m_tcp[sn]->send_keep_alive();
}

void w5100_device::socket_connect(int sn)
{

	if (!find_mac(sn))
		return;

	uint8_t *socket = m_memory + Sn_BASE + sn * Sn_SIZE;

	auto tcp = m_tcp[sn];

	tcp->set_local_ip(read32(m_memory + SIPR0));
	tcp->set_local_port(read16(socket + Sn_PORT0));
	tcp->set_local_mac(m_memory + SHAR0);
	tcp->set_remote_mac(socket + Sn_DHAR0);
	// todo -- buffer size,
	tcp->open(read32(socket + Sn_DIPR0), read16(socket + Sn_DPORT0));
}


void w5100_device::socket_disconnect(int sn)
{
	m_tcp[sn]->close();
}

void w5100_device::socket_recv(int sn)
{
	uint8_t *socket = m_memory + Sn_BASE + sn * Sn_SIZE;
	uint16_t read_ptr = read16(socket + Sn_RX_RD0);
	uint16_t write_ptr = read16(socket + Sn_RX_WR0);

	uint16_t mask = m_sockets[sn].rx_buffer_size - 1;

	read_ptr &= mask;
	write_ptr &= mask;

	int size = write_ptr - read_ptr;
	if (size < 0) size += m_sockets[sn].rx_buffer_size;

	LOG("receive sn=%d read_ptr = 0x%04x write_ptr = 0x%04x size = %d rsr = %d\n",
		sn, read_ptr, write_ptr, size, read16(socket + Sn_RX_RSR0));

	// update RSR and trigger a RECV interrupt if data still pending.
	socket[Sn_RX_RSR0] = size >> 8;
	socket[Sn_RX_RSR1] = size & 0xff;
	if ((socket[Sn_MR] & 0x0f) == Sn_MR_TCP)
	{
		tcp_receive(sn);
	}
	else if (size)
	{
		socket[Sn_IR] |= Sn_IR_RECV;
		update_ethernet_irq();
	}
}


/*

5100s page 77:

MACRAW Mode SOCKET 0 does not receive any Data Packet for other SOCKET
but it receives ARP Request and PING Request (If IPRAW Mode SOCKET does
not support ICMP). Even though MACRAW Mode SOCKET 0 receives ARP and
PING Request, W5100S transmits automatically ARP and PING Reply.

*/

void w5100_device::recv_cb(u8 *buffer, int length)
{
	/* If this is an ARP, it may need to be handled and/or passed to MACRAW socket */
	/* If this is a ping, it may need to be handled or passed to an IPRAW or MACRAW socket */

	bool is_multicast = false;
	bool is_broadcast = false;
	bool is_unicast = false;
	bool is_tcp = false;
	bool is_udp = false;
	int ethertype = -1; // 0x0806 = arp, 0x0800 = ip */
	int ip_proto = -1;
	int udp_port = 0;
	int ip_header_length = 0;
	bool macraw = m_memory[Sn_SR + Sn_BASE] == Sn_SR_MACRAW;

	int mr2 = m_device_type == dev_type::W5100S ? m_memory[MR2] : 0;


	LOG("recv_cb %d\n", length);
	length -= 4; // strip the FCS
	dump_bytes(buffer, length);

	if (length < 14) return;

	ethertype = read16(buffer + o_ETHERNET_TYPE);


	if (buffer[0] & 0x01)
	{
		if (!memcmp(buffer + o_ETHERNET_DEST, ETHERNET_BROADCAST, 6)) is_broadcast = true;
		else is_multicast = true;
	}
	if (!memcmp(buffer, &m_memory[SHAR0], 6)) is_unicast = true;

	// promiscuous packets only allowed for macraw socket.
	if (!is_unicast && !is_broadcast && !is_multicast)
	{
		int mr = m_memory[Sn_MR + Sn_BASE];
		if (macraw && !(mr & Sn_MR_MF))
		{
			if (m_device_type == dev_type::W5100S)
			{
				int mr2 = m_memory[Sn_MR2 + Sn_BASE];
				if ((mr2 & Sn_MR2_MBBLK) && is_broadcast) return;
				if ((mr2 & Sn_MR2_MMBLK) && is_multicast) return;
				if ((mr2 & Sn_MR2_IPV6BLK) && ethertype == ETHERNET_TYPE_IPV6) return;
			}
			receive(0, buffer, length);
		}
		return;
	}

	if (ethertype == ETHERNET_TYPE_ARP && verify_arp(buffer, length))
	{
		if (length < 16) return;
		uint8_t *arp = buffer + 14;
		int arp_op = read16(arp + o_ARP_OPCODE);

		if (arp_op == ARP_OPCODE_REPLY)
		{
			handle_arp_reply(buffer, length);
		}
		if (arp_op == ARP_OPCODE_REQUEST)
		{
			handle_arp_request(buffer, length);
		}
		if (!macraw) return;
	}

	bool igmp_query = false;
	uint32_t igmp_query_ip = -1;
	if (ethertype == ETHERNET_TYPE_IP)
	{
		ip_header_length = verify_ip(buffer, length);
		if (ip_header_length)
		{
			uint8_t *ip = buffer + 14;
			uint8_t *data = ip + ip_header_length;
			ip_proto = ip[o_IP_PROTOCOL];
			if (ip_proto == IP_TCP) is_tcp = true;
			if (ip_proto == IP_UDP)
			{
				is_udp = true;
				udp_port = read16(data + o_UDP_DEST_PORT);
			}
			if (ip_proto == IP_IGMP)
			{
				uint8_t *igmp = buffer + 14 + ip_header_length;
				if (igmp[o_IGMP_TYPE] == IGMP_TYPE_MEMBERSHIP_QUERY)
				{
					igmp_query = true;
					igmp_query_ip = read32(igmp + o_IGMP_GROUP_ADDRESS);
				}
			}
		}

	}

	bool handle_udp = false;
	bool handle_tcp = false;
	// find a matching socket
	for (int sn = 0; sn < 4; ++sn)
	{
		const uint8_t *socket = m_memory + Sn_BASE + sn * Sn_SIZE;
		int sr = socket[Sn_SR];
		int proto = socket[Sn_MR] & 0x0f;

		int port = read16(socket + Sn_PORT0);

		if (sr == Sn_SR_INIT || sr == Sn_SR_CLOSED) continue;

		if (proto == Sn_MR_IPRAW && ip_proto == socket[Sn_PROTO])
		{
			receive(sn, buffer, length);
			return;
		}

		if (proto == Sn_MR_UDP)
		{
			handle_udp = true;
			if (is_udp && udp_port == port)
			{
				int mr = socket[Sn_MR];

				if (is_multicast && !(mr & Sn_MR_MULT)) return;

				if (m_device_type == dev_type::W5100S)
				{
					int mr2 = socket[Sn_MR2];
					if (is_broadcast && (mr2 & Sn_MR2_BRDB)) return;
					if (is_unicast && (mr & Sn_MR_MULT) && (mr2 & Sn_MR2_UNIB)) return;
				}
				receive(sn, buffer, length);
				return;
			}

			if (igmp_query && (socket[Sn_MR] & Sn_MR_MULT))
			{
				// n.b. - should use random delay between 0 and igmp max response time.
				uint32_t ip = read32(socket + Sn_DIPR0);
				if (igmp_query_ip == 0 || igmp_query_ip == ip)
					send_igmp(sn, true);
			}
		}

		if (proto == Sn_MR_TCP)
		{
			handle_tcp = true;
			if (m_tcp[sn]->check_segment(buffer, length))
			{
				m_tcp[sn]->segment(buffer, length);
				return;
			}
		}
	}


	if (ip_proto == IP_ICMP)
	{
		uint8_t *icmp = buffer + 14 + ip_header_length;
		int icmp_type = icmp[o_ICMP_TYPE];

		if (icmp_type == ICMP_DESTINATION_UNREACHABLE && icmp[o_ICMP_CODE] == 3 && icmp[8 + o_IP_PROTOCOL] == IP_UDP && is_unicast)
		{
			// an ICMP destination unreachable message from a UDP will
			// generate an unreachable interrupt and set unreachable ip/port registers.

			if (length < 14 + ip_header_length + 8 + 20) return;
			int ihl = (icmp[8 + o_IP_IHL] & 0x0f) << 2;
			if (length < 14 + ip_header_length + ihl + 8) return;

			memcpy(m_memory + UIPR0, icmp + 8 + o_IP_DEST_ADDRESS, 4); 
			memcpy(m_memory + UPORT0, icmp + 8 + ihl + o_UDP_DEST_PORT, 2);
			m_memory[IR] | IR_UNREACH;
			update_ethernet_irq();
		}

		// respond to ICMP ping
		if (icmp_type == ICMP_ECHO_REQUEST && (m_memory[MR] & MR_PB) == 0)
		{
			handle_icmp_request(buffer, length);
		}
		// socket-less ICMP ping response
		if (icmp_type == ICMP_ECHO_REPLY && m_device_type == dev_type::W5100S && m_sockets[4].command == SLCR_PING)
		{
			uint16_t id = read16(m_memory + PINGIDR0);
			uint16_t seq = read16(m_memory + PINGSEQR0);
			if (id == read16(icmp + 4) && seq == read16(icmp + 6))
			{
				m_memory[SLCR] = 0;
				m_sockets[4].command = 0;
				m_timers[4]->reset();
				m_memory[SLIR] |= SLIR_PING;
				update_ethernet_irq();
			}
		}
	}

	if (is_udp && (handle_udp || !macraw))
	{
		if (is_unicast && !(mr2 & MR2_UDPURB))
		{
			send_icmp_unreachable(buffer, length);
		}
		return;
	}
	if (is_tcp && (handle_tcp || !macraw))
	{
		if (is_unicast && !(mr2 & MR2_NOTCPRST))
		{
			auto seg = tcpip_device::build_reset_segment(buffer, length);
			if (!seg.empty())
				send(seg.data(), seg.size());
		}
		return;
	}

	/* if socket 0 is an open macraw socket, it can accept anything. */
	if (macraw)
	{
		if (m_device_type == dev_type::W5100S)
		{
			int mr2 = m_memory[Sn_MR2 + Sn_BASE];
			if ((mr2 & Sn_MR2_MBBLK) && is_broadcast) return;
			if ((mr2 & Sn_MR2_MMBLK) && is_multicast) return;
			if ((mr2 & Sn_MR2_IPV6BLK) && ethertype == ETHERNET_TYPE_IPV6) return;
		}
		receive(0, buffer, length);
	}

}

/* store UDP, IPRAW, and MACRAW data into the receive buffer */
/* TCP not handled here!!! */
void w5100_device::receive(int sn, const uint8_t *buffer, int length)
{

	LOG("Packet received for socket %d\n", sn);

	uint8_t *socket = m_memory + Sn_BASE + sn * Sn_SIZE;

	static const int MAX_HEADER_SIZE = 8;
	uint8_t header[MAX_HEADER_SIZE];

	int offset = 0;
	int header_size = 0;
	int ihl = 0;

	int rx_buffer_offset = m_sockets[sn].rx_buffer_offset;
	int rx_buffer_size = m_sockets[sn].rx_buffer_size;

	uint16_t write_ptr = (socket[Sn_RX_WR0] << 8) | socket[Sn_RX_WR1];
	// uint16_t read_ptr = (socket[Sn_RX_RD0] << 8) | socket[Sn_RX_RD1];
	// int sr = socket[Sn_SR];
	int proto = socket[Sn_MR] & 0x0f;

	int mask = rx_buffer_size - 1;
	write_ptr &= mask;
	// read_ptr &= mask;

	int used = read16(socket + Sn_RX_RSR0);
	// int used = write_ptr - read_ptr;
	// if (used < 0) used += rx_buffer_size;

	switch(proto)
	{
		case Sn_MR_MACRAW:
			offset = 0x00;

			// header: {uint16_t size }
			// MACRAW length *includes* the 2-byte header.
			header[0] = (length + 2) >> 8;
			header[1] = (length + 2);

			header_size = 2;
			break;

		case Sn_MR_IPRAW:
			ihl = (buffer[14 + o_IP_IHL] & 0x0f) << 2;
			offset = ihl + 14;
			length = read16(buffer + 14 + o_IP_LENGTH) - ihl;

			// header: { uint32_t foreign_ip, uint16_t size }
			memcpy(header + 0, buffer + 14 + o_IP_SRC_ADDRESS, 4);

			header[4] = length >> 8;
			header[5] = length;

			header_size = 6;
			break;

		case Sn_MR_UDP:

			ihl = (buffer[14 + o_IP_IHL] & 0x0f) << 2;
			offset = ihl + 14 + 8;
			length = read16(buffer + 14 + ihl + o_UDP_LENGTH) - 8;

			// header { uint32_t foreign_ip, uint16_t foreign_port, uint16_t size }
			memcpy(header + 0, buffer + 14 + o_IP_SRC_ADDRESS, 4);
			memcpy(header + 4, buffer + 14 + ihl + o_UDP_SRC_PORT, 2);

			header[6] = length >> 8;
			header[7] = length;

			header_size = 8;
			break;
	}

	// drop the packet if no room.
	if (length + header_size <= 0) return;
	if (used + length + header_size > rx_buffer_size)
	{
		LOG("No room for data on socket %d\n", sn);
		return;
	}

	if (header_size)
	{
		copy_out(m_memory + rx_buffer_offset, header, header_size, write_ptr, rx_buffer_size);
		write_ptr += header_size;
		write_ptr &= mask;
		used += header_size;
	}

	copy_out(m_memory + rx_buffer_offset, buffer + offset, length, write_ptr, rx_buffer_size);

	/* update pointers and available */
	write_ptr += length;
	write_ptr &= mask;
	used += length;

	LOG("used = %d\n", used);

	socket[Sn_RX_WR0] = write_ptr >> 8;
	socket[Sn_RX_WR1] = write_ptr;

	socket[Sn_RX_RSR0] = used >> 8;
	socket[Sn_RX_RSR1] = used;

	socket[Sn_IR] |= Sn_IR_RECV;
	update_ethernet_irq();
}





/* returns true if Sn_DHAR is valid, false (and ARP request sent) otherwise */
bool w5100_device::find_mac(int sn)
{
	/* find the mac address for the destination ip and store as DHAR*/
	/* if not local, use the gateway mac address */

	/* UDP/IPRAW - if broadcast ip, (255.255.255.255) or (local | ~subnet) */
	/* use broadcast ethernet address */

	uint8_t *socket = m_memory + Sn_BASE + sn * Sn_SIZE;

	uint32_t subnet = read32(m_memory + SUBR0);
	uint32_t ip = read32(m_memory + SIPR0);

	uint32_t dest = read32(socket + Sn_DIPR0);
	int rtr = read16(m_memory + RTR0);
	int mr = socket[Sn_MR];
	bool udp = (mr & 0x0f) == Sn_MR_UDP;

	if (udp && (mr & Sn_MR_MULT)) return true; // multi-cast

	// socket-less ARP doesn't handle broadcast addresses properly so handle them here.
	if (dest == 0xffffffff || dest == (ip | ~subnet))
	{
		/* broadcast ip address */
		memcpy(socket + Sn_DHAR0, ETHERNET_BROADCAST, 6);
		m_sockets[sn].arp_ip_address = dest;
		m_sockets[sn].arp_ok = true;
		return true;
	}

	if (m_device_type == dev_type::W5100S)
	{
		int sn_rtr = read16(socket + Sn_RTR0);

		if (sn_rtr) rtr = sn_rtr;

		if (udp && (m_memory[MR2] & MR2_FARP))
			m_sockets[sn].arp_ok = false;
	}

	if (m_device_type == dev_type::W5100S && udp && (m_memory[MR2] & MR2_FARP))
		m_sockets[sn].arp_ok = false;


	bool rv = find_mac(sn, dest, rtr);

	if (!rv)
		socket[Sn_SR] = Sn_SR_ARP;

	return rv;

}

// used for socket + socket-less commands.
bool w5100_device::find_mac(int sn, uint32_t dest, int rtr)
{
	uint32_t gateway = read32(m_memory + GAR0);
	uint32_t subnet = read32(m_memory + SUBR0);
	uint32_t ip = read32(m_memory + SIPR0);

	if (m_sockets[sn].arp_ok && m_sockets[sn].arp_ip_address == dest)
		return true;

	if ((dest & subnet) != (ip & subnet) && (dest & ~subnet) != 0)
	{
		dest = gateway;
		if (m_sockets[sn].arp_ok && m_sockets[sn].arp_ip_address == dest)
			return true;
	}

	m_sockets[sn].arp_ip_address = dest;
	m_sockets[sn].arp_ok = false;
	m_sockets[sn].retry = 0;

	/* Retry Timeout Register, 1 = 100us */
	if (!rtr) rtr = 0x07d0;
	attotime tm = attotime::from_usec(rtr * 100);
	m_timers[sn]->adjust(tm, 0, tm);

	send_arp_request(dest);
	return false;
}

void w5100_device::handle_arp_reply(const uint8_t *buffer, int length)
{
	/* if this is an ARP response, possibly update all the Sn_SR_ARP */
	/* keep a separate mac for the gateway instead of re-checking every time? */
	/* remove retry/timeout timers */
	/* queue up the send/synsent */
	/* if another device claims our MAC address, need to generate a CONFLICT interrupt */
	/* TODO - comparing IP is not correct when it's a gateway lookup */

	const uint8_t *arp = buffer + 14;

	uint32_t ip = read32(arp + o_ARP_SPA);

	LOGMASKED(LOG_ARP, "Received ARP reply for %d.%d.%d.%d\n",
		(ip >> 24) & 0xff, (ip >> 16) & 0xff,
		(ip >> 8) & 0xff, (ip >> 0) & 0xff
	);

	if (m_device_type == dev_type::W5100S)
	{
		// socket-less ARP/PING
		if (m_sockets[4].arp_ip_address == ip)
		{
			memcpy(m_memory + SLPHAR0, arp + o_ARP_SHA, 6);

			m_sockets[4].arp_ok = true;
			if (m_sockets[4].command == SLCR_ARP)
			{
				m_memory[SLCR] = 0;
				m_timers[4]->reset();
				m_memory[SLIR] |= SLIR_ARP;
				update_ethernet_irq();
			}
			else
			{
				m_sockets[4].retry = 0;
				send_icmp_request();	
			}
		}
	}

	for (int sn = 0; sn < 4; ++sn)
	{
		uint8_t *socket = m_memory + Sn_BASE + sn * Sn_SIZE;
		uint8_t &sr = socket[Sn_SR];
		int proto = socket[Sn_MR] & 0x0f;
		if (sr == Sn_SR_ARP)
		{
			if (m_sockets[sn].arp_ip_address == ip)
			{
				memcpy(socket + Sn_DHAR0, arp + o_ARP_SHA, 6);
				m_sockets[sn].arp_ok = true;
				m_timers[sn]->reset();
				switch(proto)
				{
					case Sn_MR_IPRAW:
						sr = Sn_SR_IPRAW;
						socket_send_mac(sn);
						break;
					case Sn_MR_UDP:
						sr = Sn_SR_UDP;
						socket_send_mac(sn);
						break;
					case Sn_MR_TCP:
						sr = Sn_SR_INIT;
						socket_connect(sn);
						break;
				}
			}
		}
	}
}

void w5100_device::handle_arp_request(const uint8_t *buffer, int length)
{
	/* reply to (broadcast) request for our mac address */

	const uint8_t *arp = buffer + 14;

	if (memcmp(arp + o_ARP_TPA, m_memory + SIPR0, 4)) return;

	static const int MESSAGE_SIZE = 42;
	uint8_t message[MESSAGE_SIZE];

	// memset(message, 0, sizeof(message));

	memcpy(message, arp + o_ARP_SHA, 6);
	memcpy(message + 6, m_memory + SHAR0, 6);
	message[12] = ETHERNET_TYPE_ARP >> 8;
	message[13] = ETHERNET_TYPE_ARP;

	message[14] = ARP_HTYPE_ETHERNET >> 8; // hardware type = ethernet
	message[15] = ARP_HTYPE_ETHERNET;
	message[16] = ETHERNET_TYPE_IP >> 8;
	message[17] = ETHERNET_TYPE_IP;
	message[18] = 6; // hardware size
	message[19] = 4; // protocol size
	message[20] = ARP_OPCODE_REPLY >> 8;
	message[21] = ARP_OPCODE_REPLY;
	memcpy(message + 22, m_memory + SHAR0, 6); //sender mac
	memcpy(message + 28, m_memory + SIPR0, 4); // sender ip
	memcpy(message + 32, arp + o_ARP_SHA, 10); // dest mac + ip.

	LOGMASKED(LOG_ARP, "Replying to ARP request\n");
	send(message, MESSAGE_SIZE);
}


void w5100_device::send_arp_request(uint32_t ip)
{
	static const int MESSAGE_SIZE = 42;
	uint8_t message[MESSAGE_SIZE];

	// memset(message, 0, sizeof(message));

	memcpy(message, ETHERNET_BROADCAST, 6);
	memcpy(message + 6, &m_memory[SHAR0], 6);
	message[12] = ETHERNET_TYPE_ARP >> 8;
	message[13] = ETHERNET_TYPE_ARP;

	message[14] = ARP_HTYPE_ETHERNET >> 8; // hardware type = ethernet
	message[15] = ARP_HTYPE_ETHERNET;
	message[16] = ETHERNET_TYPE_IP >> 8;
	message[17] = ETHERNET_TYPE_IP;
	message[18] = 6; // hardware size
	message[19] = 4; // protocol size
	message[20] = ARP_OPCODE_REQUEST >> 8;
	message[21] = ARP_OPCODE_REQUEST;
	memcpy(message + 22, &m_memory[SHAR0], 6); //sender mac
	memcpy(message + 28, &m_memory[SIPR0], 4); // sender ip
	memset(message + 32, 0, 6); // target mac
	// memcpy(message + 38, ip, 4); // target ip
	message[38] = ip >> 24;
	message[39] = ip >> 16;
	message[40] = ip >> 8;
	message[41] = ip >> 0;

	LOGMASKED(LOG_ARP, "Sending ARP request for %d.%d.%d.%d\n",
		(ip >> 24) & 0xff, (ip >> 16) & 0xff,
		(ip >> 8) & 0xff, (ip >> 0) & 0xff
	);
	send(message, MESSAGE_SIZE);
}


/* build and send the IGMP join/leave message for multicast UDP socked */
// RFC 1112, Host Extensions for IP Multicasting
// RFC 2236, Internet Group Management Protocol, Version 2
// RFC 2113, IP Router Alert Option
void w5100_device::send_igmp(int sn, bool connect)
{
	static const int MESSAGE_SIZE = 46;
	uint8_t message[MESSAGE_SIZE];

	uint16_t crc;

	const uint8_t *socket = m_memory + Sn_BASE + sn * Sn_SIZE;

	const int igmpv = socket[Sn_MR] & Sn_MR_MC ? 1 : 2;

	// IGMP v1 doesn't have a leave message.
	if (!connect && igmpv == 1) return;

	memcpy(message, socket + Sn_DHAR0, 6);
	memcpy(message + 6, &m_memory[SHAR0], 6);
	message[12] = ETHERNET_TYPE_IP >> 8;
	message[13] = ETHERNET_TYPE_IP;

	++m_identification;


	// ip header
	message[14] = 0x46; // IPv4, length = 6*4
	message[15] = socket[Sn_TOS]; // TOS
	message[16] = 32 >> 8; // total length
	message[17] = 32;
	message[18] = m_identification >> 8; // identification
	message[19] = m_identification;
	message[20] = 0x40; // flags - don't fragment
	message[21] = 0x00;
	message[22] = 1; // ttl
	message[23] = IP_IGMP;
	message[24] = 0; // checksum...
	message[25] = 0;
	memcpy(message + 26, m_memory + SIPR0, 4); // source ip
	memcpy(message + 30, socket + Sn_DIPR0, 4); // destination ip

	// IP Option - Router Alert
	message[34] = 0x94;
	message[35] = 0x04;
	message[36] = 0x00;
	message[37] = 0x00;


	message[38] = igmpv == 2 ? IGMP_TYPE_MEMBERSHIP_REPORT_V2 : IGMP_TYPE_MEMBERSHIP_REPORT_V1;
	message[39] = 0; // max resp time
	message[40] = 0; // checksum
	message[41] = 0;
	memcpy(message + 42, socket + Sn_DIPR0, 4); // multicast address -- destination ip

	if (!connect)
	{
		// IGMP v2 leave messages go to the subnet router.
		static uint8_t eth[] = { 0x01, 0x00, 0x5e, 0x00, 0x00, 0x02 };
		static uint8_t ip[] = { 0xe0, 0x00, 0x00, 0x02 };
		memcpy(message + 0, eth, 6);
		memcpy(message + 30, ip, 4);
		message[34] = IGMP_TYPE_LEAVE_GROUP;
	}

	crc = util::internet_checksum_creator::simple(message + 14, 20);
	message[24] = crc >> 8;
	message[25] = crc;

	crc = util::internet_checksum_creator::simple(message + 38, 8);
	message[40] = crc >> 8;
	message[41] = crc;

	send(message, MESSAGE_SIZE);
}


/* length includes the 34-byte ethernet/ip header */
void w5100_device::build_ipraw_header(int sn, uint8_t *buffer, int length)
{
	uint8_t *socket = m_memory + Sn_BASE + Sn_SIZE * sn;

	//ethernet header
	memcpy(buffer + 0, &socket[Sn_DHAR0], 6);
	memcpy(buffer + 6, &m_memory[SHAR0], 6);
	buffer[12] = ETHERNET_TYPE_IP >> 8;
	buffer[13] = ETHERNET_TYPE_IP;

	length -= 14;

	++m_identification;

	// ip header
	buffer[14] = 0x45; // IPv4, length = 5*4
	buffer[15] = socket[Sn_TOS];
	buffer[16] = length >> 8; // total length
	buffer[17] = length;
	buffer[18] = m_identification >> 8; // identification
	buffer[19] = m_identification;
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
	buffer[12] = ETHERNET_TYPE_IP >> 8;
	buffer[13] = ETHERNET_TYPE_IP;

	length -= 14;

	++m_identification;

	// ip header
	buffer[14] = 0x45; // IPv4, length = 5*4
	buffer[15] = socket[Sn_TOS];
	buffer[16] = length >> 8; // total length
	buffer[17] = length;
	buffer[18] = m_identification >> 8; // identification
	buffer[19] = m_identification;
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


	util::internet_checksum_creator cc;

	// ip pseudo header.
	cc.append(m_memory + SIPR0, 4); // source ip
	cc.append(socket + Sn_DIPR0, 4); // dest ip
	cc.append(static_cast<uint16_t>(IP_UDP));
	cc.append(static_cast<uint16_t>(length + 20));
	cc.append(buffer + 34, length);

	crc = cc.finish();
	if (crc == 0) crc = 0xffff;
	buffer[40] = crc >> 8;
	buffer[41] = crc;
}

void w5100_device::handle_icmp_request(uint8_t *buffer, int length)
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

void w5100_device::send_icmp_unreachable(uint8_t *buffer, int length)
{

	uint16_t crc;
	uint8_t message[14 + 20 + 8 + 8 + 60]; // max ip header is 15 * 4 == 60

	int ihl = (buffer[14 + o_IP_IHL] & 0x0f) << 4;

	int new_length = 20 + 8 + ihl + 8;

	// ethernet header
	memcpy(message + o_ETHERNET_DEST , buffer + o_ETHERNET_SRC, 6);
	memcpy(message + o_ETHERNET_SRC, m_memory + SHAR0, 6);
	write16(message + o_ETHERNET_TYPE, ETHERNET_TYPE_IP);

	// ip header
	message[14] = 0x45; // IPv4, length = 5*4
	message[15] = 0; // TOS
	message[16] = new_length >> 8; // total length
	message[17] = new_length;
	message[18] = m_identification >> 8; // identification
	message[19] = m_identification;
	message[20] = 0x40; // flags - don't fragment
	message[21] = 0x00;
	message[22] = 64; // TTOL
	message[23] = IP_ICMP;
	message[24] = 0; // checksum...
	message[25] = 0;
	memcpy(buffer + 26, m_memory + SIPR0, 4); // source ip
	memcpy(buffer + 30, buffer + 14 + o_IP_SRC_ADDRESS, 4); // destination ip

	// icmp header
	message[34] = ICMP_DESTINATION_UNREACHABLE;
	message[35] = 3; // port unreachable
	message[36] = 0; // checksum
	message[37] = 0;
	message[38] = 0;
	message[39] = 0;

	memcpy(message + 40, buffer + 14, 8 + ihl);

	// ip crc.
	crc = util::internet_checksum_creator::simple(buffer + 14, 20);
	buffer[24] = crc >> 8;
	buffer[25] = crc;

	// icmp crc
	crc = util::internet_checksum_creator::simple(buffer + 34, 8 + ihl + 8);
	buffer[36] = crc >> 8;
	buffer[37] = crc;

	send(message, new_length + 14);
}

// w5100s socket-less ping command.
void w5100_device::send_icmp_request()
{

	static const int MESSAGE_SIZE = 14 + 20 + 26;
	uint8_t message[MESSAGE_SIZE];

	uint16_t crc;

	memcpy(message + 0, m_memory + SLPHAR0, 6);
	memcpy(message + 6, m_memory + SHAR0, 6);
	write16(message + 12, ETHERNET_TYPE_IP);

	message[14] = 0x45; // IPv4, length = 5*4
	message[15] = 0; // TOS
	message[16] = MESSAGE_SIZE >> 8; // total length
	message[17] = MESSAGE_SIZE;
	message[18] = m_identification >> 8; // identification
	message[19] = m_identification;
	message[20] = 0x40; // flags - don't fragment
	message[21] = 0x00;
	message[22] = 64; // TTOL
	message[23] = IP_ICMP;
	message[24] = 0; // checksum...
	message[25] = 0;
	memcpy(message + 26, m_memory + SIPR0, 4); // source ip
	memcpy(message + 30, m_memory + SLIPR0, 4); // destination ip

	// icmp header
	message[34] = ICMP_ECHO_REQUEST;
	message[35] = 0;
	message[36] = 0; // checksum
	message[37] = 0;
	message[38] = m_memory[PINGIDR0];
	message[39] = m_memory[PINGIDR1];
	message[40] = m_memory[PINGSEQR0];
	message[41] = m_memory[PINGSEQR1];
	for (int i = 0; i < 18; ++i)
		message[42 + i] = 'a' + i;


	// ip crc.
	crc = util::internet_checksum_creator::simple(message + 14, 20);
	message[24] = crc >> 8;
	message[25] = crc;

	// icmp crc
	crc = util::internet_checksum_creator::simple(message + 34, 26);
	message[36] = crc >> 8;
	message[37] = crc;

	// set timer...
	send(message, MESSAGE_SIZE);
}

void w5100_device::dump_bytes(const uint8_t *buffer, int length)
{
	if (VERBOSE & LOG_PACKETS)
	{
		static char hex[] = "0123456789abcdef";
		char dump[16 *3 + 2];
		int j = 0;

		for (int i = 0; i < length; ++i)
		{
			uint8_t c = buffer[i];
			dump[j++] = hex[c >> 4];
			dump[j++] = hex[c & 0x0f];
			dump[j++] = ' ';

			if ((i & 0x0f) == 0x0f)
			{
				dump[--j] = 0;
				LOGMASKED(LOG_PACKETS, "%s\n", dump);
				j = 0;
			}
		}
		if (j > 0)
		{
			dump[--j] = 0; 
			LOGMASKED(LOG_PACKETS, "%s\n", dump);

		}
	}
}

/* tcp callbacks */

void w5100_device::tcp_state_change(int sn, tcpip_device::tcp_state new_state, tcpip_device::tcp_state old_state)
{
	auto tcp = m_tcp[sn];

	uint8_t *socket = m_memory + Sn_BASE + sn * Sn_SIZE;
	uint8_t &sr = socket[Sn_SR];

	disconnect_type dt = disconnect_type::none;

	switch(new_state)
	{
		case tcp_state::TCPS_CLOSED:
			sr = Sn_SR_CLOSED;
			dt = tcp->get_disconnect_type();
			if (dt == disconnect_type::passive_reset || dt == disconnect_type::active_close)
			{
				socket[Sn_IR] |= Sn_IR_DISCON; // fin packet recvd.
				update_ethernet_irq();	
			}
			if (dt == disconnect_type::timeout)
			{
				socket[Sn_IR] |= Sn_IR_TIMEOUT;
				update_ethernet_irq();
			}
			LOGMASKED(LOG_TCP, "tcp socket %d SR_CLOSED\n", sn);
			break;

		case tcp_state::TCPS_LISTEN:
			// TODO - TCP model remains listening if connection closes before it's established.
			sr = Sn_SR_LISTEN;
			LOGMASKED(LOG_TCP, "tcp socket %d SR_LISTEN\n", sn);
			break;

		case tcp_state::TCPS_SYN_SENT:
			// if (old_state != tcp_state::TCPS_SYN_RECEIVED)
			sr = Sn_SR_SYNSENT;
			LOGMASKED(LOG_TCP, "tcp socket %d SR_SYNSENT\n", sn);
			break;

		case tcp_state::TCPS_SYN_RECEIVED:
			sr = Sn_SR_SYNRECV;
			break;

		case tcp_state::TCPS_ESTABLISHED:
			if (tcp->get_connect_type() == connect_type::passive)
			{
				write32(socket + Sn_DIPR0, tcp->get_remote_ip());
				write16(socket + Sn_DPORT0, tcp->get_remote_ip());
				write16(socket + Sn_MSSR0, tcp->get_remote_mss());
				memcpy(socket + Sn_DHAR0, tcp->get_remote_mac(), 6);
			}
			sr = Sn_SR_ESTABLISHED;
			socket[Sn_IR] |= Sn_IR_CON;
			update_ethernet_irq();
			LOGMASKED(LOG_TCP, "tcp socket %d SR_ESTABLISHED\n", sn);
			break;

		case tcp_state::TCPS_CLOSE_WAIT:
			// close-wait indicates a FIN packet was received.
			sr = Sn_SR_CLOSE_WAIT;
			socket[Sn_IR] |= Sn_IR_DISCON;
			update_ethernet_irq();
			LOGMASKED(LOG_TCP, "tcp socket %d SR_CLOSE_WAIT\n", sn);
			break;

		case tcp_state::TCPS_FIN_WAIT_1:
		case tcp_state::TCPS_FIN_WAIT_2:
			sr = Sn_SR_FIN_WAIT;
			break;

		case tcp_state::TCPS_CLOSING:
			sr = Sn_SR_CLOSING;
			break;

		case tcp_state::TCPS_LAST_ACK:
			sr = Sn_SR_LAST_ACK;
			break;

		case tcp_state::TCPS_TIME_WAIT:
			sr = Sn_SR_TIME_WAIT;
			break;
	}
}

void w5100_device::tcp_receive(int sn)
{
	/* read available data from tcp device into the rx buffer, updates pointers, sets irq */
	/* called by socket read and tcp_event callback */

	auto tcp = m_tcp[sn];
	uint8_t * socket = m_memory + Sn_BASE + sn * Sn_SIZE;

	int rx_buffer_offset = m_sockets[sn].rx_buffer_offset;
	int rx_buffer_size = m_sockets[sn].rx_buffer_size;

	uint16_t read_ptr = read16(socket + Sn_RX_RD0);
	uint16_t write_ptr = read16(socket + Sn_RX_WR0);

	read_ptr &= (rx_buffer_size - 1);
	write_ptr &= (rx_buffer_size - 1);

	int used = read16(socket + Sn_RX_RSR0);

#if 0
	// doesn't work when full!
	int used = write_ptr - read_ptr;
	if (used < 0) used += rx_buffer_size;
#endif
	int available = rx_buffer_size - used;
	uint8_t *ptr = m_memory + rx_buffer_offset;

	while (available > 0 && !tcp->receive_buffer_empty())
	{
		int length = available;
		if (write_ptr + length > rx_buffer_size)
			length = rx_buffer_size - write_ptr;

		auto err = tcp->receive(ptr + write_ptr, length, nullptr, nullptr);
		if (err != tcp_error::ok) break;
		LOGMASKED(LOG_TCP, "copied %d bytes from tcp receive buffer\n", length);
		available -= length;
		used += length;
		write_ptr = (write_ptr + length) & (rx_buffer_size - 1);
	}


	socket[Sn_RX_WR0] = write_ptr >> 8;
	socket[Sn_RX_WR1] = write_ptr;

	socket[Sn_RX_RSR0] = used >> 8;
	socket[Sn_RX_RSR1] = used;

	if (used != 0)
	{
		socket[Sn_IR] |= Sn_IR_RECV;
		update_ethernet_irq();
	}

	LOG("exit receive sn=%d read_ptr = 0x%04x write_ptr = 0x%04x rsr = %d\n",
		sn, read_ptr, write_ptr, used);

}

void w5100_device::tcp_send_complete(int sn)
{
	uint8_t *socket = m_memory + Sn_BASE + sn * Sn_SIZE;

	auto tcp = m_tcp[sn];

	// int tx_buffer_offset = m_sockets[sn].tx_buffer_offset;
	int tx_buffer_size = m_sockets[sn].tx_buffer_size;

	uint16_t read_ptr = read16(socket + Sn_TX_RD0);
	uint16_t write_ptr = read16(socket + Sn_TX_WR0);

	int free = tcp->send_count();
	read_ptr = (write_ptr - free) & (tx_buffer_size - 1);


	socket[Sn_TX_RD0] = read_ptr >> 8;
	socket[Sn_TX_RD1] = read_ptr;
	socket[Sn_TX_FSR0] = free >> 8;
	socket[Sn_TX_FSR1] = free;

	if (tcp->send_buffer_empty())
	{
		socket[Sn_IR] |= Sn_IR_SEND_OK;
		update_ethernet_irq(); 
	}

}



w5100_device::w5100_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock)
	: w5100_device(mconfig, W5100, tag, owner, clock, dev_type::W5100)
{
}

w5100s_device::w5100s_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock)
	: w5100_device(mconfig, W5100S, tag, owner, clock, dev_type::W5100S)
{
}



DEFINE_DEVICE_TYPE(W5100, w5100_device, "w5100", "WIZnet W5100 Ethernet Controller")
DEFINE_DEVICE_TYPE(W5100S, w5100s_device, "w5100s", "WIZnet W5100s Ethernet Controller")
