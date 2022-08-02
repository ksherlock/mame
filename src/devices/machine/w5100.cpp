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
	Not supported:
	- anything PPPoE related
	- w5100s PHY, etc

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
	CLKLCKR = 0x70,
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
	Sn_FRAGR0, // also on w5100
	Sn_FRAGR1, // also on w5100
	Sn_MR2,
	Sn_KPALVTR,
	Sn_TSR, /* "reserved", Socket Timer Status Register. */
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


/* Socket Command Register */
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

	// documented in iolib header for w5100s
	Sn_CR_IGMP_JOIN = 0x23,
	Sn_CR_IGMP_LEAVE = 0x24,

};


/* Socket Status Register */
enum {
	Sn_SR_CLOSED = 0x00,
	Sn_SR_INIT = 0x13,
	Sn_SR_LISTEN = 0x14,
	Sn_SR_SYNSENT = 0x15,
	Sn_SR_SYNRECV = 0x16,
	Sn_SR_ESTABLISHED = 0x17,
	Sn_SR_FIN_WAIT = 0x18,
	Sn_SR_CLOSING = 0x1a,
	Sn_SR_TIME_WAIT = 0x1b,
	Sn_SR_CLOSE_WAIT = 0x1c,
	Sn_SR_LAST_ACK = 0x1d,

	Sn_SR_UDP = 0x22,
	Sn_SR_IPRAW = 0x32,
	Sn_SR_MACRAW = 0x42,
	Sn_SR_PPPOE = 0x5f,

	// n.b. SR_ARP only documented for w5100.
	Sn_SR_ARP = 0x01,

	//
	Sn_SR_FIN_WAIT_1 = 0x18,
	Sn_SR_FIN_WAIT_2 = 0x19,

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

	IP_PROTOCOL_ICMP = 1,
	IP_PROTOCOL_IGMP = 2,
	IP_PROTOCOL_TCP = 6,
	IP_PROTOCOL_UDP = 17,
};

enum {
	o_UDP_SRC_PORT = 0,
	o_UDP_DEST_PORT = 2,
	o_UDP_LENGTH = 4,
	o_UDP_CHECKSUM = 6,
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

	if (proto == IP_PROTOCOL_ICMP || proto == IP_PROTOCOL_IGMP)
	{
		if (!util::internet_checksum_creator::simple(data, length)) return false;
	}
	else if (proto == IP_PROTOCOL_UDP)
	{
		if (length < read16(data + o_UDP_LENGTH)) return false;

		uint16_t crc = read16(data + o_UDP_CHECKSUM);
		if (crc)
		{
			uint8_t header[12];
			memcpy(header + 0, ip + o_IP_SRC_ADDRESS, 4);
			memcpy(header + 4, ip + o_IP_DEST_ADDRESS, 4);
			write16(header + 8, IP_PROTOCOL_UDP);
			write16(header + 10, length);

			util::internet_checksum_creator cr;
			cr.append(header, sizeof(header));
			cr.append(data, length);
			if (cr.finish() != 0) return false;
			// uint16_t xcrc = cr.finish();
			// if (xcrc == 0) xcrc = 0xffff;
			// if (crc != xcrc) return false;
		}
	}
	else if (proto == IP_PROTOCOL_TCP)
	{
		if (length < 20) return false;

		int offset = (data[o_TCP_DATA_OFFSET] >> 4) << 2;
		if (offset < 20) return false;
		if (length < offset) return false;

		uint8_t header[12];
		memcpy(header + 0, ip + o_IP_SRC_ADDRESS, 4);
		memcpy(header + 4, ip + o_IP_DEST_ADDRESS, 4);
		write16(header + 8, IP_PROTOCOL_TCP);
		write16(header + 10, length);

		util::internet_checksum_creator cr;
		cr.append(header, sizeof(header));
		cr.append(data, length);
		if (cr.finish() != 0) return false;
	}

	return ihl;
}


static std::tuple<int, int, int> get_tcp_offsets(const uint8_t *buffer)
{
	const uint8_t *ptr = buffer + 14;

	int ip_header_length = (ptr[o_IP_IHL] & 0x0f) << 2;
	int ip_length = read16(ptr + o_IP_LENGTH);

	ptr += ip_header_length;
	int tcp_header_length = (ptr[o_TCP_DATA_OFFSET] >> 4) << 2;

	int data_length = ip_length - ip_header_length - tcp_header_length;

	return std::make_tuple(ip_header_length, tcp_header_length, data_length);
}

static void tcp_checksum(uint8_t *segment, int ip_length, int tcp_length)
{
	uint8_t pseudo_header[12];
	uint16_t crc;

	crc = util::internet_checksum_creator::simple(segment, ip_length);
	write16(segment + o_IP_CHECKSUM, crc);

	util::internet_checksum_creator cc;

	memcpy(pseudo_header + 0, segment + o_IP_SRC_ADDRESS, 4);
	memcpy(pseudo_header + 4, segment + o_IP_DEST_ADDRESS, 4);
	write16(pseudo_header + 8, IP_PROTOCOL_TCP);
	write16(pseudo_header + 10, tcp_length);

	segment += ip_length;

	cc.append(pseudo_header, sizeof(pseudo_header));
	cc.append(segment, tcp_length);

	crc = cc.finish();
	write16(segment + o_TCP_CHECKUSM, crc);
}

static void udp_checksum(uint8_t *segment, int ip_length, int udp_length)
{
	uint8_t pseudo_header[12];
	uint16_t crc;

	crc = util::internet_checksum_creator::simple(segment, ip_length);
	write16(segment + o_IP_CHECKSUM, crc);

	util::internet_checksum_creator cc;

	memcpy(pseudo_header + 0, segment + o_IP_SRC_ADDRESS, 4);
	memcpy(pseudo_header + 4, segment + o_IP_DEST_ADDRESS, 4);
	write16(pseudo_header + 8, IP_PROTOCOL_UDP);
	write16(pseudo_header + 10, udp_length);

	segment += ip_length;

	cc.append(pseudo_header, sizeof(pseudo_header));
	cc.append(segment, udp_length);

	crc = cc.finish();
	if (crc == 0) crc = 0xffff;

	write16(segment + o_UDP_CHECKSUM, crc);
}



/* tcp sequence comparisons. */
// a <= b <= c
inline static bool ack_valid_le_le(uint32_t a, uint32_t b, uint32_t c)
{
	if (a <= c) return (a <= b) && (b <= c);
	return (a <= b) || (b <= c);
}

#if 0
// a <= b < c
inline static bool ack_valid_le_lt(uint32_t a, uint32_t b, uint32_t c)
{
	if (a < c) return (a <= b) && (b < c);
	return (a <= b) || (b < c);

}
#endif

// a < b <= c
inline static bool ack_valid_lt_le(uint32_t a, uint32_t b, uint32_t c)
{
	if (a < c) return (a < b) && (b <= c);
	return (a < b) || (b <= c);
}

// a > b
inline static bool ack_valid_gt(uint32_t a, uint32_t b)
{
	return static_cast<int32_t>(a - b) > 0;
}


[[maybe_unused]] static const char *sr_to_cstring(int sr)
{
	switch(sr)
	{
		case Sn_SR_CLOSED: return "SR_CLOSED";
		case Sn_SR_INIT: return "SR_INIT";
		case Sn_SR_LISTEN: return "SR_LISTEN";
		case Sn_SR_SYNSENT: return "SR_SYNSENT";
		case Sn_SR_SYNRECV: return "SR_SYNRECV";
		case Sn_SR_ESTABLISHED: return "SR_ESTABLISHED";
		case Sn_SR_FIN_WAIT_1: return "SR_FIN_WAIT_1";
		case Sn_SR_FIN_WAIT_2: return "SR_FIN_WAIT_2";
		case Sn_SR_CLOSING: return "SR_CLOSING";
		case Sn_SR_TIME_WAIT: return "SR_TIME_WAIT";
		case Sn_SR_CLOSE_WAIT: return "SR_CLOSE_WAIT";
		case Sn_SR_LAST_ACK: return "SR_LAST_ACK";
		case Sn_SR_UDP: return "SR_UDP";
		case Sn_SR_IPRAW: return "SR_IPRAW";
		case Sn_SR_MACRAW: return "SR_MACRAW";
		case Sn_SR_PPPOE: return "SR_PPPOE";
		case Sn_SR_ARP: return "SR_ARP";
		default: return "???";
	}
}


[[maybe_unused]] static std::string ip_to_string(uint32_t ip, uint16_t port)
{
	char buffer[4 * 4 + 5 + 1];
	snprintf(buffer, sizeof(buffer), "%d.%d.%d.%d:%d",
		(ip >> 24) & 0xff,
		(ip >> 16) & 0xff,
		(ip >> 8) & 0xff,
		(ip >> 0) & 0xff,
		port
	);
	return buffer;
}

[[maybe_unused]] static std::string ip_to_string(uint32_t ip)
{
	char buffer[4 * 4 + 5 + 1];
	snprintf(buffer, sizeof(buffer), "%d.%d.%d.%d",
		(ip >> 24) & 0xff,
		(ip >> 16) & 0xff,
		(ip >> 8) & 0xff,
		(ip >> 0) & 0xff
	);
	return buffer;
}


w5100_base_device::w5100_base_device(const machine_config &mconfig, device_type type, const char *tag, device_t *owner, uint32_t clock, dev_type device_type)
	: device_t(mconfig, type, tag, owner, clock)
	, device_network_interface(mconfig, *this, 10)
	, m_device_type(device_type)
	, m_irq_handler(*this)
{
}

void w5100_base_device::device_start()
{
	save_item(m_common_registers, "General Registers");
	save_item(m_socket_registers[0], "Socket 0 Registers");
	save_item(m_socket_registers[1], "Socket 1 Registers");
	save_item(m_socket_registers[2], "Socket 2 Registers");
	save_item(m_socket_registers[3], "Socket 3 Registers");
	save_item(m_tx_buffer, "TX Buffer Memory");
	save_item(m_rx_buffer, "RX Buffer Memory");

	save_item(NAME(m_idm));
	save_item(NAME(m_identification));
	save_item(NAME(m_irq_state));

	m_irq_handler.resolve_safe();

	m_interrupt_timer = timer_alloc(FUNC(w5100_base_device::interrupt_timer), this);
	for (int sn = 0; sn < 4 ; ++sn)
	{
		emu_timer *t;
		t = timer_alloc(FUNC(w5100_base_device::delayed_ack_timer), this);
		t->set_param(sn);
		m_delayed_ack_timers[sn] = t;

		t = timer_alloc(FUNC(w5100_base_device::keep_alive_timer), this);
		t->set_param(sn);
		m_keep_alive_timers[sn] = t;
	}

	for (int sn = 0; sn < 5; ++sn)
	{
		m_retry_timers[sn] = timer_alloc(FUNC(w5100_base_device::retry_timer), this);
	}

}


void w5100_base_device::device_add_mconfig(machine_config &config)
{
}


void w5100_base_device::device_reset()
{
	// nyi - rx / tx buffer not cleared on reset.

	m_idm = 0;

	memset(m_common_registers, 0, sizeof(m_common_registers));
	memset(m_socket_registers, 0, sizeof(m_socket_registers));

	memset(m_sockets, 0, sizeof(m_sockets));

	m_common_registers[RTR0] = 0x07;
	m_common_registers[RTR1] = 0xd0;
	m_common_registers[RCR] = 0x08;
	m_common_registers[RMSR] = 0x55;
	m_common_registers[TMSR] = 0x55;
	m_common_registers[PTIMER] = 0x28;

	update_tmsr(0x55);
	update_rmsr(0x55);

	for (int sn = 0; sn < 4; ++sn)
	{
		uint8_t *socket = m_socket_registers[sn];

		for (int i = 0; i < 6; ++i)
		{
			socket[Sn_DHAR0+i] = 0xff;
		}

		socket[Sn_TTL] = 0x80;
		socket[Sn_FRAGR0] = 0x40;

		// socket[Sn_TX_FSR0] = 0x08;
		// socket[Sn_TX_FSR1] = 0x00;

		if (m_device_type == dev_type::W5100S)
		{
			socket[Sn_IMR] = 0xff;
		}

		m_sockets[sn].reset();
		m_sockets[sn].reset_tcp();

	}


	if (m_device_type == dev_type::W5100S)
	{
		m_common_registers[MR] = MR_AI | MR_IND;
		m_common_registers[MR2] = MR2_IEN;
		m_common_registers[PMRUR0] = 0xff;
		m_common_registers[PMRUR1] = 0xff;
		m_common_registers[PHYSR1] = 0x81;
		m_common_registers[PHYDIVR] = 0x01;
		m_common_registers[PHYCR1] = 0x41;
		m_common_registers[SLRTR0] = 0x07;
		m_common_registers[SLRTR1] = 0xd0;
		m_common_registers[VERR] = 0x51;
		m_common_registers[PHYSR0] = PHYSR0_LINK;
		m_common_registers[RCR] = 0x07; // incorrectly documented as 0x08
	}


	m_identification = 0;

	if (m_irq_state)
		m_irq_handler(CLEAR_LINE);
	m_irq_state = 0;

	set_mac(reinterpret_cast<char *>(m_common_registers + SHAR0));
	set_promisc(false);
}


void w5100_base_device::device_post_load()
{
	// memset(m_sockets, 0, sizeof(m_sockets));
	// todo -- store previous values, only if updated.
	// update_tmsr(m_common_registers[TMSR]);
	// update_rmsr(m_common_registers[RMSR]);
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

// param & 0xff = socket, 5 = socket less command
// param >> 8 = type
enum {
	TIMER_ARP = 0x0100,
	TIMER_PING = 0x0200,
	TIMER_TCP_KEEP_ALIVE = 0x0300,
	TIMER_TCP_DELAYED_ACK = 0x0400,
	TIMER_TCP_RESEND = 0x0500,
	// TIMER_TCP_2MSL = 0x0600,
	// TIMER_TCP_KEEP_ALIVE = 0x0700,
};

void w5100_base_device::socket_repeat_timer(int sn, int param)
{
	int rcr;
	int rtr;

	if (m_device_type == dev_type::W5100S)
	{
		const uint8_t *socket = m_socket_registers[sn];
		rcr = socket[Sn_RCR];
		rtr = read16(socket + Sn_RTR0);
	}
	else
	{
		rcr = m_common_registers[RCR];
		rtr = read16(m_common_registers + RTR0);
	}
	if (!rtr) rtr = 1;

	attotime tm = attotime::from_usec(rtr * 100);

	m_sockets[sn].retry = rcr;
	m_retry_timers[sn]->adjust(tm, param | sn, tm);

}



TIMER_CALLBACK_MEMBER(w5100_base_device::retry_timer)
{
	// used for ARP, PING, and tcp resend.
	int sn = param & 0xff;
	int cmd = param & 0xff00;

	bool timeout = false;
	if (--m_sockets[sn].retry < 0)
	{
		timeout = true;
		m_retry_timers[sn]->enable(false);
	}

	if (cmd == TIMER_ARP)
	{
		uint32_t ip = m_sockets[sn].arp_ip_address;

		if (timeout)
		{
			LOGMASKED(LOG_ARP, "ARP timeout for %s\n", ip_to_string(ip));

			if (sn == 5)
			{
				m_common_registers[SLIR] |= SLIR_TIMEOUT;
			}
			else
			{
				uint8_t *socket = m_socket_registers[sn];
				int proto = m_sockets[sn].proto;
				uint8_t &sr = socket[Sn_SR];

				// TODO -- UDP / IPRAW need to update tx_rd and fsr.
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
				socket[Sn_IR] |= Sn_IR_TIMEOUT;
			}
			update_ethernet_irq();				
			return;
		}
		send_arp_request(ip);
		return;

	}
	if (cmd == TIMER_PING)
	{
		uint32_t ip = m_sockets[sn].arp_ip_address;

		// socket-less ping.
		if (sn == 5)
		{
			if (timeout)
			{
				LOGMASKED(LOG_ARP, "PING timeout for %s\n", ip_to_string(ip));

				m_common_registers[SLIR] |= SLIR_TIMEOUT;
				update_ethernet_irq();
				return;				
			}
			send_icmp_request();
		}
		return;
	}


	// TODO -- TCP connect (maybe others) backs off.
	// eg, .2 seconds, .4 seconds, .8 seconds, 1.6 seconds, 3.2 seconds
	if (cmd == TIMER_TCP_RESEND)
	{
		uint8_t *socket = m_socket_registers[sn];
		int sr = socket[Sn_SR];

		if (timeout)
		{
			LOGMASKED(LOG_TCP, "TCP timeout %d\n", sn);

			socket[Sn_IR] |= Sn_IR_TIMEOUT;
			socket[Sn_SR] = Sn_SR_CLOSED;
			m_sockets[sn].proto == 0;
			update_ethernet_irq();
			return;
		}
		LOGMASKED(LOG_TCP, "TCP Resend Timer %d\n", sn);

		const auto iss = m_sockets[sn].iss;
		const auto snd_nxt = m_sockets[sn].snd_nxt;
		const auto snd_una = m_sockets[sn].snd_una;
		const auto rcv_nxt = m_sockets[sn].rcv_nxt;

		switch(sr)
		{
			case Sn_SR_SYNSENT:
				tcp_send_segment(sn, TCP_SYN, iss, 0);
				break;

			case Sn_SR_SYNRECV:
				tcp_send_segment(sn, TCP_ACK | TCP_SYN, iss, rcv_nxt);
				break;

			case Sn_SR_ESTABLISHED:
			case Sn_SR_CLOSE_WAIT:
				if (snd_nxt == snd_una)
					tcp_send_segment(sn, TCP_ACK, snd_nxt - 1, rcv_nxt); // keep-alive
				else
					tcp_send(sn, true);
				break;

			case Sn_SR_FIN_WAIT_1:
			case Sn_SR_LAST_ACK:
				tcp_send_segment(sn, TCP_FIN|TCP_ACK, snd_nxt - 1, rcv_nxt);
				break;
		}
	}

}

TIMER_CALLBACK_MEMBER(w5100_base_device::keep_alive_timer)
{
	// w5100s keep-alive timer
	int sn = param;
	LOGMASKED(LOG_TCP, "TCP: %d - keep alive timer\n", sn);
	socket_send_keep(sn, true);
}

TIMER_CALLBACK_MEMBER(w5100_base_device::delayed_ack_timer)
{
	int sn = param;

	auto snd_nxt = m_sockets[sn].snd_nxt;
	auto rcv_nxt = m_sockets[sn].rcv_nxt;
	LOGMASKED(LOG_TCP, "TCP: %d - delayed ack timer\n", sn);
	tcp_send_segment(sn, TCP_ACK, snd_nxt, rcv_nxt);
}



/*
INTPTMR sets internal Interrupt Pending Timer Count. 

When INTn is de-asserted to High, Timer Count is initialized to INTPTMR and decreased by 1 from initial value to ‘0’ every SYS_CLK x 4.
When Interrupt occurs and the corresponding Interrupt Mask is set and INTPTMR is ‘0’, INTn is asserted to Low.

INTn is pin 47, 

See How To Use Interrupt Application Note.
*/


TIMER_CALLBACK_MEMBER(w5100_base_device::interrupt_timer)
{
	// w5100s delayed IRQ timer
	if (m_irq_state) m_irq_handler(ASSERT_LINE);
}


void w5100_base_device::update_ethernet_irq()
{
	// nyi - w5100s INTPTMR interrupt pending time register delays interrupt signal.

	int ir = m_common_registers[IR] & 0b11100000;
	int ir2 = 0;
	int slir = 0;

	for (int sn = 0, bit = IR_S0_INT; sn < 4; ++sn, bit <<= 1)
	{
		const uint8_t *socket = m_socket_registers[sn];
		int sir = socket[Sn_IR] & 0b00011111;

		if (m_device_type == dev_type::W5100S)
			sir &= socket[Sn_IMR];

		if (sir) ir |= bit;
	}

	m_common_registers[IR] = ir;
	ir &= m_common_registers[IMR];

	int intptmr = 0;

	if (m_device_type == dev_type::W5100S)
	{
		ir2 = m_common_registers[IR2] & 0b00000001;
		ir2 &= m_common_registers[IMR2];
		slir = m_common_registers[SLIR] & 0b00000111;
		slir &= m_common_registers[SLIMR];

		if ((m_common_registers[MR2] & MR2_IEN) == 0)
		{
			ir = 0;
			ir2 = 0;
			slir = 0;
		}
		intptmr = read16(m_common_registers + INTPTMR0);
	}

	uint32_t new_state = (slir << 16) | (ir2 << 8) | (ir);


	if (new_state ^ m_irq_state)
	{
		m_irq_state = new_state;

		if (intptmr)
		{
			// w5100s only.
			// pending interrupt timer is kicked off when interrupts are cleared.
			// while the timer is active, interrupts will be defered.
			if (m_irq_state && m_interrupt_timer->enabled())
				return;
			if (!m_irq_state && !m_interrupt_timer->enabled())
					m_interrupt_timer->adjust(clocks_to_attotime(intptmr * 4));
		}

		m_irq_handler(m_irq_state ? ASSERT_LINE : CLEAR_LINE);		
	}

}

int w5100_base_device::register_bank(uint16_t offset)
{
	if ((offset & 0x0700) < 0x0400) return 0;

	if (m_device_type == dev_type::W5100)
	{
		if (offset > 0x07ff) return 7;
	}
	return (offset & 0x0700) >> 8;
}


/*
 * Direct bus interface: 15-bit address, 8-bit data bus
 * Indirect bus interface: 2-bit address, 8-bit data bus
 * W5100s is always indirect w/ auto-increment
 */

uint8_t w5100_base_device::read(uint16_t offset)
{
	if (m_common_registers[0] & MR_IND)
	{
		switch(offset & 0x03)
		{
			case IDM_OR:
				return m_common_registers[0];
				break;
			case IDM_AR0:
				return m_idm >> 8;
				break;
			case IDM_AR1:
				return m_idm & 0xff;
				break;
			case IDM_DR:
				offset = m_idm;

				if ((m_common_registers[0] & MR_AI) && !machine().side_effects_disabled())
				{
					m_idm++;
					if (m_device_type == dev_type::W5100 && (m_idm & 0x1fff) == 0x0000)
						m_idm -= 0x2000;
				}
				break;
		}
	}

	offset &= 0x7fff;

	int bank;
	switch(offset >> 13)
	{
		case 0:
		case 1:
			bank = register_bank(offset);
			switch(bank)
			{
				case 4:
				case 5:
				case 6:
				case 7:
					return m_socket_registers[bank & 0x03][offset & 0xff];
					break;
				default:
					return m_common_registers[offset & 0xff];
					break;
			}
			break;
		case 2:
			return m_tx_buffer[offset & 0x1fff];
			break;
		case 3:
			return m_rx_buffer[offset & 0x1fff];
			break;
		default:
			return 0;
	}
}


void w5100_base_device::write(uint16_t offset, uint8_t data)
{
	if (m_common_registers[0] & MR_IND)
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
				if (m_common_registers[0] & MR_AI)
				{
					m_idm++;
					if (m_device_type == dev_type::W5100 && (m_idm & 0x1fff) == 0x0000)
						m_idm -= 0x2000;
				}
				break;
		}
	}


	offset &= 0x7fff;
	LOGMASKED(LOG_WRITE, "write(0x%04x, 0x%02x)\n", offset, data);

	int bank;
	switch(offset >> 13)
	{
		case 0:
		case 1:
			bank = register_bank(offset);
			switch(bank)
			{
				case 4:
				case 5:
				case 6:
				case 7:
					write_socket_register(bank & 0x3, offset & 0xff, data);
					break;
				default:
					return write_common_register(offset & 0xff, data);
					break;
			}
		case 2:
			m_tx_buffer[offset & 0x1fff] = data;
			break;
		case 3:
			m_rx_buffer[offset & 0x1fff] = data;
			break;
	}
}


void w5100_base_device::write_socket_register(int sn, int offset, uint8_t data)
{
	uint8_t *socket = m_socket_registers[sn];

	const bool W5100S = m_device_type == dev_type::W5100S;

	switch(offset)
	{
		case Sn_MR:
			socket[offset] = data;
			if ((sn == 0) && (data & Sn_MR_MF) == Sn_MR_MF)
				set_promisc(false);
			break;

		case Sn_PORT0:
		case Sn_PORT1:
		case Sn_PROTO:
		case Sn_TOS:
		case Sn_TTL:
		case Sn_FRAGR0:
		case Sn_FRAGR1:
			/* these update immediately */
			socket[offset] = data;
			break;


		case Sn_MR2:
			if (W5100S)
				socket[offset] = data;
			break;

		case Sn_RTR0:
		case Sn_RTR1:
		case Sn_RCR:
			if (W5100S)
				socket[offset + 0x80] = data;
			break;

		case Sn_DHAR0:
		case Sn_DHAR1:
		case Sn_DHAR2:
		case Sn_DHAR3:
		case Sn_DHAR4:
		case Sn_DHAR5:
		case Sn_DIPR0:
		case Sn_DIPR1:
		case Sn_DIPR2:
		case Sn_DIPR3:
		case Sn_DPORT0:
		case Sn_DPORT1:
		case Sn_MSSR0:
		case Sn_MSSR1:
		case Sn_TX_WR0:
		case Sn_TX_WR1:
		case Sn_RX_RD0:
		case Sn_RX_RD1:
			/* these don't update until a command (usually INIT, CONNECT, SEND, or RECV) is executed */
			socket[offset + 0x80] = data;
			break;

		case Sn_IR:
			/* write clears */
			socket[offset] &= ~data;
			update_ethernet_irq();
			break;

		case Sn_CR:
			socket_command(sn, data);
			break;

		case Sn_RX_BUF_SIZE:
			// only documented for w5100s, but also available on w5100
			socket[offset] = data;
			update_socket_rx_bufsize();
			break;

		case Sn_TX_BUF_SIZE:
			// only documented for w5100s, but also avilable on w5100
			socket[offset] = data;
			update_socket_tx_bufsize();
			break;

		/* W5100S below */

		case Sn_IMR:
			if (W5100S)
			{
				socket[offset] = data;
				update_ethernet_irq();
			}
			break;

		case Sn_KPALVTR:
			if (W5100S)
			{
				socket[offset] = data;
				auto sr = socket[Sn_SR];

				if (data == 0)
				{
					m_keep_alive_timers[sn]->enable(false);
				}
				else if (sr == Sn_SR_ESTABLISHED || sr == Sn_SR_CLOSE_WAIT)
				{
					attotime tm = attotime::from_seconds(data * 5);
					m_keep_alive_timers[sn]->adjust(tm, TIMER_TCP_KEEP_ALIVE, tm);
				}
			}
			break;

		default:
			/* read-only */
			break;
	}

}

void w5100_base_device::write_common_register(int offset, uint8_t data)
{
	const bool W5100S = m_device_type == dev_type::W5100S;

	switch(offset)
	{
		case MR:
			if (W5100S) data |= MR_AI | MR_IND;
			m_common_registers[offset] = data;
			if (data & MR_RST)
			{
				LOGMASKED(LOG_COMMAND, "software reset\n");
				device_reset();
			}
			break;

		case GAR0:
		case GAR1:
		case GAR2:
		case GAR3:
		case SUBR0:
		case SUBR1:
		case SUBR2:
		case SUBR3:
		case SIPR0:
		case SIPR1:
		case SIPR2:
		case SIPR3:
			// TODO - for w5100s, read-only when NETLCKR is locked.
			for (int sn = 0; sn < 4; ++sn)
				m_sockets[sn].arp_ok = false;
			m_common_registers[offset] = data;
			break;

		case SHAR0:
		case SHAR1:
		case SHAR2:
		case SHAR3:
		case SHAR4:
		case SHAR5:
			m_common_registers[offset] = data;
			set_mac(reinterpret_cast<char *>(m_common_registers + SHAR0));
			break;

		case INTPTMR0:
		case INTPTMR1:
			// TODO - interrupt pending timer support
			if (W5100S)
				m_common_registers[offset] = data;
			break;

		case IR:
			m_common_registers[offset] &= ~data;
			update_ethernet_irq();
			break;

		case IMR:
			m_common_registers[offset] = data;
			update_ethernet_irq();
			break;

		case RTR0:
		case RTR1:
		case RCR:
		case PTIMER:
		case PMAGIC:
			m_common_registers[offset] = data;
			break;

		case RMSR:
			m_common_registers[offset] = data;
			update_rmsr(data);
			break;

		case TMSR:
			m_common_registers[offset] = data;
			update_tmsr(data);
			break;

		case PATR0:
		case PATR1:
			if (!W5100S)
			{
				m_common_registers[offset] = data;
			}
			break;

		case IR2:
		case SLIR:
			if (W5100S)
			{
				m_common_registers[offset] &= ~data;
				update_ethernet_irq();
			}
			break;

		case IMR2:
		case MR2:
		case SLIMR:
			if (W5100S)
			{
				m_common_registers[offset] = data;
				update_ethernet_irq();
			}
			break;

		case PHAR0:
		case PHAR1:
		case PHAR2:
		case PHAR3:
		case PHAR4:
		case PHAR5:
		case PSIDR0:
		case PSIDR1:
		case PMRUR0:
		case PMRUR1:
		case PHYAR:
		case PHYDIR0:
		case PHYDIR1:
		case PHYDOR0:
		case PHYDOR1:
		case PHYDIVR:
		case PHYCR0:
		case PHYCR1:

		case SLRTR0:
		case SLRTR1:
		case SLRCR:
		case SLIPR0:
		case SLIPR1:
		case SLIPR2:
		case SLIPR3:
		case PINGSEQR0:
		case PINGSEQR1:
		case PINGIDR0:
		case PINGIDR1:
			if (W5100S)
				m_common_registers[offset] = data;
			break;

		case PHYACR:
			if (W5100S)
				/* unsupported */ ;
			break;

		case SLCR:
			if (W5100S)
				sl_command(data);
			break;

		case TCNTCLR:
			if (W5100S)
			{
				m_common_registers[TCNTR0] = 0;
				m_common_registers[TCNTR1] = 0;
			}
			break;

		case CLKLCKR:
		case NETLCKR:
		case PHYLCKR:
			/* write-only... */
			if (W5100S)
				/* unsupported */ ;
			break;

		default:
			/* read-only / reserved */
			break;
	}
}



/*
 * w5100s defines Sn_TXBUF_SIZE / Sn_RXBUF_SIZE as alternates for TMSR / RMSR
 * 0, 1, 2, 4, or 8 for 0k, 1k, 2k, 4k, 8k, respectively.
 * w5200+ eliminates TMSR/RMSR 
 */

void w5100_base_device::update_rmsr(uint8_t value)
{

	int offset = 0;
	for (int sn = 0; sn < 4; ++sn, value >>= 2)
	{
		uint8_t *socket = m_socket_registers[sn];
		int size = 1024 << (value & 0x3);
		m_sockets[sn].rx_buffer_size = size;
		m_sockets[sn].rx_buffer_offset = offset;
		offset += size;
		socket[Sn_RX_BUF_SIZE] = size >> 10;
	}

}

void w5100_base_device::update_tmsr(uint8_t value)
{

	int offset = 0;
	for (int sn = 0; sn < 4; ++sn, value >>= 2)
	{
		uint8_t *socket = m_socket_registers[sn];
		int size = 1024 << (value & 0x3);
		m_sockets[sn].tx_buffer_size = size;
		m_sockets[sn].tx_buffer_offset = offset;
		offset += size;

		socket[Sn_TX_BUF_SIZE] = size >> 10;

		/* also update FSR.   */
		uint16_t read_ptr = read16(socket + Sn_TX_RD0);
		uint16_t write_ptr = read16(socket + Sn_TX_WR0);

		if (m_sockets[sn].proto == Sn_MR_TCP)
			read_ptr = m_sockets[sn].snd_una;

		unsigned fsr = size + read_ptr - write_ptr;
		write16(socket + Sn_TX_FSR0, fsr);
		// LOG("socket %d free size = %d\n", sn, fsr);
	}

}


void w5100_base_device::update_socket_tx_bufsize()
{
	/* called after Sn_TXBUF_SIZE has been updated */
	/* w5100: invalid values set FSR = $2000 */
	/* w5100s: invalid values set FSR = $0001 */

	const bool W5100S = m_device_type == dev_type::W5100S;
	int offset = 0;

	for (int sn = 0; sn < 4; ++sn)
	{
		uint8_t *socket = m_socket_registers[sn];
		int v = socket[Sn_TX_BUF_SIZE];
		unsigned size = 0;
		switch(v)
		{
			case 0:
			case 1:
			case 2:
			case 4:
			case 8:
				size = v << 10;
				break;
			default:
				if (W5100S) size = 1;
				else size = 0x2000;
				break;
		}
		m_sockets[sn].tx_buffer_size = size;
		m_sockets[sn].tx_buffer_offset = offset;

		uint16_t read_ptr = read16(socket + Sn_TX_RD0);
		uint16_t write_ptr = read16(socket + Sn_TX_WR0);

		if (m_sockets[sn].proto == Sn_MR_TCP)
			read_ptr = m_sockets[sn].snd_una;

		unsigned fsr = size + read_ptr - write_ptr;
		write16(socket + Sn_TX_FSR0, fsr);

		offset += size;
	}
}

void w5100_base_device::update_socket_rx_bufsize()
{

	const bool W5100S = m_device_type == dev_type::W5100S;
	int offset = 0;

	for (int sn = 0; sn < 4; ++sn)
	{
		uint8_t *socket = m_socket_registers[sn];
		int v = socket[Sn_RX_BUF_SIZE];
		unsigned size = 0;
		switch(v)
		{
			case 0:
			case 1:
			case 2:
			case 4:
			case 8:
				size = v << 10;
				break;
			default:
				if (W5100S) size = 1;
				else size = 0x2000;
				break;
		}
		m_sockets[sn].rx_buffer_size = size;
		m_sockets[sn].rx_buffer_offset = offset;

		offset += size;
	}

}

void w5100_base_device::sl_command(int command)
{

	uint8_t &cr = m_common_registers[SLRCR];

	if (cr) return;

	switch(command)
	{
		case SLCR_ARP:
		case SLCR_PING:
			LOGMASKED(LOG_COMMAND, "Socket-Less %s\n", command == SLCR_ARP ? "ARP" : "PING");
			cr = command;
			m_sockets[4].command = command;
			m_sockets[4].arp_ok = false;
			ip_arp(4, read32(m_common_registers + SLIPR0), read16(m_common_registers + SLRTR0), m_common_registers[SLRCR]);
			break;

		default:
			LOGMASKED(LOG_COMMAND, "Socket-Less Unknown command (0x%02x)\n", command);
			break;

	}

}


void w5100_base_device::socket_command(int sn, int command)
{
	if (sn < 0 || sn > 3) return;

	uint8_t *socket = m_socket_registers[sn];
	//unsigned proto = m_sockets[sn].proto;
	uint8_t &sr = socket[Sn_SR];
	uint8_t mr = socket[Sn_MR];

	switch(command)
	{
		case Sn_CR_OPEN:
			// a2stream re-opens CR_MACRAW as TCP w/o closing.
			LOGMASKED(LOG_COMMAND, "Socket: %d: open\n", sn);
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

		case Sn_CR_IGMP_JOIN:
			LOGMASKED(LOG_COMMAND, "Socket: %d: IGMP Join\n", sn);
			if (m_device_type == dev_type::W5100S && sr == Sn_SR_UDP && mr & Sn_MR_MULT)
				send_igmp(sn, true);
			break;

		case Sn_CR_IGMP_LEAVE:
			LOGMASKED(LOG_COMMAND, "Socket: %d: IGMP Leave\n", sn);
			if (m_device_type == dev_type::W5100S && sr == Sn_SR_UDP && mr & Sn_MR_MULT)
				send_igmp(sn, false);
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


void w5100_base_device::socket_open(int sn)
{
	uint8_t *socket = m_socket_registers[sn];
	unsigned proto = socket[Sn_MR] & 0x0f;
	uint8_t &sr = socket[Sn_SR];

	// reset read/write pointers
	socket[Sn_RX_RD0] = 0;
	socket[Sn_RX_RD1] = 0;
	socket[Sn_RX_WR0] = 0;
	socket[Sn_RX_WR1] = 0;
	socket[Sn_RX_RSR0] = 0;
	socket[Sn_RX_RSR1] = 0;


	socket[Sn_TX_RD0] = 0;
	socket[Sn_TX_RD1] = 0;
	socket[Sn_TX_WR0] = 0;
	socket[Sn_TX_WR1] = 0;
	write16(socket + Sn_TX_FSR0, m_sockets[sn].tx_buffer_size);


	reset_socket_timers(sn);
	m_sockets[sn].reset();


	if (VERBOSE & LOG_COMMAND)
	{
		char extra[32];
		switch(proto)
		{
			case Sn_MR_IPRAW:
				snprintf(extra, sizeof(extra), "proto = %d", socket[Sn_PROTO]);
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

	uint16_t max_mss = 1472;

	switch (proto)
	{
		case Sn_MR_TCP:
			sr = Sn_SR_INIT;
			max_mss = 1460;
			break;
		case Sn_MR_UDP:
			sr = Sn_SR_UDP;
			max_mss = 1472;
			if (socket[Sn_MR] & Sn_MR_MULT)
				send_igmp(sn, true);
			break;
		case Sn_MR_IPRAW:
			max_mss = 1480;
			sr = Sn_SR_IPRAW;
			break;

		case Sn_MR_MACRAW:
			if (sn == 0)
			{
				sr = Sn_SR_MACRAW;
				max_mss = 1514;
				if ((socket[Sn_MR] & Sn_MR_MF) == 0)
					set_promisc(true);
			}
			else
				proto = 0;
			break;

		case Sn_MR_PPPoE: /* pppoe */
			#if 0
			if (sn == 0)
				sr = Sn_SR_PPPOE;
			#endif
			break;

		case Sn_MR_CLOSED: /* closed */
			break;

		default:
			proto = 0;
			break;
	}

	m_sockets[sn].proto = proto;
	if (m_device_type == dev_type::W5100S)
	{
		uint16_t rtr = read16(socket + Sn_RTR0 + 0x80);
		int rcr = socket[Sn_RCR + 0x80];

		if (!rtr) rtr = read16(m_common_registers + RTR0);
		write16(socket + Sn_RTR0, rtr);

		if (!rcr) rcr = m_common_registers[RCR];
		socket[Sn_RCR] = rcr;
	}

	uint16_t mss = read16(socket + Sn_MSSR0 + 0x80);
	if (mss == 0 || mss > max_mss) mss = max_mss;
	write16(socket + Sn_MSSR0, mss);
}

void w5100_base_device::socket_close(int sn)
{
	uint8_t *socket = m_socket_registers[sn];

	int proto = m_sockets[sn].proto;

	int mr = socket[Sn_MR];

	if (proto == Sn_MR_UDP && (mr & Sn_MR_MULT))
		send_igmp(sn, false);

	m_sockets[sn].proto = 0;
	socket[Sn_SR] = Sn_SR_CLOSED;
	reset_socket_timers(sn);
}


static void copy_from_tx(uint8_t *dest, const uint8_t *src, int length, int src_offset, int bank_size)
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

static void copy_to_rx(uint8_t *dest, const uint8_t *src, int length, int dest_offset, int bank_size)
{
	if (length > bank_size)
		length %= bank_size;

	int avail = bank_size - dest_offset;

	if (avail >= length)
		memcpy(dest + dest_offset, src, length);
	else
	{
		memcpy(dest + dest_offset, src, avail);
		memcpy(dest, src + avail, length - avail);
	}

}

void w5100_base_device::socket_send(int sn)
{
	unsigned proto = m_sockets[sn].proto;


	// if this is a UDP or IPRAW socket, possibly send an ARP
	// and perform send once resolved...

	if (proto == Sn_MR_UDP || proto == Sn_MR_IPRAW)
	{
		if (!socket_arp(sn)) return;
	}

	socket_send_common(sn);
}


void w5100_base_device::socket_send_mac(int sn)
{
	uint8_t *socket = m_socket_registers[sn];
	unsigned proto = m_sockets[sn].proto;

	if (proto == Sn_MR_UDP || proto == Sn_MR_IPRAW)
	{
		// update registers.
		for (int i = 0; i < 6; ++i)
			socket[Sn_DHAR0 + i] = socket[Sn_DHAR0 + i + 0x80];
		for (int i = 0; i < 4; ++i)
			socket[Sn_DIPR0 + i] = socket[Sn_DIPR0 + i + 0x80];

		socket[Sn_DPORT0] = socket[Sn_DPORT0 + 0x80];
		socket[Sn_DPORT1] = socket[Sn_DPORT1 + 0x80];

		m_sockets[sn].arp_ok = true;
	}

	socket_send_common(sn);
}

void w5100_base_device::socket_send_common(int sn)
{
	static const int BUFFER_SIZE = 1514;
	uint8_t buffer[BUFFER_SIZE];

	uint8_t *socket = m_socket_registers[sn];
	unsigned proto = m_sockets[sn].proto;

	// n.b -- on w5100s hardware, TX_WR and FSR are updated *before* ARP happens.
	// (yes, if the ARP fails, TX_WR and FSR are still updated.)
	// FSR is initially set to  buffer size - (write - read).  
	// while sending (or after ARP timeout) it is updated to a reasonable value
	// There is no special handling for invalid values, so size > buffer size will be sent.

	/* w5100: UDP w/ 0 size will lock up the socket. size > MSS will be split. */
	/* w5100s: UDP w/0 size will send 0-byte UDP packet */

	uint16_t read_ptr = read16(socket + Sn_TX_RD0);
	uint16_t write_ptr = read16(socket + Sn_TX_WR0 + 0x80);


	int tx_buffer_offset = m_sockets[sn].tx_buffer_offset;
	int tx_buffer_size = m_sockets[sn].tx_buffer_size;

	int mask = tx_buffer_size - 1;

	int size = (write_ptr - read_ptr) & 0xffff;
	// if (size < 0) size += tx_buffer_size;

	LOGMASKED(LOG_COMMAND, "Socket %d send write_ptr = 0x%04x read_ptr = 0x%04x size = %d\n",
		sn, write_ptr, read_ptr, size);


	if (proto == Sn_MR_TCP)
	{
		tcp_send(sn, false);
		return;
	}

	int header_size = proto_header_size(proto);
	int mss = read16(socket + Sn_MSSR0);


	if (proto == Sn_MR_UDP)
	{
		if (size == 0 && m_device_type == dev_type::W5100)
			return; // actual chip locks up and requires a reset.

		// UDP needs to be split into multiple chunks 
		while (size > mss)
		{
			int msize = std::min(size, mss);
			memset(buffer, 0, header_size);
			copy_from_tx(buffer + header_size, m_tx_buffer + tx_buffer_offset, msize, read_ptr & mask, tx_buffer_size);

			size -= msize;
			read_ptr += msize;

			build_udp_header(sn, buffer, msize);
			msize += header_size;
			dump_bytes(buffer, msize);
			send(buffer, msize);
		}

	}

	if (proto == Sn_MR_MACRAW || proto == Sn_MR_IPRAW || proto == Sn_MR_UDP)
	{
		// based on testing - packet dropped if > mss
		// but still sets the send ok irq.
		if (size <= mss)
		{
			memset(buffer, 0, header_size);
			copy_from_tx(buffer + header_size, m_tx_buffer + tx_buffer_offset, size, read_ptr & mask, tx_buffer_size);

			if (proto == Sn_MR_IPRAW)
				build_ipraw_header(sn, buffer, size);
			if (proto == Sn_MR_UDP)
				build_udp_header(sn, buffer, size);

			size += header_size;
			dump_bytes(buffer, size);
			send(buffer, size);
		}
	}

	// update registers.
	write16(socket + Sn_TX_RD0, write_ptr);
	write16(socket + Sn_TX_WR0, write_ptr);
	write16(socket + Sn_TX_FSR0, tx_buffer_size);

	socket[Sn_IR] |= Sn_IR_SEND_OK;
	update_ethernet_irq();
}

void w5100_base_device::socket_send_keep(int sn, bool from_timer)
{
	// manual keepalive.  ignored on w5100s if Sn_KPALVTR > 0

	const uint8_t *socket = m_socket_registers[sn];

	if (m_device_type == dev_type::W5100S && !from_timer && socket[Sn_KPALVTR])
		return;

	int sr = socket[Sn_SR];

	if (sr == Sn_SR_ESTABLISHED || sr == Sn_SR_CLOSE_WAIT)
	{
		auto snd_nxt = m_sockets[sn].snd_nxt;
		auto rcv_nxt = m_sockets[sn].rcv_nxt;
		tcp_send_segment(sn, TCP_ACK, snd_nxt - 1, rcv_nxt);
		if (!m_retry_timers[sn]->enabled())
			socket_repeat_timer(sn, TIMER_TCP_RESEND);
	}
}


void w5100_base_device::socket_connect(int sn, bool arp)
{
	// copy DIPR, DPORT

	if (arp && !socket_arp(sn))
		return;

	uint8_t *socket = m_socket_registers[sn];

	auto &sr = socket[Sn_SR];

	LOGMASKED(LOG_COMMAND, "Socket: %d: connect %s\n",
		sn, ip_to_string(read32(socket + Sn_DIPR0), read16(socket + Sn_DPORT0))
	);

	m_sockets[sn].reset_tcp();

	auto &iss = m_sockets[sn].iss;
	auto &snd_una = m_sockets[sn].snd_una;
	auto &snd_nxt = m_sockets[sn].snd_nxt;
	auto &rcv_wnd = m_sockets[sn].rcv_wnd;


	rcv_wnd = m_sockets[sn].rx_buffer_size;

	iss = 1;
	snd_una = iss;
	snd_nxt = iss + 1;

	// observed behavior.
	write16(socket + Sn_TX_RD0, snd_nxt);

	tcp_send_segment(sn, TCP_SYN, iss, 0);
	
	sr = Sn_SR_SYNSENT;

	socket_repeat_timer(sn, TIMER_TCP_RESEND);
}


void w5100_base_device::socket_disconnect(int sn)
{
	LOGMASKED(LOG_TCP, "Closing TCP socket %d\n", sn);

	// pp 60

	uint8_t *socket = m_socket_registers[sn];
	uint8_t &sr = socket[Sn_SR];

	auto &snd_nxt = m_sockets[sn].snd_nxt;
	const auto rcv_nxt = m_sockets[sn].rcv_nxt;
	const auto snd_una = m_sockets[sn].snd_una;
	switch(sr)
	{
		case Sn_SR_SYNSENT:
		case Sn_SR_SYNRECV:
			sr = Sn_SR_CLOSED;
			break;

		case Sn_SR_ESTABLISHED:
		case Sn_SR_CLOSE_WAIT:
			// send fin
			// TODO -- verify behavior when unsent / unacknowledge data in the tx buffer
			if (snd_nxt == snd_una && read16(socket + Sn_TX_RD0) == read16(socket + Sn_TX_WR0))
			{
				tcp_send_segment(sn, TCP_FIN|TCP_ACK, snd_nxt, rcv_nxt);
				snd_nxt++;
				sr++;
				socket_repeat_timer(sn, TIMER_TCP_RESEND);
			}
			else
				m_sockets[sn].fin_pending = true;

			break;

		default:
			return;
	}
}



/* based on testing, works even when socket is closed */
void w5100_base_device::socket_recv(int sn)
{
	uint8_t *socket = m_socket_registers[sn];

	uint16_t read_ptr = read16(socket + Sn_RX_RD0 + 0x80);
	uint16_t write_ptr = read16(socket + Sn_RX_WR0);

	uint16_t size = write_ptr - read_ptr;

	LOGMASKED(LOG_COMMAND, "Socket %d recv: write_ptr = 0x%04x read_ptr = 0x%04x prev read_ptr = 0x%04x remaining size = %d\n",
		sn, write_ptr, read_ptr, read16(socket + Sn_RX_RD0), size);


	// update Sn_RX_RD and Sn_RX_RSR
	write16(socket + Sn_RX_RD0, read_ptr);
	write16(socket + Sn_RX_RSR0, size);

	LOG("Socket %d: RSR: %d\n", sn, size);


	if (m_sockets[sn].proto == Sn_MR_TCP)
	{

		bool send_ack = false;

		int buffer_size = m_sockets[sn].rx_buffer_size;

		auto &rcv_wnd = m_sockets[sn].rcv_wnd;

		/*
		 * When Sn_MR_ND is 1 (no delay) all recv commands generate a window update ack
		 * When Sn_MR_ND is 0 (delay), window ack is only generated when the window size < mss
		 */
		if ((socket[Sn_MR] & Sn_MR_ND) || rcv_wnd < read16(socket + Sn_MSSR0))
			send_ack = true;

		rcv_wnd = buffer_size - size;

		if (send_ack)
		{
			m_delayed_ack_timers[sn]->enable(false);

			auto snd_nxt = m_sockets[sn].snd_nxt;
			auto rcv_nxt = m_sockets[sn].rcv_nxt;
			tcp_send_segment(sn, TCP_ACK, snd_nxt, rcv_nxt);
		}
	}

	if (size)
	{
		// re-trigger IRQ if there's still more data pending.
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

void w5100_base_device::recv_cb(u8 *buffer, int length)
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
	int local_port = 0;
	int remote_port = 0;
	uint32_t remote_ip = 0;
	int ip_header_length = 0;
	bool macraw = m_sockets[0].proto == Sn_MR_MACRAW;

	int mr2 = m_device_type == dev_type::W5100S ? m_common_registers[MR2] : 0;


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
	if (!memcmp(buffer, m_common_registers + SHAR0, 6)) is_unicast = true;

	// promiscuous packets only allowed for macraw socket.
	if (!is_unicast && !is_broadcast && !is_multicast)
	{
		int mr = m_socket_registers[0][Sn_MR];
		if (macraw && !(mr & Sn_MR_MF))
		{
			if (m_device_type == dev_type::W5100S)
			{
				int mr2 = m_socket_registers[0][Sn_MR2];
				if ((mr2 & Sn_MR2_MBBLK) && is_broadcast) return;
				if ((mr2 & Sn_MR2_MMBLK) && is_multicast) return;
				if ((mr2 & Sn_MR2_IPV6BLK) && ethertype == ETHERNET_TYPE_IPV6) return;
			}
			LOG("MACRAW matched (promiscuous)\n");
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
			remote_ip = read32(ip + o_IP_SRC_ADDRESS);

			if (ip_proto == IP_PROTOCOL_TCP)
			{
				is_tcp = true;
				local_port = read16(data + o_TCP_DEST_PORT);
				remote_port = read16(data + o_TCP_SRC_PORT);
			}
			if (ip_proto == IP_PROTOCOL_UDP)
			{
				is_udp = true;
				local_port = read16(data + o_UDP_DEST_PORT);
				remote_port = read16(data + o_UDP_SRC_PORT);
			}
			if (ip_proto == IP_PROTOCOL_IGMP)
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
		const uint8_t *socket = m_socket_registers[sn];
		int sr = socket[Sn_SR];
		int proto = m_sockets[sn].proto;

		int port = read16(socket + Sn_PORT0);

		if (sr == Sn_SR_INIT || sr == Sn_SR_CLOSED) continue;

		if (proto == Sn_MR_IPRAW && ip_proto == socket[Sn_PROTO])
		{
			LOG("IPRAW Matched %d\n", sn);
			receive(sn, buffer, length);
			return;
		}

		if (proto == Sn_MR_UDP)
		{
			dump_socket(sn);
			handle_udp = true;
			if (is_udp && local_port == port)
			{
				int mr = socket[Sn_MR];

				if (is_multicast && !(mr & Sn_MR_MULT)) return;

				if (m_device_type == dev_type::W5100S)
				{
					int mr2 = socket[Sn_MR2];
					if (is_broadcast && (mr2 & Sn_MR2_BRDB)) return;
					if (is_unicast && (mr & Sn_MR_MULT) && (mr2 & Sn_MR2_UNIB)) return;
				}
				LOG("UDP Matched %d\n", sn);
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
			dump_socket(sn);

			handle_tcp = true;
			if (is_tcp && local_port == port && is_unicast)
			{
				int sr = socket[Sn_SR];

				if (sr == Sn_SR_LISTEN)
				{
					LOG("TCP Matched (Listener) %d\n", sn);
					tcp_segment(sn, buffer, length);
					return;
				}
				if (remote_port == read16(socket + Sn_DPORT0) && remote_ip == read32(socket + Sn_DIPR0))
				{
					LOG("TCP Matched %d\n", sn);
					tcp_segment(sn, buffer, length);
					return;					
				}
			}
		}
	}


	if (ip_proto == IP_PROTOCOL_ICMP)
	{
		uint8_t *icmp = buffer + 14 + ip_header_length;
		int icmp_type = icmp[o_ICMP_TYPE];

		if (icmp_type == ICMP_DESTINATION_UNREACHABLE && icmp[o_ICMP_CODE] == 3 && icmp[8 + o_IP_PROTOCOL] == IP_PROTOCOL_UDP && is_unicast)
		{
			// an ICMP destination unreachable message from a UDP will
			// generate an unreachable interrupt and set unreachable ip/port registers.

			if (length < 14 + ip_header_length + 8 + 20) return;
			int ihl = (icmp[8 + o_IP_IHL] & 0x0f) << 2;
			if (length < 14 + ip_header_length + ihl + 8) return;

			memcpy(m_common_registers + UIPR0, icmp + 8 + o_IP_DEST_ADDRESS, 4); 
			memcpy(m_common_registers + UPORT0, icmp + 8 + ihl + o_UDP_DEST_PORT, 2);
			m_common_registers[IR] | IR_UNREACH;
			update_ethernet_irq();
		}

		// respond to ICMP ping
		if (icmp_type == ICMP_ECHO_REQUEST && (m_common_registers[MR] & MR_PB) == 0)
		{
			handle_icmp_request(buffer, length);
		}
		// socket-less ICMP ping response
		if (icmp_type == ICMP_ECHO_REPLY && m_device_type == dev_type::W5100S && m_sockets[4].command == SLCR_PING)
		{
			uint16_t id = read16(m_common_registers + PINGIDR0);
			uint16_t seq = read16(m_common_registers + PINGSEQR0);
			if (id == read16(icmp + 4) && seq == read16(icmp + 6))
			{
				m_common_registers[SLCR] = 0;
				m_sockets[4].command = 0;
				m_retry_timers[4]->enable(false);
				m_common_registers[SLIR] |= SLIR_PING;
				update_ethernet_irq();
			}
		}
	}

	// what if ipraw tcp / udp socket?
	// what if no active tcp/udp sockets?
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
			tcp_reset(buffer, length);
		}
		return;
	}

	/* if socket 0 is an open macraw socket, it can accept anything. */
	if (macraw)
	{
		if (m_device_type == dev_type::W5100S)
		{
			int mr2 = m_socket_registers[0][Sn_MR2];
			if ((mr2 & Sn_MR2_MBBLK) && is_broadcast) return;
			if ((mr2 & Sn_MR2_MMBLK) && is_multicast) return;
			if ((mr2 & Sn_MR2_IPV6BLK) && ethertype == ETHERNET_TYPE_IPV6) return;
		}
		LOG("MACRAW matched (last chance)\n");
		receive(0, buffer, length);
	}

}

/* store data into the receive buffer */
/* returns number of bytes stored (needed for TCP) */
int w5100_base_device::receive(int sn, const uint8_t *buffer, int length)
{

	LOG("Packet received for socket %d\n", sn);

	uint8_t *socket = m_socket_registers[sn];

	static const int MAX_HEADER_SIZE = 8;
	uint8_t header[MAX_HEADER_SIZE];

	int offset = 0;
	int header_size = 0;
	int ihl = 0;

	int rx_buffer_offset = m_sockets[sn].rx_buffer_offset;
	int rx_buffer_size = m_sockets[sn].rx_buffer_size;

	uint16_t write_ptr = read16(socket + Sn_RX_WR0);
	// uint16_t read_ptr = (socket[Sn_RX_RD0] << 8) | socket[Sn_RX_RD1];
	// int sr = socket[Sn_SR];
	int proto = m_sockets[sn].proto;

	int mask = rx_buffer_size - 1;

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

		case Sn_MR_TCP:
			offset = 0;
			header_size = 0;
			break;
	}

	// drop the packet if no room.
	// not implemented - W5100S with an invalid buffer size is treated as having a buffer size of 1.
	// (which is the final byte of the destination MAC address)

	// TODO -- will TCP store partial data?

	if (length + header_size <= 0) return 0;
	if (used <= rx_buffer_size && used + length + header_size > rx_buffer_size)
	{
		LOG("No room for data on socket %d (buffer size = %u used = %u length = %u\n",
			sn, rx_buffer_size, used, length + header_size);
		return 0;
	}

	if (header_size)
	{
		copy_to_rx(m_rx_buffer + rx_buffer_offset, header, header_size, write_ptr & mask, rx_buffer_size);
		write_ptr += header_size;
		used += header_size;
	}

	LOGMASKED(LOG_GENERAL, "Socket %d: receive %d bytes (write_ptr = 0x%04x)\n", sn, length, write_ptr);
	copy_to_rx(m_rx_buffer + rx_buffer_offset, buffer + offset, length, write_ptr & mask, rx_buffer_size);

	/* update pointers and available */
	write_ptr += length;
	used += length;

	LOG("used = %d\n", used);

	if (proto == Sn_MR_TCP)
		m_sockets[sn].rcv_wnd -= length;

	write16(socket + Sn_RX_WR0, write_ptr);
	write16(socket + Sn_RX_RSR0, used);

	socket[Sn_IR] |= Sn_IR_RECV;
	update_ethernet_irq();

	LOG("Socket %d: RSR: %d\n", sn, used);

	return header_size + length;
}



/* returns true if Sn_DHAR is valid, false (and ARP request sent) otherwise */
bool w5100_base_device::socket_arp(int sn)
{
	uint8_t *socket = m_socket_registers[sn];

	int proto = m_sockets[sn].proto;

	// update registers.
	for (int i = 0; i < 4; ++i)
		socket[Sn_DIPR0 + i] = socket[Sn_DIPR0 + i + 0x80];

	socket[Sn_DPORT0] = socket[Sn_DPORT0 + 0x80];
	socket[Sn_DPORT1] = socket[Sn_DPORT1 + 0x80];

	if (proto == Sn_MR_UDP && (socket[Sn_MR] & Sn_MR_MULT))
	{
		// use provided DHAR
		for (int i = 0; i < 6; ++i)
			socket[Sn_DHAR0 + i] = socket[Sn_DHAR0 + i + 0x80];

		m_sockets[sn].arp_ok = true;
		return true;
	}

	uint32_t dest = read32(socket + Sn_DIPR0);

	if (proto == Sn_MR_UDP || proto == Sn_MR_IPRAW)
	{
		uint32_t subnet = read32(m_common_registers + SUBR0);
		uint32_t ip = read32(m_common_registers + SIPR0);

		if (dest == 0xffffffff || dest == (ip | ~subnet))
		{
			/* broadcast ip address */
			memcpy(socket + Sn_DHAR0, ETHERNET_BROADCAST, 6);
			m_sockets[sn].arp_ip_address = dest;
			m_sockets[sn].arp_ok = true;
			return true;
		}
	}
	uint16_t rtr = read16(m_common_registers + RTR0);
	int rcr = m_common_registers[RCR];

	if (m_device_type == dev_type::W5100S)
	{
		rtr = read16(socket + Sn_RTR0);
		rcr = socket[Sn_RCR];

		if (proto == Sn_MR_UDP && (m_common_registers[MR2] & MR2_FARP))
			m_sockets[sn].arp_ok = false;
	}

	bool rv = ip_arp(sn, dest, rtr, rcr);
	// TODO - W5100S doesn't have SR_ARP status.
	if (!rv)
		socket[Sn_SR] = Sn_SR_ARP;

	return rv;
}


// used for socket + socket-less commands.
bool w5100_base_device::ip_arp(int sn, uint32_t dest, int rtr, int rcr)
{
	uint32_t gateway = read32(m_common_registers + GAR0);
	uint32_t subnet = read32(m_common_registers + SUBR0);
	uint32_t ip = read32(m_common_registers + SIPR0);


	if ((dest & subnet) != (ip & subnet) && (dest & ~subnet) != 0)
	{
		dest = gateway;
	}

	if (m_sockets[sn].arp_ok && m_sockets[sn].arp_ip_address == dest)
		return true;


	m_sockets[sn].arp_ip_address = dest;
	m_sockets[sn].arp_ok = false;
	m_sockets[sn].retry = rcr;

	/* Retry Timeout Register, 1 = 100us */
	if (!rtr) rtr = 1;
	attotime tm = attotime::from_usec(rtr * 100);
	m_retry_timers[sn]->adjust(tm, TIMER_ARP | sn, tm);

	send_arp_request(dest);
	return false;
}

void w5100_base_device::handle_arp_reply(const uint8_t *buffer, int length)
{
	/* if this is an ARP response, possibly update all the Sn_SR_ARP */
	/* keep a separate mac for the gateway instead of re-checking every time? */
	/* remove retry/timeout timers */
	/* queue up the send/synsent */
	/* if another device claims our MAC address, need to generate a CONFLICT interrupt */
	/* TODO - comparing IP is not correct when it's a gateway lookup */

	const uint8_t *arp = buffer + 14;

	uint32_t ip = read32(arp + o_ARP_SPA);

	LOGMASKED(LOG_ARP, "Received ARP reply for %s\n", ip_to_string(ip));

	if (m_device_type == dev_type::W5100S)
	{
		const int sn = 4;
		// socket-less ARP/PING
		if (m_sockets[sn].arp_ip_address == ip)
		{
			memcpy(m_common_registers + SLPHAR0, arp + o_ARP_SHA, 6);

			m_sockets[sn].arp_ok = true;
			if (m_sockets[sn].command == SLCR_ARP)
			{
				m_retry_timers[sn]->enable(false);
				m_common_registers[SLCR] = 0;
				m_common_registers[SLIR] |= SLIR_ARP;
				update_ethernet_irq();
			}
			else
			{
				m_retry_timers[sn]->set_param(TIMER_PING | sn);
				send_icmp_request();	
			}
		}
	}

	for (int sn = 0; sn < 4; ++sn)
	{
		uint8_t *socket = m_socket_registers[sn];
		uint8_t &sr = socket[Sn_SR];
		int proto = m_sockets[sn].proto;
		// TODO -- w5100s doesn't have a documented Sn_SR_ARP status.
		if (sr == Sn_SR_ARP)
		{
			if (m_sockets[sn].arp_ip_address == ip)
			{
				memcpy(socket + Sn_DHAR0, arp + o_ARP_SHA, 6);
				m_sockets[sn].arp_ok = true;
				m_retry_timers[sn]->enable(false);

				switch(proto)
				{
					case Sn_MR_IPRAW:
						sr = Sn_SR_IPRAW;
						socket_send_common(sn);
						break;
					case Sn_MR_UDP:
						sr = Sn_SR_UDP;
						socket_send_common(sn);
						break;
					case Sn_MR_TCP:
						sr = Sn_SR_INIT;
						socket_connect(sn, false);
						break;
				}
			}
		}
	}
}

void w5100_base_device::handle_arp_request(const uint8_t *buffer, int length)
{
	/* reply to (broadcast) request for our mac address */

	const uint8_t *arp = buffer + 14;

	if (memcmp(arp + o_ARP_TPA, m_common_registers + SIPR0, 4)) return;

	static const int MESSAGE_SIZE = 42;
	uint8_t message[MESSAGE_SIZE];

	// memset(message, 0, sizeof(message));

	memcpy(message, arp + o_ARP_SHA, 6);
	memcpy(message + 6, m_common_registers + SHAR0, 6);
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
	memcpy(message + 22, m_common_registers + SHAR0, 6); //sender mac
	memcpy(message + 28, m_common_registers + SIPR0, 4); // sender ip
	memcpy(message + 32, arp + o_ARP_SHA, 10); // dest mac + ip.

	LOGMASKED(LOG_ARP, "Replying to ARP request\n");
	send(message, MESSAGE_SIZE);
}


void w5100_base_device::send_arp_request(uint32_t ip)
{
	static const int MESSAGE_SIZE = 42;
	uint8_t message[MESSAGE_SIZE];

	// memset(message, 0, sizeof(message));

	memcpy(message, ETHERNET_BROADCAST, 6);
	memcpy(message + 6, m_common_registers + SHAR0, 6);
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
	memcpy(message + 22, m_common_registers + SHAR0, 6); //sender mac
	memcpy(message + 28, m_common_registers + SIPR0, 4); // sender ip
	memset(message + 32, 0, 6); // target mac
	// memcpy(message + 38, ip, 4); // target ip
	message[38] = ip >> 24;
	message[39] = ip >> 16;
	message[40] = ip >> 8;
	message[41] = ip >> 0;

	LOGMASKED(LOG_ARP, "Sending ARP request for %s\n", ip_to_string(ip));
	send(message, MESSAGE_SIZE);
}


/* build and send the IGMP join/leave message for multicast UDP socked */
// RFC 1112, Host Extensions for IP Multicasting
// RFC 2236, Internet Group Management Protocol, Version 2
// RFC 2113, IP Router Alert Option
void w5100_base_device::send_igmp(int sn, bool connect)
{
	static const int MESSAGE_SIZE = 46;
	uint8_t message[MESSAGE_SIZE];

	uint16_t crc;

	const uint8_t *socket = m_socket_registers[sn];

	const int igmpv = socket[Sn_MR] & Sn_MR_MC ? 1 : 2;

	// IGMP v1 doesn't have a leave message.
	if (!connect && igmpv == 1) return;

	memcpy(message, socket + Sn_DHAR0, 6);
	memcpy(message + 6, m_common_registers + SHAR0, 6);
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
	message[23] = IP_PROTOCOL_IGMP;
	message[24] = 0; // checksum...
	message[25] = 0;
	memcpy(message + 26, m_common_registers + SIPR0, 4); // source ip
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


void w5100_base_device::build_ipraw_header(int sn, uint8_t *buffer, int data_length)
{
	uint8_t *socket = m_socket_registers[sn];
	uint16_t fragment = read16(socket + Sn_FRAGR0);

	//ethernet header
	memcpy(buffer + 0, socket + Sn_DHAR0, 6);
	memcpy(buffer + 6, m_common_registers + SHAR0, 6);
	buffer[12] = ETHERNET_TYPE_IP >> 8;
	buffer[13] = ETHERNET_TYPE_IP;

	
	const int ip_header_length = 20;
	const int length = data_length + ip_header_length;
	++m_identification;

	uint8_t *ip_ptr = buffer + 14;

	// ip header
	ip_ptr[0] = 0x45; // IPv4, length = 5*4
	ip_ptr[1] = socket[Sn_TOS];
	write16(ip_ptr + 2, length); // total length
	write16(ip_ptr + 4, m_identification); // identification
	write16(ip_ptr + 6, fragment);
	ip_ptr[8] = socket[Sn_TTL];
	ip_ptr[9] = socket[Sn_PROTO];
	ip_ptr[10] = 0; // checksum...
	ip_ptr[11] = 0;
	memcpy(ip_ptr + 12, m_common_registers + SIPR0, 4); // source ip
	memcpy(ip_ptr + 16, socket + Sn_DIPR0, 4); // destination ip

	uint16_t crc = util::internet_checksum_creator::simple(ip_ptr, ip_header_length);
	write16(ip_ptr + o_IP_CHECKSUM, crc);
}

/* length includes the 42-byte ethernet/ip/udp header */
void w5100_base_device::build_udp_header(int sn, uint8_t *buffer, int data_length)
{
	uint8_t *socket = m_socket_registers[sn];
	uint16_t fragment = read16(socket + Sn_FRAGR0);

	//ethernet header
	memcpy(buffer + 0, socket + Sn_DHAR0, 6);
	memcpy(buffer + 6, m_common_registers + SHAR0, 6);
	buffer[12] = ETHERNET_TYPE_IP >> 8;
	buffer[13] = ETHERNET_TYPE_IP;

	const int ip_header_length = 20;
	const int udp_header_length = 8;
	const int length = data_length + ip_header_length + udp_header_length;

	++m_identification;

	uint8_t *ip_ptr = buffer + 14;
	uint8_t *udp_ptr = ip_ptr + 20;


	// ip header
	ip_ptr[0] = 0x45; // IPv4, length = 5*4
	ip_ptr[1] = socket[Sn_TOS];
	write16(ip_ptr + 2, length); // total length
	write16(ip_ptr + 4, m_identification); // identification
	write16(ip_ptr + 6, fragment);
	ip_ptr[8] = socket[Sn_TTL];
	ip_ptr[9] = IP_PROTOCOL_UDP;
	ip_ptr[10] = 0; // checksum...
	ip_ptr[11] = 0;
	memcpy(ip_ptr + 12, m_common_registers + SIPR0, 4); // source ip
	memcpy(ip_ptr + 16, socket + Sn_DIPR0, 4); // destination ip


	// udp header
	udp_ptr[0] = socket[Sn_PORT0]; // source port
	udp_ptr[1] = socket[Sn_PORT1];
	udp_ptr[2] = socket[Sn_DPORT0]; // dest port
	udp_ptr[3] = socket[Sn_DPORT1];
	write16(udp_ptr + 4, length - ip_header_length);
	udp_ptr[6] = 0; // checksum - optional
	udp_ptr[7] = 0;

	udp_checksum(ip_ptr, ip_header_length, udp_header_length + data_length);
}


void w5100_base_device::build_tcp_header(int sn, uint8_t *buffer, int data_length, int flags, uint32_t seq, uint32_t ack)
{
	uint8_t *socket = m_socket_registers[sn];
	uint16_t fragment = read16(socket + Sn_FRAGR0);

	const uint16_t rcv_wnd = m_sockets[sn].rcv_wnd;

	const bool is_syn = flags & TCP_SYN;
	// const int ethernet_header_length = 14;
	const int ip_header_length = 20;
	const int tcp_header_length = is_syn ? 24 : 20;

	int length = data_length + ip_header_length + tcp_header_length;
	++m_identification;

	//ethernet header
	memcpy(buffer + 0, socket + Sn_DHAR0, 6);
	memcpy(buffer + 6, m_common_registers + SHAR0, 6);
	write16(buffer + 12, ETHERNET_TYPE_IP);


	uint8_t *ip_ptr = buffer + 14;
	uint8_t *tcp_ptr = ip_ptr + 20;

	// ip header
	ip_ptr[0] = 0x45; // IPv4, length = 5*4
	ip_ptr[1] = socket[Sn_TOS];
	write16(ip_ptr + 2, length);
	write16(ip_ptr + 4, m_identification);
	write16(ip_ptr + 6, fragment);
	ip_ptr[8] = socket[Sn_TTL];
	ip_ptr[9] = IP_PROTOCOL_TCP;
	write16(ip_ptr + 10, 0); // checksum
	memcpy(ip_ptr + 12, m_common_registers + SIPR0, 4); // source ip
	memcpy(ip_ptr + 16, socket + Sn_DIPR0, 4); // destination ip


	// tcp header
	memcpy(tcp_ptr + 0, socket + Sn_PORT0, 2);
	memcpy(tcp_ptr + 2, socket + Sn_DPORT0, 2);
	write32(tcp_ptr + 4, seq);
	write32(tcp_ptr + 8, ack);
	tcp_ptr[12] = is_syn ? 0x60 : 0x50; // data offset
	tcp_ptr[13] = flags;
	write16(tcp_ptr + 14, rcv_wnd);
	write16(tcp_ptr + 16, 0); // checksum
	write16(tcp_ptr + 18, 0); // urgent ptr

	if (is_syn)
	{
		// MSS option always included for SYN.
		tcp_ptr[20] = 0x02; // kind = mss
		tcp_ptr[21] = 0x04; // length
		tcp_ptr[22] = socket[Sn_MSSR0];
		tcp_ptr[23] = socket[Sn_MSSR1];
	}

	tcp_checksum(ip_ptr, ip_header_length, tcp_header_length + data_length);
}

void w5100_base_device::handle_icmp_request(uint8_t *buffer, int length)
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

void w5100_base_device::send_icmp_unreachable(uint8_t *buffer, int length)
{

	uint16_t crc;
	uint8_t message[14 + 20 + 8 + 8 + 60]; // max ip header is 15 * 4 == 60

	int ihl = (buffer[14 + o_IP_IHL] & 0x0f) << 4;

	int new_length = 20 + 8 + ihl + 8;

	// ethernet header
	memcpy(message + o_ETHERNET_DEST , buffer + o_ETHERNET_SRC, 6);
	memcpy(message + o_ETHERNET_SRC, m_common_registers + SHAR0, 6);
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
	message[23] = IP_PROTOCOL_ICMP;
	message[24] = 0; // checksum...
	message[25] = 0;
	memcpy(buffer + 26, m_common_registers + SIPR0, 4); // source ip
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
void w5100_base_device::send_icmp_request()
{

	static const int MESSAGE_SIZE = 14 + 20 + 26;
	uint8_t message[MESSAGE_SIZE];

	uint16_t crc;

	memcpy(message + 0, m_common_registers + SLPHAR0, 6);
	memcpy(message + 6, m_common_registers + SHAR0, 6);
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
	message[23] = IP_PROTOCOL_ICMP;
	message[24] = 0; // checksum...
	message[25] = 0;
	memcpy(message + 26, m_common_registers + SIPR0, 4); // source ip
	memcpy(message + 30, m_common_registers + SLIPR0, 4); // destination ip

	// icmp header
	message[34] = ICMP_ECHO_REQUEST;
	message[35] = 0;
	message[36] = 0; // checksum
	message[37] = 0;
	message[38] = m_common_registers[PINGIDR0];
	message[39] = m_common_registers[PINGIDR1];
	message[40] = m_common_registers[PINGSEQR0];
	message[41] = m_common_registers[PINGSEQR1];
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



void w5100_base_device::dump_bytes(const uint8_t *buffer, int length)
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

[[maybe_unused]] void w5100_base_device::dump_socket(int sn)
{
	if (sn < 0 || sn > 4) return;
	const uint8_t *socket = m_socket_registers[sn];

	int proto = m_sockets[sn].proto;

	LOG("Socket %d\n", sn);
	LOG("MR: %02x\n", socket[Sn_MR]);
	LOG("SR: %02x - %s\n", socket[Sn_SR], sr_to_cstring(socket[Sn_SR]));
	LOG("IR: %02x\n", socket[Sn_IR]);

	if (proto == Sn_MR_UDP || proto == Sn_MR_TCP)
	{
		LOG("Remote IP: %s\n", ip_to_string(read32(socket + Sn_DIPR0), read16(socket +Sn_DPORT0)));
		LOG("Local Port: %u\n", read16(socket + Sn_PORT0));
	}
	if (proto == Sn_MR_IPRAW)
	{
		LOG("Proto: %d\n", socket[Sn_PROTO]);
	}

	if (proto)
	{
		LOG("TX Read: 0x%04x Write: 0x%04x FSR: %u\n",
			read16(socket + Sn_TX_RD0), read16(socket + Sn_TX_WR0), read16(socket + Sn_TX_FSR0));

		LOG("RX Read: 0x%04x Write: 0x%04x RSR: %u\n",
			read16(socket + Sn_RX_RD0), read16(socket + Sn_RX_WR0), read16(socket + Sn_RX_RSR0));

	}

	LOG("MSS: %u\n", read16(socket + Sn_MSSR0));
}

/* TCP functions */


void w5100_base_device::tcp_send(int sn, bool retransmit)
{
	static const int BUFFER_SIZE = 1514;
	uint8_t buffer[BUFFER_SIZE];

	uint8_t *socket = m_socket_registers[sn];

	const auto snd_una = m_sockets[sn].snd_una;
	auto &snd_nxt = m_sockets[sn].snd_nxt;
	const auto rcv_nxt = m_sockets[sn].rcv_nxt;
	// const auto rcv_wnd = m_sockets[sn].rcv_wnd;

	const bool force_psh = m_device_type == dev_type::W5100 || socket[Sn_MR2] & Sn_MR2_BRDB;


	uint16_t write_ptr = retransmit ? snd_nxt : read16(socket + Sn_TX_WR0 + 0x80);
	uint16_t read_ptr = retransmit ? snd_una : read16(socket + Sn_TX_RD0);

	int mss = read16(socket + Sn_MSSR0);


	int tx_buffer_offset = m_sockets[sn].tx_buffer_offset;
	int tx_buffer_size = m_sockets[sn].tx_buffer_size;

	int mask = tx_buffer_size - 1;


    //                    tx_rd .... tx_wr
	// | ................|...............|
	// snd_una ... snd_nxt

	uint32_t seq = retransmit ? snd_una : snd_nxt;
	// snd_una .... snd_nxt

	// int offset = seq & mask;
	int size = (write_ptr - seq) & 0xffff;
	if (!size) return;

	while (size)
	{
		int flags = TCP_ACK;
		if (size <= mss || force_psh)
			flags |= TCP_PSH;

		int msize = std::min(mss, size);

		copy_from_tx(buffer + 54, m_tx_buffer + tx_buffer_offset, msize, read_ptr & mask, tx_buffer_size);

		build_tcp_header(sn, buffer, msize, flags, seq, rcv_nxt);

		dump_bytes(buffer, msize + 54);
		send(buffer, msize + 54);


		size -= msize;
		seq += msize;
		read_ptr += msize;
	}

	if (!retransmit)
	{
		snd_nxt = seq;
		write16(socket + Sn_TX_RD0, write_ptr);
		write16(socket + Sn_TX_WR0, write_ptr);

		unsigned fsr = tx_buffer_size + snd_una - write_ptr;
		// int avail = (snd_nxt - snd_una) & mask;
		write16(socket + Sn_TX_FSR0, fsr);

		socket_repeat_timer(sn, TIMER_TCP_RESEND);
	}


}


// after 3-way handshake, tx rd/wr is set to snd_nxt & 0xffff.
// snd_nxt, snd_una

void w5100_base_device::tcp_send_segment(int sn, int flags, uint32_t seq, uint32_t ack)
{
	uint8_t *socket = m_socket_registers[sn];

	// const auto snd_up = m_sockets[sn].snd_up;
	const auto rcv_wnd = m_sockets[sn].rcv_wnd;

	static const int SEGMENT_SIZE = 60;
	uint8_t segment[SEGMENT_SIZE];

	uint8_t *ptr = segment;

	const bool is_syn = flags & TCP_SYN;
	const int length = is_syn ? 44 : 40;

	// ethernet header
	memcpy(ptr, socket + Sn_DHAR0, 6);
	memcpy(ptr + 6, m_common_registers + SHAR0, 6);
	write16(ptr + 12, ETHERNET_TYPE_IP);
	ptr += 14;

	++m_identification;

	// ip header
	ptr[0] = 0x45; // ipv4, length = 5*4
	ptr[1] = socket[Sn_TOS]; // TOS
	write16(ptr + 2, length); // length
	write16(ptr + 4, m_identification); // identification
	ptr[6] = 0x40; // flags - don't fragment
	ptr[7] = 0x00;
	ptr[8] = socket[Sn_TTL];
	ptr[9] = IP_PROTOCOL_TCP;
	write16(ptr + 10, 0); // checksum
	memcpy(ptr + 12, m_common_registers + SIPR0, 4);
	memcpy(ptr + 16, socket + Sn_DIPR0, 4);
	ptr += 20;

	// tcp header
	memcpy(ptr + 0, socket + Sn_PORT0, 2);
	memcpy(ptr + 2, socket + Sn_DPORT0, 2);
	write32(ptr + 4, seq);
	write32(ptr + 8, ack);
	ptr[12] = is_syn ? 0x60 : 0x50; // 4 * 5 bytes
	ptr[13] = flags;
	write16(ptr + 14, rcv_wnd);
	write16(ptr + 16, 0); // checksum
	write16(ptr + 18, 0); // urgent ptr
	// write16(ptr + 18, flags & TCP_URG ? snd_up : 0); // urgent ptr

	if (is_syn)
	{
		// MSS option always included for SYN.
		ptr[20] = 0x02; // kind = mss
		ptr[21] = 0x04; // length
		ptr[22] = socket[Sn_MSSR0];
		ptr[23] = socket[Sn_MSSR1];
	}


	memset(segment + length + 14, 0, SEGMENT_SIZE - length - 14);
	tcp_checksum(segment + 14, 20, is_syn ? 24 : 20);

	LOGMASKED(LOG_TCP, "Sending TCP segment seq=%u, ack=%u, flags=0x%02x\n", seq, ack, flags);
	dump_bytes(segment, SEGMENT_SIZE);

	send(segment, SEGMENT_SIZE);

	// TODO - w5100s - update keep alive timer.
}


/* RST a TCP packet.  ip address, port, mac take from buffer */
void w5100_base_device::tcp_reset(const uint8_t *buffer, int length)
{
	// pp 65

	static const int SEGMENT_SIZE = 60;
	uint8_t segment[SEGMENT_SIZE];

	uint8_t *ptr = segment;

	int ip_header_length = 0;
	int tcp_header_length = 0;
	int seg_len = 0;

	const uint8_t *ether_ptr = buffer;

	std::tie(ip_header_length, tcp_header_length, seg_len) = get_tcp_offsets(buffer);

	const uint8_t *ip_ptr = ether_ptr + 14;
	const uint8_t *tcp_ptr = ip_ptr + ip_header_length;

	int flags = tcp_ptr[o_TCP_FLAGS];

	if (flags & TCP_RST) return;

	// ethernet header
	memcpy(ptr + o_ETHERNET_DEST, ether_ptr + o_ETHERNET_SRC, 6);
	memcpy(ptr + o_ETHERNET_SRC, ether_ptr + o_ETHERNET_DEST, 6);
	write16(ptr + 12, ETHERNET_TYPE_IP);
	ptr += 14;

	m_identification++;

	// ip header
	ptr[0] = 0x45; // ipv4, length = 5*4
	ptr[1] = 0; // TOS
	write16(ptr + 2, 40); // length
	write16(ptr + 4, m_identification); // identification
	ptr[6] = 0x40; // flags - don't fragment
	ptr[7] = 0x00;
	ptr[8] = 0x80;
	ptr[9] = IP_PROTOCOL_TCP;
	write16(ptr + 10, 0); // checksum
	write32(ptr + 12, read32(ip_ptr + o_IP_DEST_ADDRESS));
	write32(ptr + 16, read32(ip_ptr + o_IP_SRC_ADDRESS));
	ptr += 20;

	// tcp header
	write16(ptr + 0, read16(tcp_ptr + o_TCP_DEST_PORT));
	write16(ptr + 2, read16(tcp_ptr + o_TCP_SRC_PORT));
	write32(ptr + 4, 0); // seq
	write32(ptr + 8, 0); // ack
	ptr[12] = 0x50; // 4 * 5 bytes
	ptr[13] = 0; // flags
	write16(ptr + 14, 0);
	write16(ptr + 16, 0); // checksum
	write16(ptr + 18, 0); // urgent ptr


	if (flags & TCP_ACK)
	{
		uint32_t seg_ack = read32(tcp_ptr + o_TCP_ACK_NUMBER);

		ptr[o_TCP_FLAGS] = TCP_RST;
		write16(ptr + o_TCP_SEQ_NUMBER, seg_ack);
		write16(ptr + o_TCP_ACK_NUMBER, 0);
	}
	else
	{
		uint32_t seg_seq = read32(tcp_ptr + o_TCP_SEQ_NUMBER);

		ptr[o_TCP_FLAGS] = TCP_RST | TCP_ACK;
		write16(ptr + o_TCP_SEQ_NUMBER, 0);
		write16(ptr + o_TCP_ACK_NUMBER, seg_seq + seg_len);
	}

	memset(segment + 54, 0, 6);
	tcp_checksum(segment + 14, 20, 20);

	LOGMASKED(LOG_TCP, "TCP: Sending RST\n");
	dump_bytes(segment, SEGMENT_SIZE);
	send(segment, SEGMENT_SIZE);
}

void w5100_base_device::reset_socket_timers(int sn)
{
	m_retry_timers[sn]->enable(false);
	m_keep_alive_timers[sn]->enable(false);
	m_delayed_ack_timers[sn]->enable(false);	
}

void w5100_base_device::tcp_disconnect(int sn, bool irq)
{
	uint8_t *socket = m_socket_registers[sn];
	socket[Sn_SR] = Sn_SR_CLOSED;

	reset_socket_timers(sn);

	if (irq)
	{
		socket[Sn_IR] |= Sn_IR_DISCON;
		update_ethernet_irq();
	}

}


//
// delayed ack - only applies with data segments? a re-transmission will trigger an immediate ack
//
// doesn't seem to be a 2msl timer.
void w5100_base_device::tcp_segment(int sn, const uint8_t *buffer, int length)
{

	int ip_header_length;
	int tcp_header_length;
	int seg_len;

	std::tie(ip_header_length, tcp_header_length, seg_len) = get_tcp_offsets(buffer);

	const uint8_t *ip_ptr = buffer + 14;
	const uint8_t *tcp_ptr = ip_ptr + ip_header_length;


	int flags = tcp_ptr[o_TCP_FLAGS];
	uint32_t seg_ack = flags & TCP_ACK ? read32(tcp_ptr + o_TCP_ACK_NUMBER) : 0;
	uint32_t seg_seq = read32(tcp_ptr + o_TCP_SEQ_NUMBER);
	// uint32_t seg_wnd = read16(tcp_ptr + o_TCP_WINDOW_SIZE);
	// uint32_t seg_up = flags & TCP_URG ? read16(tcp_ptr + o_TCP_URGENT) : 0;

	uint8_t *socket = m_socket_registers[sn];
	auto &sr = socket[Sn_SR];
	const auto mr = socket[Sn_MR];

	auto &rcv_nxt = m_sockets[sn].rcv_nxt;
	// auto &rcv_wnd = m_sockets[sn].rcv_wnd;
	auto &snd_nxt = m_sockets[sn].snd_nxt;
	auto &snd_una = m_sockets[sn].snd_una;
	auto &irs = m_sockets[sn].irs;
	auto &iss = m_sockets[sn].iss;
	auto &fin_pending = m_sockets[sn].fin_pending;

	LOGMASKED(LOG_TCP, "TCP Segment: %d (%s)\n", sn, sr_to_cstring(sr));
	LOGMASKED(LOG_TCP, "flags=%02x, ack=%u seq=%u length=%u\n", flags, seg_ack, seg_seq, seg_len);

	if (sr == Sn_SR_LISTEN)
	{
		// pp 65
		if (flags & TCP_RST) return;
		if (flags & TCP_ACK)
		{
			tcp_reset(buffer, length);
			return;
		}
		if (flags & TCP_SYN)
		{
			// parse_tcp_options(tcp_ptr + 20, tcp_header_length - 20);

			rcv_nxt = seg_seq + 1;
			irs = seg_seq;
			iss = 1;

			snd_nxt = iss + 1;
			snd_una = iss;

			write16(socket + Sn_TX_RD0, snd_nxt);
			write16(socket + Sn_TX_WR0, snd_nxt);
			write16(socket + Sn_DPORT0, read16(tcp_ptr + o_TCP_SRC_PORT));
			write32(socket + Sn_DIPR0, read32(ip_ptr + o_IP_SRC_ADDRESS));
			memcpy(socket + Sn_DHAR0, buffer + o_ETHERNET_SRC, 6);

			tcp_send_segment(sn, TCP_SYN|TCP_ACK, iss, rcv_nxt); // after variables set above.
			sr = Sn_SR_SYNRECV;
			socket_repeat_timer(sn, TIMER_TCP_RESEND);
			return;
		}
		return;
	}



	if (sr == Sn_SR_SYNSENT)
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

			if (!ack_valid_le_le(snd_una, seg_ack, snd_nxt))
			{
				if (flags & TCP_RST) return;
				tcp_send_segment(sn, TCP_RST, seg_ack, 0);
				return;
			}
		}
		if (flags & TCP_RST)
		{
			if (flags & TCP_ACK)
			{
				tcp_disconnect(sn, true);
				return;
			}
			return;
		}

		if (flags & TCP_SYN)
		{
			// data segments not supported until established.
			// parse_tcp_options(tcp_ptr + 20, tcp_header_length - 20);

			rcv_nxt = seg_seq + 1;
			irs = seg_seq;
			if (flags & TCP_ACK)
				snd_una = seg_ack;

			// If SND.UNA > ISS (our SYN has been ACKed)
			if (snd_una == snd_nxt)
			{
				// m_snd_wnd = seg_wnd;
				// m_snd_wl1 = seg_seq;
				// m_snd_wl2 = seg_ack;

				write16(socket + Sn_TX_WR0, snd_nxt);

				tcp_send_segment(sn, TCP_ACK, snd_nxt, rcv_nxt);
				sr = Sn_SR_ESTABLISHED;
				socket[Sn_IR] |= Sn_IR_CON;
				update_ethernet_irq();

				m_retry_timers[sn]->enable(false);
				if (m_device_type == dev_type::W5100S && socket[Sn_KPALVTR])
				{
					attotime tm = attotime::from_seconds(socket[Sn_KPALVTR] * 5);
					m_keep_alive_timers[sn]->adjust(tm, TIMER_TCP_KEEP_ALIVE, tm);
				}

			}
			else
			{
				tcp_send_segment(sn, TCP_SYN|TCP_ACK, iss, rcv_nxt);
				sr = Sn_SR_SYNRECV;
				socket_repeat_timer(sn, TIMER_TCP_RESEND);
				return;
			}

		}
		return;
	}



	// pp 69


	// sequence # check
	// TODO -- how are mis-ordered segments handled?

	// simplify to: seg_seq == rcv_nxt -- no out of order segments.

	bool seq_ok = false;
#if 0
	if (seg_len > 0 && rcv_wnd == 0)
	{
		// TODO -
		/* special allowance for ACKs, URGs, RST. */
	}

	switch (((seg_len > 0) << 1) | (rcv_wnd > 0))
	{
		case 0b00:
			seq_ok = seg_seq == rcv_nxt;
			break;
		case 0b01:
			seq_ok = ack_valid_le_lt(rcv_nxt, seg_seq, rcv_nxt + rcv_wnd);
			break;
		case 0b10:
			seq_ok = false;
			break;
		case 0b11:
			seq_ok = ack_valid_le_lt(rcv_nxt, seg_seq, rcv_nxt + rcv_wnd)
				|| ack_valid_le_lt(rcv_nxt, seg_seq + seg_len - 1, rcv_nxt + rcv_wnd);
	}
#endif

	seq_ok = seg_seq == rcv_nxt;

	if (!seq_ok)
	{
		if (flags & TCP_RST) return;
		tcp_send_segment(sn, TCP_ACK, snd_nxt, rcv_nxt);
		return;
	}

	if (flags & TCP_RST)
	{
		// pp 70
		switch(sr)
		{
			case Sn_SR_SYNRECV:
			case Sn_SR_ESTABLISHED:
			case Sn_SR_FIN_WAIT_1:
			case Sn_SR_FIN_WAIT_2:
			case Sn_SR_CLOSE_WAIT:
			case Sn_SR_CLOSING:
			case Sn_SR_LAST_ACK:
			case Sn_SR_TIME_WAIT:
				tcp_disconnect(sn, true);
				return;

			default:
				return;
		}
	}

	if (flags & TCP_SYN)
	{
		// pp 71

		tcp_send_segment(sn, TCP_RST, snd_nxt, 0);
		tcp_disconnect(sn, true);
		return;
	}

	if (!(flags & TCP_ACK)) return;

	int tcp_flags = 0;

	if (flags & TCP_ACK)
	{
		// todo - option to delay ack and/or include pending data.

		switch(sr)
		{
			case Sn_SR_SYNRECV:
				if (ack_valid_le_le(snd_una, seg_ack, snd_nxt))
				{
					// m_snd_wnd = seg_wnd;
					// m_snd_wl1 = seg_seq;
					// m_snd_wl2 = seg_ack;

					sr = Sn_SR_ESTABLISHED;
					socket[Sn_IR] |= Sn_IR_CON;
					update_ethernet_irq();
					// update_keep_alive();
				}
				else
				{
					tcp_send_segment(sn, TCP_RST, seg_ack, 0);
					return;
				}
				/* drop through */

			case Sn_SR_ESTABLISHED:
			case Sn_SR_FIN_WAIT_1:
			case Sn_SR_FIN_WAIT_2:
			case Sn_SR_CLOSE_WAIT:
			case Sn_SR_CLOSING:

				// pp 72

				if (ack_valid_lt_le(snd_una, seg_ack, snd_nxt))
				{
					int delta = static_cast<int32_t>(seg_ack - snd_una);

					snd_una = seg_ack;

					if (snd_una == snd_nxt && sr != Sn_SR_ESTABLISHED && sr != Sn_SR_CLOSE_WAIT)
					{
						// adjust for acknowledgement of FIN.
						delta--;
					}
					if (delta)
					{
						uint16_t fsr = read16(socket + Sn_TX_FSR0);
						fsr += delta;
						write16(socket + Sn_TX_FSR0, fsr);
						socket[Sn_IR] |= Sn_IR_SEND_OK;
						update_ethernet_irq();
					}
				}
				// seg.ack <= seg.una is a duplicate and can be ignored.
				// however that will be true from above and text processing still needs to happen.
				// if ((seq(seg_ack) <= m_snd_una)) ; // duplicate
				else if (ack_valid_gt(seg_ack, snd_nxt))
				{
					// ack for something not yet sent ; drop segment and return.
					tcp_send_segment(sn, TCP_ACK, snd_nxt, rcv_nxt);
					return;
				}


				if (snd_una == snd_nxt)
				{
					if (sr == Sn_SR_ESTABLISHED && fin_pending && read16(socket + Sn_TX_RD0) == read16(socket + Sn_TX_WR0))
					{
						tcp_flags |= TCP_FIN | TCP_ACK;
					}
					// fin-wait-1 -> go to fin-wait-2 if fin acknowledged.
					else if (sr == Sn_SR_FIN_WAIT_1)
					{
						sr = Sn_SR_FIN_WAIT_2;
					}
					// closing -> time-wait if fin acknowledged.
					else if (sr == Sn_SR_CLOSING)
					{
						sr = Sn_SR_TIME_WAIT;
					}
				}

				break;

			case Sn_SR_LAST_ACK:
				if (seg_ack == snd_nxt)
				{
					// if FIN acknowledged, go to closed state.
					// based on testing, triggers the disconnect irq.
					snd_una = seg_ack;
					tcp_disconnect(sn, true);
					return;
				}
				break;

			case Sn_SR_TIME_WAIT:
				//  re-transmit of remote FIN? acknowledge and restart timer.
				break;

			default:
				break;
		}

		if (snd_una == snd_nxt)
		{
			m_retry_timers[sn]->enable(false);
		}
	}
	else return; // no ack.


	// segment text
	if (seg_len)
	{
		int copied;
		// pp 74
		switch(sr)
		{
			case Sn_SR_ESTABLISHED:
			case Sn_SR_FIN_WAIT_1:
			case Sn_SR_FIN_WAIT_2:
				tcp_flags |= TCP_ACK;
				copied = receive(sn, tcp_ptr + tcp_header_length, seg_len);
				if (copied != seg_len)
				{
					seg_len = copied;
					flags &= ~TCP_FIN;
				}
				rcv_nxt += seg_len;
				break;
			case Sn_SR_CLOSE_WAIT:
			case Sn_SR_CLOSING:
			case Sn_SR_LAST_ACK:
			case Sn_SR_TIME_WAIT:
				break;
			default:
				break;
		}

	}

	if (flags & TCP_FIN)
	{
		// pp 75
		rcv_nxt += 1;
		tcp_flags |= TCP_ACK;

		// ack it .
		switch(sr)
		{
			case Sn_SR_SYNRECV:
			case Sn_SR_ESTABLISHED:
				sr = Sn_SR_CLOSE_WAIT;
				break;

			case Sn_SR_FIN_WAIT_1:
				sr = Sn_SR_CLOSING;
				break;

			case Sn_SR_FIN_WAIT_2:
				sr = Sn_SR_TIME_WAIT;
				break;

			case Sn_SR_CLOSE_WAIT:
			case Sn_SR_CLOSING:
			case Sn_SR_LAST_ACK:
				break;
			case Sn_SR_TIME_WAIT:
				break;

			default: break;
		}
	}

	// delayed ack handling:
	// if this is a data segment and ND == 0, wait RTR to ack
	// exceptions: if delay timer already active, cancel and send immediate ack.
	// if this is a FIN, don't delay

	if (seg_len && tcp_flags == TCP_ACK && (mr & Sn_MR_ND) == 0)
	{
		auto t = m_delayed_ack_timers[sn];
		if (!t->enabled())
		{
			int rtr = m_device_type == dev_type::W5100S ? read16(socket + Sn_RTR0) : read16(m_common_registers + RTR0);
			if (!rtr) rtr = 1;
			attotime tm = attotime::from_usec(rtr * 100);
			t->reset(tm);
			return;
		}
	}

	if (tcp_flags)
	{
		m_delayed_ack_timers[sn]->enable(false);
		tcp_send_segment(sn, tcp_flags, snd_nxt, rcv_nxt);
		if (tcp_flags & TCP_FIN)
		{
			snd_nxt++;
			fin_pending = false;

			sr = sr == Sn_SR_ESTABLISHED ? Sn_SR_FIN_WAIT_1 : Sn_SR_LAST_ACK;
			socket_repeat_timer(sn, TIMER_TCP_RESEND);
		}
	}


}



w5100_device::w5100_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock)
	: w5100_base_device(mconfig, W5100, tag, owner, clock, dev_type::W5100)
{
}

w5100s_device::w5100s_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock)
	: w5100_base_device(mconfig, W5100S, tag, owner, clock, dev_type::W5100S)
{
}



DEFINE_DEVICE_TYPE(W5100, w5100_device, "w5100", "WIZnet W5100 Ethernet Controller")
DEFINE_DEVICE_TYPE(W5100S, w5100s_device, "w5100s", "WIZnet W5100s Ethernet Controller")
