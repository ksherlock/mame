// license:BSD-3-Clause
// copyright-holders: Kelvin Sherlock


/*
	WIZnet W5100 / W5100S

	Used in: Uthernet II (Apple II), Spectranet (ZX Spectrum)

	Based on:
	W5100, W5100S, W5200, W5500 datasheets
	WIZnet ioLibrary Driver (https://github.com/Wiznet/ioLibrary_Driver)
	https://docs.wiznet.io/Product/iEthernet/W5100/
	Uthernet II User's and Programmer's Manual
	Testing with Uthernet II and W5100S-EVB-Pico

	0x0000-0x00ff - common registers
	0x0100-0x03ff - reserved
	0x0400-0x07ff - socket registers
	0x0800-0x3fff - reserved
	0x4000-0x5fff - tx memory
	0x6000-0x7fff - rx memory

	"reserved" memory mirrors the common/socket registers, i.e.:
	x000-x3ff, x800-xbff are common registers,
    x400-x7ff, xb00-xfff are socket registers.
    on the w5100, all undocumented socket registers mirror socket register 3.


 */

/*
	Not supported:
	- anything PPPoE related
	- w5100s PHY, etc

*/

#include "emu.h"
#include "machine/w5100.h"
#include "util/internet_checksum.h"

// #define LOG_GENERAL (1U << 0)
#define LOG_COMMAND (1U << 1)
#define LOG_FILTER  (1U << 2)
#define LOG_PACKETS (1U << 3)
#define LOG_ARP     (1U << 4)
#define LOG_WRITE   (1U << 5)
#define LOG_TCP     (1U << 6)
#define LOG_SR      (1U << 7)
#define LOG_ICMP    (1U << 8)

#define VERBOSE (LOG_GENERAL|LOG_COMMAND|LOG_FILTER|LOG_PACKETS|LOG_ARP|LOG_TCP|LOG_SR|LOG_ICMP)
#include "logmacro.h"

ALLOW_SAVE_TYPE(util::tcp_sequence)

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
	o_TCP_CHECKSUM = 16,
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


static const int MAX_FRAME_SIZE = 1514;
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
		if (util::internet_checksum_creator::simple(data, length)) return false;
	}
	else if (proto == IP_PROTOCOL_UDP)
	{
		if (length < read16(data + o_UDP_LENGTH)) return false;

		uint16_t crc = read16(data + o_UDP_CHECKSUM);
		if (crc)
		{
			uint8_t pseudo_header[12];
			memcpy(pseudo_header + 0, ip + o_IP_SRC_ADDRESS, 4);
			memcpy(pseudo_header + 4, ip + o_IP_DEST_ADDRESS, 4);
			write16(pseudo_header + 8, IP_PROTOCOL_UDP);
			write16(pseudo_header + 10, length);

			util::internet_checksum_creator cr;
			cr.append(pseudo_header, sizeof(pseudo_header));
			cr.append(data, length);
			if (cr.finish() != 0) return false;
		}
	}
	else if (proto == IP_PROTOCOL_TCP)
	{
		if (length < 20) return false;

		int offset = (data[o_TCP_DATA_OFFSET] >> 4) << 2;
		if (offset < 20) return false;
		if (length < offset) return false;

		uint8_t pseudo_header[12];
		memcpy(pseudo_header + 0, ip + o_IP_SRC_ADDRESS, 4);
		memcpy(pseudo_header + 4, ip + o_IP_DEST_ADDRESS, 4);
		write16(pseudo_header + 8, IP_PROTOCOL_TCP);
		write16(pseudo_header + 10, length);

		util::internet_checksum_creator cr;
		cr.append(pseudo_header, sizeof(pseudo_header));
		cr.append(data, length);
		if (cr.finish() != 0) return false;
	}

	return ihl;
}

inline unsigned read_ihl(const uint8_t *buffer)
{
	return (buffer[14 + o_IP_IHL] & 0x0f) << 2;
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


static uint16_t udp_tcp_checksum(unsigned proto, const uint8_t *ip_ptr, const uint8_t *data, unsigned length)
{
	uint8_t pseudo_header[12];

	util::internet_checksum_creator cc;

	memcpy(pseudo_header + 0, ip_ptr + o_IP_SRC_ADDRESS, 4);
	memcpy(pseudo_header + 4, ip_ptr + o_IP_DEST_ADDRESS, 4);
	write16(pseudo_header + 8, proto);
	write16(pseudo_header + 10, length);

	cc.append(pseudo_header, sizeof(pseudo_header));
	cc.append(data, length);

	return cc.finish();
}

#if 0
/* tcp sequence comparisons. */
// a <= b <= c
[[maybe_unused]] inline static bool ack_valid_le_le(uint32_t a, uint32_t b, uint32_t c)
{
	if (a <= c) return (a <= b) && (b <= c);
	return (a <= b) || (b <= c);
}

// a <= b < c
[[maybe_unused]] inline static bool ack_valid_le_lt(uint32_t a, uint32_t b, uint32_t c)
{
	if (a < c) return (a <= b) && (b < c);
	return (a <= b) || (b < c);

}

// a < b <= c
[[maybe_unused]] inline static bool ack_valid_lt_le(uint32_t a, uint32_t b, uint32_t c)
{
	if (a < c) return (a < b) && (b <= c);
	return (a < b) || (b <= c);
}

// a > b
[[maybe_unused]] inline static bool ack_valid_gt(uint32_t a, uint32_t b)
{
	return static_cast<int32_t>(a - b) > 0;
}

// a >= b
[[maybe_unused]] inline static bool ack_valid_ge(uint32_t a, uint32_t b)
{
	return static_cast<int32_t>(a - b) >= 0;
}

// a < b
[[maybe_unused]] inline static bool ack_valid_lt(uint32_t a, uint32_t b)
{
	return static_cast<int32_t>(a - b) < 0;
}

// a <= b
[[maybe_unused]] inline static bool ack_valid_le(uint32_t a, uint32_t b)
{
	return static_cast<int32_t>(a - b) <= 0;
}
#endif

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
		case Sn_SR_FIN_WAIT: return "SR_FIN_WAIT";
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

[[maybe_unused]] static std::string tcp_flags_to_string(int flags)
{
	std::string rv;

	if (flags & TCP_FIN) rv += "FIN, ";
	if (flags & TCP_SYN) rv += "SYN, ";
	if (flags & TCP_RST) rv += "RST, ";
	if (flags & TCP_PSH) rv += "PSH, ";
	if (flags & TCP_ACK) rv += "ACK, ";
	if (flags & TCP_URG) rv += "URG, ";
	if (flags & TCP_ECE) rv += "ECE, ";
	if (flags & TCP_CWR) rv += "CWR, ";

	if (rv.size()) rv.resize(rv.size() - 2);
	return rv;
}


[[maybe_unused]] static std::string ip_to_string(uint32_t ip, uint16_t port)
{
	char buffer[sizeof("255.255.255.255:65535")];
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
	char buffer[sizeof("255.255.255.255")];
	snprintf(buffer, sizeof(buffer), "%d.%d.%d.%d",
		(ip >> 24) & 0xff,
		(ip >> 16) & 0xff,
		(ip >> 8) & 0xff,
		(ip >> 0) & 0xff
	);
	return buffer;
}



struct w5100_base_device::ip_info
{
	ip_info() = default;
	ip_info(const ip_info &) = default;

	void from_frame(const uint8_t *frame)
	{
		memcpy(dst_mac, frame + o_ETHERNET_SRC, 6);
		memcpy(dst_ip, frame + 14 + o_IP_SRC_ADDRESS, 4);
		proto = frame[14 + o_IP_PROTOCOL];
	}

	void from_socket(const uint8_t *socket)
	{
		switch (socket[Sn_MR] & 0x0f)
		{
			case Sn_MR_UDP:
				proto = IP_PROTOCOL_UDP;
				break;
			case Sn_MR_TCP:
				proto = IP_PROTOCOL_TCP;
				break;
			case Sn_MR_IPRAW:
			default:
				proto = socket[Sn_PROTO];
		}
		fragment = read16(socket + Sn_FRAGR0);
		ttl = socket[Sn_TTL];
		tos = socket[Sn_TOS];
		memcpy(dst_ip, socket + Sn_DIPR0, 4);
		memcpy(dst_mac, socket + Sn_DHAR0, 6);
	}

	ip_info &operator=(const ip_info &) = default;

	uint16_t fragment = 0x4000;
	uint8_t proto = 0;
	uint8_t ttl = 128;
	uint8_t tos = 0;
	uint8_t dst_mac[6] = {};
	uint8_t dst_ip[4] = {};
};


w5100_base_device::w5100_base_device(const machine_config &mconfig, device_type type, const char *tag, device_t *owner, uint32_t clock, dev_type device_type)
	: device_t(mconfig, type, tag, owner, clock)
	, device_network_interface(mconfig, *this, 10)
	, device_memory_interface(mconfig, *this)
	, m_device_type(device_type)
	, m_irq_handler(*this)
	, m_address_space_config("memory", ENDIANNESS_BIG, 8, 15, 0, address_map_constructor())
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

	save_pointer(STRUCT_MEMBER(m_tcp, snd_una), 4);
	save_pointer(STRUCT_MEMBER(m_tcp, snd_nxt), 4);
	save_pointer(STRUCT_MEMBER(m_tcp, rcv_nxt), 4);

	save_pointer(STRUCT_MEMBER(m_tcp, irs), 4);
	save_pointer(STRUCT_MEMBER(m_tcp, iss), 4);

	save_pointer(STRUCT_MEMBER(m_tcp, snd_wl1), 4);
	save_pointer(STRUCT_MEMBER(m_tcp, snd_wl2), 4);

	save_pointer(STRUCT_MEMBER(m_tcp, resend_seq), 4);

	save_pointer(STRUCT_MEMBER(m_tcp, snd_wnd), 4);
	save_pointer(STRUCT_MEMBER(m_tcp, rcv_wnd), 4);


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

	m_address_space = &space(AS_PROGRAM);

	m_address_space->install_rom(0x0000, 0x00ff, 0x3f00, m_common_registers);
	m_address_space->install_write_handler(0x0000, 0x00ff, 0, 0x3f00, 0, write8sm_delegate(*this, FUNC(w5100_base_device::write_common_register)));

	if (m_device_type == dev_type::W5100S)
	{
		// m_address_space->install_rom(0x0400, 0x07ff, 0x3800, m_socket_registers);
		m_address_space->install_read_handler(0x0400, 0x07ff, 0, 0x3800, 0, read8sm_delegate(*this, FUNC(w5100_base_device::read_socket_register)));
		m_address_space->install_write_handler(0x0400, 0x07ff, 0, 0x3800, 0, write8sm_delegate(*this, FUNC(w5100_base_device::write_socket_register)));
	}
	else
	{
		// on the w5100, socket 3 is mirrored.
		m_address_space->install_read_handler(0x0400, 0x04ff, 0x00ff, 0x3800, 0, read8sm_delegate(*this, FUNC(w5100_base_device::read_socket_register_3)));
		m_address_space->install_write_handler(0x0400, 0x04ff, 0x00ff, 0x3800, 0, write8sm_delegate(*this, FUNC(w5100_base_device::write_socket_register_3)));

		m_address_space->install_read_handler(0x0400, 0x07ff, 0, 0x0000, 0, read8sm_delegate(*this, FUNC(w5100_base_device::read_socket_register)));
		m_address_space->install_write_handler(0x0400, 0x07ff, 0, 0x0000, 0, write8sm_delegate(*this, FUNC(w5100_base_device::write_socket_register)));


	}
	m_address_space->install_ram(0x4000, 0x5fff, 0x0000, m_tx_buffer);
	m_address_space->install_ram(0x6000, 0x7fff, 0x0000, m_rx_buffer);
}

device_memory_interface::space_config_vector w5100_base_device::memory_space_config() const
{
	return space_config_vector {
		std::make_pair(AS_PROGRAM, &m_address_space_config)
	};
}

void w5100_base_device::device_add_mconfig(machine_config &config)
{
}


void w5100_base_device::device_reset()
{
	m_idm = 0;

	memset(m_common_registers, 0, sizeof(m_common_registers));
	memset(m_socket_registers, 0, sizeof(m_socket_registers));

	memset(m_sockets, 0, sizeof(m_sockets));

	// tx/rx buffers not cleared on reset.

	while (!m_queue.empty())
		m_queue.pop();

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

		if (m_device_type == dev_type::W5100S)
		{
			socket[Sn_IMR] = 0xff;
		}

		m_sockets[sn].reset();
		m_tcp[sn].reset();
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


// param & 0xff = socket, 4 = socket less command
static const int kSLSocket = 4;
enum
{
	TIMER_ARP = 0x0100,
	TIMER_PING = 0x0200,
	TIMER_TCP_RESEND = 0x0300,
};


void w5100_base_device::read_timeout_registers(int sn, unsigned &rcr, unsigned &rtr)
{
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

}
void w5100_base_device::socket_repeat_timer(int sn, int param)
{
	// arp/ping timer.
	unsigned rcr;
	unsigned rtr;

	read_timeout_registers(sn, rcr, rtr);

	attotime tm = attotime::from_usec(rtr * 100);

	m_sockets[sn].rcr = rcr;
	m_sockets[sn].rtr = rtr;

	m_retry_timers[sn]->adjust(tm, param | sn, tm);
}

void w5100_base_device::socket_tcp_timer(int sn,bool requeue)
{
	// tcp resend uses a back off so they are one-shot and updated when done.
	unsigned rcr;
	unsigned rtr;

	if (requeue)
	{
		rtr = m_sockets[sn].rtr;
		if (rtr < 0x8000)
		{
			rtr *= 2;
			m_sockets[sn].rtr = rtr;
		}
	}
	else
	{
		read_timeout_registers(sn, rcr, rtr);

		m_sockets[sn].rcr = rcr;
		m_sockets[sn].rtr = rtr;
	}

	m_tcp[sn].resend_seq = m_tcp[sn].snd_una;

	attotime tm = attotime::from_usec(rtr * 100);
	m_retry_timers[sn]->adjust(tm, TIMER_TCP_RESEND | sn);
}


TIMER_CALLBACK_MEMBER(w5100_base_device::retry_timer)
{
	// used for ARP, PING, and tcp resend, and tcp keep alives.
	int sn = param & 0xff;
	int cmd = param & 0xff00;

	bool timeout = false;
	if (--m_sockets[sn].rcr < 0)
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

			m_sockets[sn].arp_in_progress = false;
			if (sn == kSLSocket)
			{
				m_common_registers[SLIR] |= SLIR_TIMEOUT;
			}
			else
			{
				uint8_t *socket = m_socket_registers[sn];
				int proto = m_sockets[sn].proto;
				uint8_t &sr = socket[Sn_SR];

				if (proto == Sn_MR_UDP || proto == Sn_MR_IPRAW)
				{
					// UDP / IPRAW update tx_rd and tx_fsr at this point.
					uint16_t write_ptr = read16(socket + Sn_TX_WR0);
					write16(socket + Sn_TX_RD0, write_ptr);
					write16(socket + Sn_TX_FSR0, m_sockets[sn].tx_buffer_size);
				}

				switch(proto)
				{
					case Sn_MR_UDP:
						sr = Sn_SR_UDP;
						LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(sr));
						break;
					case Sn_MR_IPRAW:
						sr = Sn_SR_IPRAW;
						LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(sr));
						break;
					case Sn_MR_TCP:
						socket_close(sn);
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
		if (sn == kSLSocket)
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


	if (cmd == TIMER_TCP_RESEND)
	{
		uint8_t *socket = m_socket_registers[sn];
		int sr = socket[Sn_SR];

		if (timeout)
		{
			LOGMASKED(LOG_TCP, "TCP Resend Timeout %d\n", sn);

			socket_close(sn, Sn_IR_TIMEOUT);
			return;
		}
		LOGMASKED(LOG_TCP, "TCP Resend Timer %d\n", sn);

		const auto iss = m_tcp[sn].iss;
		const auto snd_nxt = m_tcp[sn].snd_nxt;
		const auto rcv_nxt = m_tcp[sn].rcv_nxt;

		bool requeue = false;

		switch(sr)
		{
			case Sn_SR_SYNSENT:
				tcp_send_segment(sn, TCP_SYN, iss, 0);
				requeue = true;
				break;

			case Sn_SR_SYNRECV:
				tcp_send_segment(sn, TCP_ACK | TCP_SYN, iss, rcv_nxt);
				requeue = true;
				break;

			case Sn_SR_ESTABLISHED:
			case Sn_SR_CLOSE_WAIT:
			case Sn_SR_FIN_WAIT:
				if (busy())
					m_sockets[sn].resend_in_progress = true;
				else
					tcp_send(sn, true);
				break;

			case Sn_SR_LAST_ACK:
				tcp_send_segment(sn, TCP_FIN | TCP_ACK, snd_nxt - 1, rcv_nxt);
				requeue = true;
				break;
		}

		if (requeue)
			socket_tcp_timer(sn, true);

		return;
	}

}

TIMER_CALLBACK_MEMBER(w5100_base_device::keep_alive_timer)
{
	// w5100s keep-alive timer
	int sn = param;
	LOGMASKED(LOG_TCP, "TCP: %d - keep alive timer\n", sn);
	tcp_send_keep(sn, false);
}

TIMER_CALLBACK_MEMBER(w5100_base_device::delayed_ack_timer)
{
	int sn = param;

	auto snd_nxt = m_tcp[sn].snd_nxt;
	auto rcv_nxt = m_tcp[sn].rcv_nxt;
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

	return m_address_space->read_byte(offset);
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

	m_address_space->write_byte(offset, data);
}

uint8_t w5100_base_device::read_socket_register_3(offs_t offset) const
{
	return read_socket_register(0x0300 | (offset & 0xff));
}


uint8_t w5100_base_device::read_socket_register(offs_t offset) const
{
	int sn = offset >> 8;
	offset &= 0xff;
	if (offset >= 0x80) return 0x00;

	return m_socket_registers[sn][offset];
}

void w5100_base_device::write_socket_register_3(offs_t offset, uint8_t data)
{
	write_socket_register(0x0300 | (offset & 0xff), data);
}

void w5100_base_device::write_socket_register(offs_t offset, uint8_t data)
{
	const bool W5100S = m_device_type == dev_type::W5100S;

	int sn = offset >> 8;
	offset &= 0xff;

	uint8_t *socket = m_socket_registers[sn];

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
					m_keep_alive_timers[sn]->adjust(tm, sn, tm);
				}
			}
			break;

		default:
			/* read-only */
			break;
	}

}

void w5100_base_device::write_common_register(offs_t offset, uint8_t data)
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
			for (int sn = 0; sn < 5; ++sn)
				m_sockets[sn].arp_valid = false;
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
				m_common_registers[offset] = data;
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
			read_ptr = (uint32_t)m_tcp[sn].snd_una;

		unsigned fsr = size + read_ptr - write_ptr;
		write16(socket + Sn_TX_FSR0, fsr);
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
			read_ptr = (uint32_t)m_tcp[sn].snd_una;

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
			m_sockets[kSLSocket].command = command;
			m_sockets[kSLSocket].arp_valid = false;
			ip_arp(kSLSocket, read32(m_common_registers + SLIPR0), read16(m_common_registers + SLRTR0), m_common_registers[SLRCR]);
			break;

		default:
			LOGMASKED(LOG_COMMAND, "Socket-Less Unknown command (0x%02x)\n", command);
			break;

	}

}


void w5100_base_device::socket_command(int sn, int command)
{
	if (sn < 0 || sn > 3) return;

	const uint8_t *socket = m_socket_registers[sn];
	const uint8_t sr = socket[Sn_SR];
	const uint8_t mr = socket[Sn_MR];

	switch(command)
	{
		case Sn_CR_OPEN:
			LOGMASKED(LOG_COMMAND, "Socket: %d: open\n", sn);
			socket_open(sn);
			break;

		case Sn_CR_LISTEN:
			LOGMASKED(LOG_COMMAND, "Socket: %d: listen\n", sn);
			if (sr == Sn_SR_INIT)
				socket_listen(sn);
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

	switch(proto)
	{
		case Sn_MR_TCP:
			sr = Sn_SR_INIT;
			LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(sr));
			max_mss = 1460;
			break;

		case Sn_MR_UDP:
			sr = Sn_SR_UDP;
			LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(sr));
			max_mss = 1472;
			if (socket[Sn_MR] & Sn_MR_MULT)
				send_igmp(sn, true);
			break;

		case Sn_MR_IPRAW:
			sr = Sn_SR_IPRAW;
			LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(sr));
			max_mss = 1480;
			break;

		case Sn_MR_MACRAW:
			if (sn == 0)
			{
				sr = Sn_SR_MACRAW;
				LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(sr));
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
		// set the retry/timeout registers
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

void w5100_base_device::socket_close(int sn, unsigned irqs)
{
	uint8_t *socket = m_socket_registers[sn];
	int mr = socket[Sn_MR];
	int proto = m_sockets[sn].proto;

	if (proto == Sn_MR_UDP && (mr & Sn_MR_MULT))
		send_igmp(sn, false);

	reset_socket_timers(sn);
	m_sockets[sn].reset();
	socket[Sn_SR] = Sn_SR_CLOSED;
	LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(Sn_SR_CLOSED));

	if (irqs)
	{
		socket[Sn_IR] |= irqs;
		update_ethernet_irq();
	}
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


/*
  Send / Send mac:

  All:
  FSR + TX_WR are updated immediately

  if ARP timeout:
  FSR, TX_RD are updated
  Sn_IR_TIMEOUT generated

  UDP/MACRAW/IPRAW (assuming no ARP timeout):
  FSR, TX_RD are updated as the data is sent.
  Sn_IR_SENDOK geneated after all data is sent

  TCP:
  TX_RD updated after data is sent or peer window is full
  Sn_IR_SENDOK after data is sent or peer window is full

  FSR updated as data is acked.

  UDP and TCP will split data if > MSS ; MACRAW/IPRAW will drop it.

 */
void w5100_base_device::socket_send(int sn)
{
	uint8_t *socket = m_socket_registers[sn];
	unsigned proto = m_sockets[sn].proto;


	uint16_t read_ptr = read16(socket + Sn_TX_RD0);
	uint16_t write_ptr = read16(socket + Sn_TX_WR0 + 0x80);

	unsigned size = m_sockets[sn].tx_buffer_size;

	if (proto == Sn_MR_TCP)
		read_ptr = (uint32_t)m_tcp[sn].snd_una;

	unsigned fsr = size + read_ptr - write_ptr;

	write16(socket + Sn_TX_WR0, write_ptr);
	write16(socket + Sn_TX_FSR0, fsr);


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

	uint16_t read_ptr = read16(socket + Sn_TX_RD0);
	uint16_t write_ptr = read16(socket + Sn_TX_WR0 + 0x80);
	unsigned fsr = m_sockets[sn].tx_buffer_size + read_ptr - write_ptr;

	write16(socket + Sn_TX_WR0, write_ptr);
	write16(socket + Sn_TX_FSR0, fsr);

	if (proto == Sn_MR_UDP || proto == Sn_MR_IPRAW)
	{
		// update registers.
		for (int i = 0; i < 6; ++i)
			socket[Sn_DHAR0 + i] = socket[Sn_DHAR0 + i + 0x80];
		for (int i = 0; i < 4; ++i)
			socket[Sn_DIPR0 + i] = socket[Sn_DIPR0 + i + 0x80];

		socket[Sn_DPORT0] = socket[Sn_DPORT0 + 0x80];
		socket[Sn_DPORT1] = socket[Sn_DPORT1 + 0x80];

		m_sockets[sn].arp_valid = true;
	}

	socket_send_common(sn);
}


void w5100_base_device::socket_send_common(int sn)
{
	uint8_t frame[MAX_FRAME_SIZE];

	uint8_t *socket = m_socket_registers[sn];
	unsigned proto = m_sockets[sn].proto;

	if (busy())
	{
		m_sockets[sn].send_in_progress = true;
		return;
	}

	if (proto == Sn_MR_TCP)
	{
		tcp_send(sn, false);
		return;
	}

	uint16_t read_ptr = read16(socket + Sn_TX_RD0);
	uint16_t write_ptr = read16(socket + Sn_TX_WR0);

	int tx_buffer_offset = m_sockets[sn].tx_buffer_offset;
	int tx_buffer_size = m_sockets[sn].tx_buffer_size;

	int mask = tx_buffer_size - 1;

	int size = (write_ptr - read_ptr) & 0xffff;

	LOGMASKED(LOG_COMMAND, "Socket %d send write_ptr = 0x%04x read_ptr = 0x%04x size = %d\n",
		sn, write_ptr, read_ptr, size);

	int header_size = proto_header_size(proto);
	int mss = read16(socket + Sn_MSSR0);

	memset(frame, 0, header_size);
	if (proto == Sn_MR_UDP)
	{
		// UDP will be split into multiple packets if > mss.
		// Sn_TX_RD and Sn_TX_FSR are updated as sent

		if (size == 0 && m_device_type == dev_type::W5100)
		{
			// actual chip locks up and requires a reset.
			return;
		}

		int msize = std::min(size, mss);
		copy_from_tx(frame + header_size, m_tx_buffer + tx_buffer_offset, msize, read_ptr & mask, tx_buffer_size);

		size -= msize;
		read_ptr += msize;

		build_udp_header(sn, frame, msize);
		msize += header_size;
		dump_bytes(frame, msize);

		send(frame, msize);

		unsigned fsr = tx_buffer_size - size;
		write16(socket + Sn_TX_RD0, read_ptr);
		write16(socket + Sn_TX_FSR0, fsr);
		if (size == 0)
		{
			m_sockets[sn].send_in_progress = false;
			socket[Sn_IR] |= Sn_IR_SEND_OK;
			update_ethernet_irq();
		}
		else
			m_sockets[sn].send_in_progress = true;

	}

	if (proto == Sn_MR_MACRAW || proto == Sn_MR_IPRAW)
	{
		// based on testing, packet dropped if > mss
		// but still sets the send ok irq.
		if (size <= mss)
		{
			copy_from_tx(frame + header_size, m_tx_buffer + tx_buffer_offset, size, read_ptr & mask, tx_buffer_size);

			if (proto == Sn_MR_IPRAW)
				build_ipraw_header(sn, frame, size);

			size += header_size;
			dump_bytes(frame, size);
			send(frame, size);
		}

		// update registers.
		write16(socket + Sn_TX_RD0, write_ptr);
		write16(socket + Sn_TX_FSR0, tx_buffer_size);

		socket[Sn_IR] |= Sn_IR_SEND_OK;
		update_ethernet_irq();
	}

}

void w5100_base_device::socket_send_keep(int sn)
{
	// manual keepalive.  ignored on w5100s if Sn_KPALVTR > 0
	// ignored if no data has been sent.

	const uint8_t *socket = m_socket_registers[sn];

	if (m_device_type == dev_type::W5100S && socket[Sn_KPALVTR])
		return;

	tcp_send_keep(sn, false);
}


// keep alive may be initiated by the Cr_SEND_KEEP command
// or the keep-alive timer (w5100s)
// keep alive is implemented by decrementing snd_una and initiating a tcp-resend.
void w5100_base_device::tcp_send_keep(int sn, bool retransmit)
{
	uint8_t *socket = m_socket_registers[sn];
	const int sr = socket[Sn_SR];

	// has any data been sent yet?
	if (m_tcp[sn].snd_nxt == m_tcp[sn].iss + 1)
		return;

	// has all data been sent?
	if (m_tcp[sn].snd_nxt != m_tcp[sn].snd_una)
		return;

	if (sr == Sn_SR_ESTABLISHED || sr == Sn_SR_CLOSE_WAIT)
	{
		--m_tcp[sn].snd_una;
		unsigned fsr = m_sockets[sn].tx_buffer_size - 1;
		write16(socket + Sn_TX_FSR0, fsr);

		// initiate re-send.
		socket_tcp_timer(sn);
	}
}

void w5100_base_device::socket_listen(int sn)
{

	uint8_t *socket = m_socket_registers[sn];
	auto &sr = socket[Sn_SR];

	LOGMASKED(LOG_COMMAND, "Socket: %d listen %s\n",
		sn, ip_to_string(read32(m_common_registers + SIPR0), read16(socket + Sn_PORT0))
	);


	m_tcp[sn].reset();
	m_tcp[sn].rcv_wnd = m_sockets[sn].rx_buffer_size;

	sr = Sn_SR_LISTEN;
	LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(sr));
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

	m_tcp[sn].reset();

	auto &iss = m_tcp[sn].iss;
	auto &snd_una = m_tcp[sn].snd_una;
	auto &snd_nxt = m_tcp[sn].snd_nxt;
	auto &rcv_wnd = m_tcp[sn].rcv_wnd;


	rcv_wnd = m_sockets[sn].rx_buffer_size;

	iss = tcp_generate_iss();
	snd_una = iss;
	snd_nxt = iss + 1;

	// observed behavior.
	write16(socket + Sn_TX_RD0, (uint32_t)snd_nxt);

	tcp_send_segment(sn, TCP_SYN, iss, 0);

	sr = Sn_SR_SYNSENT;
	LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(sr));

	socket_tcp_timer(sn);
}

void w5100_base_device::socket_disconnect(int sn)
{
	LOGMASKED(LOG_TCP, "Closing TCP socket %d\n", sn);

	// 3.10.4

	uint8_t *socket = m_socket_registers[sn];
	uint8_t &sr = socket[Sn_SR];

	auto &snd_nxt = m_tcp[sn].snd_nxt;
	const auto rcv_nxt = m_tcp[sn].rcv_nxt;

	switch(sr)
	{
		case Sn_SR_ESTABLISHED:
		case Sn_SR_CLOSE_WAIT:

			// if a send is in progress, it will handle the FIN as well.
			// otherwise, send it now.
			if (!m_sockets[sn].send_in_progress)
			{
				tcp_send_segment(sn, TCP_FIN|TCP_ACK, snd_nxt, rcv_nxt);
				++snd_nxt;
				socket_tcp_timer(sn);
			}
			++sr;
			LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(sr));
			break;

		default:
			return;
	}
}


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

		auto &rcv_wnd = m_tcp[sn].rcv_wnd;

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

			auto snd_nxt = m_tcp[sn].snd_nxt;
			auto rcv_nxt = m_tcp[sn].rcv_nxt;
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

	// network is presumably up.
	if (m_device_type == dev_type::W5100S)
		m_common_registers[PHYSR0] |= PHYSR0_LINK;


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

	// find a matching socket
	for (int sn = 0; sn < 4; ++sn)
	{
		const uint8_t *socket = m_socket_registers[sn];
		const int sr = socket[Sn_SR];
		const int proto = m_sockets[sn].proto;

		int port = read16(socket + Sn_PORT0);

		if (sr == Sn_SR_INIT || sr == Sn_SR_CLOSED) continue;

		// IPRAW will not match UDP or TCP protocols
		if (proto == Sn_MR_IPRAW && ip_proto == socket[Sn_PROTO] && !is_udp && !is_tcp)
		{
			LOG("IPRAW Matched %d\n", sn);
			receive(sn, buffer, length);
			return;
		}

		if (proto == Sn_MR_UDP)
		{
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
				// spec says to use a random delay between 0 and igmp max response time.
				uint32_t ip = read32(socket + Sn_DIPR0);
				if (igmp_query_ip == 0 || igmp_query_ip == ip)
					send_igmp(sn, true);
			}
		}

		if (proto == Sn_MR_TCP)
		{
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

		LOGMASKED(LOG_ICMP, "ICMP type %d\n", icmp_type);

		if (icmp_type == ICMP_DESTINATION_UNREACHABLE && icmp[o_ICMP_CODE] == 3 && icmp[8 + o_IP_PROTOCOL] == IP_PROTOCOL_UDP && is_unicast)
		{
			// an ICMP destination unreachable message from a UDP will
			// generate an unreachable interrupt and set unreachable ip/port registers.

			if (length < 14 + ip_header_length + 8 + 20) return;
			int ihl = (icmp[8 + o_IP_IHL] & 0x0f) << 2;
			if (length < 14 + ip_header_length + ihl + 8) return;

			memcpy(m_common_registers + UIPR0, icmp + 8 + o_IP_DEST_ADDRESS, 4);
			memcpy(m_common_registers + UPORT0, icmp + 8 + ihl + o_UDP_DEST_PORT, 2);
			m_common_registers[IR] |= IR_UNREACH;
			update_ethernet_irq();
		}

		// respond to ICMP ping
		if (icmp_type == ICMP_ECHO_REQUEST && (m_common_registers[MR] & MR_PB) == 0)
		{
			send_icmp_reply(buffer, length);
		}

		// socket-less ICMP ping response
		if (icmp_type == ICMP_ECHO_REPLY && m_device_type == dev_type::W5100S && m_sockets[kSLSocket].command == SLCR_PING)
		{
			// TODO - does this also check the ip address / mac?
			uint16_t id = read16(m_common_registers + PINGIDR0);
			uint16_t seq = read16(m_common_registers + PINGSEQR0);
			if (id == read16(icmp + 4) && seq == read16(icmp + 6))
			{
				m_sockets[kSLSocket].command = 0;
				m_retry_timers[kSLSocket]->enable(false);
				m_common_registers[SLCR] = 0;
				m_common_registers[SLIR] |= SLIR_PING;
				update_ethernet_irq();
			}
		}
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
		return;
	}

	if (is_udp && is_unicast && !(mr2 & MR2_UDPURB))
	{
		send_icmp_unreachable(buffer, length);
	}
	return;

	if (is_tcp && is_unicast && !(mr2 & MR2_NOTCPRST))
	{
		tcp_reset(buffer, length);
	}
}



void w5100_base_device::recv_complete_cb(int result)
{
	//
}

void w5100_base_device::send_complete_cb(int result)
{

	if (m_device_type == dev_type::W5100S)
	{
		if (result)
			m_common_registers[PHYSR0] |= PHYSR0_LINK;
		else
			m_common_registers[PHYSR0] &= ~PHYSR0_LINK;
	}

	if (!m_queue.empty())
	{
		auto m = std::move(m_queue.front());
		m_queue.pop();
		dump_bytes(m.data(), m.size());
		send(m.data(), m.size());
	}
	else
	{
		// check all sockets for send / retransmit in progress.
		for (int sn = 0; sn < 4; ++sn)
		{
			if (m_sockets[sn].send_in_progress)
			{
				// any protocol
				m_sockets[sn].send_in_progress = false;
				socket_send_common(sn);
				if (busy())
					break;
			}
			if (m_sockets[sn].resend_in_progress)
			{
				// tcp only.
				m_sockets[sn].resend_in_progress = false;
				tcp_send(sn, true);
				if (busy())
					break;
			}
		}
	}
}


void w5100_base_device::send_or_queue(uint8_t *buffer, int length)
{
	if (busy())
	{
		if (m_queue.size() >= 16)
		{
			LOG("queue full, dropping packet");
			return;
		}
		m_queue.emplace(buffer, buffer + length);
	}
	else
	{
		send(buffer, length);
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
	int proto = m_sockets[sn].proto;

	int mask = rx_buffer_size - 1;

	int used = read16(socket + Sn_RX_RSR0);

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
			ihl = read_ihl(buffer);
			offset = ihl + 14;
			length = read16(buffer + 14 + o_IP_LENGTH) - ihl;

			// header: { uint32_t foreign_ip, uint16_t size }
			memcpy(header + 0, buffer + 14 + o_IP_SRC_ADDRESS, 4);

			header[4] = length >> 8;
			header[5] = length;

			header_size = 6;
			break;

		case Sn_MR_UDP:

			ihl = read_ihl(buffer);
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
	// (The final byte of the destination MAC address will be stored)

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
		m_tcp[sn].rcv_wnd -= length;

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

		m_sockets[sn].arp_valid = true;
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
			m_sockets[sn].arp_valid = true;
			return true;
		}
	}

	unsigned rtr;
	unsigned rcr;
	read_timeout_registers(sn, rcr, rtr);

	if (m_device_type == dev_type::W5100S)
	{
		if (proto == Sn_MR_UDP && (m_common_registers[MR2] & MR2_FARP))
			m_sockets[sn].arp_valid = false;
	}

	bool rv = ip_arp(sn, dest, rtr, rcr);
	if (!rv && m_device_type == dev_type::W5100)
	{
		// W5100S doesn't have Sn_SR_ARP status.
		socket[Sn_SR] = Sn_SR_ARP;
		LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(Sn_SR_ARP));
	}

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

	if (m_sockets[sn].arp_valid && m_sockets[sn].arp_ip_address == dest)
		return true;

	/* Retry Timeout Register, 1 = 100us */
	if (!rtr) rtr = 1;

	m_sockets[sn].arp_ip_address = dest;
	m_sockets[sn].arp_valid = false;
	m_sockets[sn].rcr = rcr;
	m_sockets[sn].rtr = rtr;
	m_sockets[sn].arp_in_progress = true;

	attotime tm = attotime::from_usec(rtr * 100);
	m_retry_timers[sn]->adjust(tm, TIMER_ARP | sn, tm);

	send_arp_request(dest);
	return false;
}

void w5100_base_device::handle_arp_reply(const uint8_t *buffer, int length)
{
	/* if this is an ARP response, possibly update all the Sn_SR_ARP */
	/* remove retry/timeout timers */
	/* queue up the send/synsent */

	const uint8_t *arp = buffer + 14;

	uint32_t ip = read32(arp + o_ARP_SPA);

	LOGMASKED(LOG_ARP, "Received ARP reply for %s\n", ip_to_string(ip));

	if (m_device_type == dev_type::W5100S)
	{
		// socket-less ARP/PING
		if (m_sockets[kSLSocket].arp_in_progress && m_sockets[kSLSocket].arp_ip_address == ip)
		{
			memcpy(m_common_registers + SLPHAR0, arp + o_ARP_SHA, 6);

			m_sockets[kSLSocket].arp_valid = true;
			m_sockets[kSLSocket].arp_in_progress = false;

			if (m_sockets[kSLSocket].command == SLCR_ARP)
			{
				m_retry_timers[kSLSocket]->enable(false);
				m_common_registers[SLCR] = 0;
				m_common_registers[SLIR] |= SLIR_ARP;
				update_ethernet_irq();
			}
			else
			{
				m_retry_timers[kSLSocket]->set_param(TIMER_PING | kSLSocket);
				send_icmp_request();
			}
		}
	}

	for (int sn = 0; sn < 4; ++sn)
	{
		uint8_t *socket = m_socket_registers[sn];

		if (m_sockets[sn].arp_in_progress)
		{
			if (m_sockets[sn].arp_ip_address == ip)
			{
				uint8_t &sr = socket[Sn_SR];
				int proto = m_sockets[sn].proto;

				memcpy(socket + Sn_DHAR0, arp + o_ARP_SHA, 6);
				m_sockets[sn].arp_valid = true;
				m_sockets[sn].arp_in_progress = false;
				m_retry_timers[sn]->enable(false);

				switch(proto)
				{
					case Sn_MR_IPRAW:
						sr = Sn_SR_IPRAW;
						LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(sr));
						socket_send_common(sn);
						break;
					case Sn_MR_UDP:
						sr = Sn_SR_UDP;
						LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(sr));
						socket_send_common(sn);
						break;
					case Sn_MR_TCP:
						sr = Sn_SR_INIT;
						LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(sr));
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

	if (memcmp(arp + o_ARP_TPA, m_common_registers + SIPR0, 4))
	{
		// "there is ARP request with same IP address as Source IP address.""
		m_common_registers[IR] |= IR_CONFLICT;
		update_ethernet_irq();
		return;
	}

	static const int FRAME_SIZE = 60;
	uint8_t frame[FRAME_SIZE];
	memset(frame, 0, sizeof(frame));

	memcpy(frame, arp + o_ARP_SHA, 6);
	memcpy(frame + 6, m_common_registers + SHAR0, 6);
	frame[12] = ETHERNET_TYPE_ARP >> 8;
	frame[13] = ETHERNET_TYPE_ARP;

	frame[14] = ARP_HTYPE_ETHERNET >> 8; // hardware type = ethernet
	frame[15] = ARP_HTYPE_ETHERNET;
	frame[16] = ETHERNET_TYPE_IP >> 8;
	frame[17] = ETHERNET_TYPE_IP;
	frame[18] = 6; // hardware size
	frame[19] = 4; // protocol size
	frame[20] = ARP_OPCODE_REPLY >> 8;
	frame[21] = ARP_OPCODE_REPLY;
	memcpy(frame + 22, m_common_registers + SHAR0, 6); //sender mac
	memcpy(frame + 28, m_common_registers + SIPR0, 4); // sender ip
	memcpy(frame + 32, arp + o_ARP_SHA, 10); // dest mac + ip.

	LOGMASKED(LOG_ARP, "Replying to ARP request\n");
	send_or_queue(frame, FRAME_SIZE);
}


void w5100_base_device::send_arp_request(uint32_t ip)
{
	static const int FRAME_SIZE = 60;
	uint8_t frame[FRAME_SIZE];
	memset(frame, 0, sizeof(frame));

	memcpy(frame, ETHERNET_BROADCAST, 6);
	memcpy(frame + 6, m_common_registers + SHAR0, 6);
	frame[12] = ETHERNET_TYPE_ARP >> 8;
	frame[13] = ETHERNET_TYPE_ARP;

	frame[14] = ARP_HTYPE_ETHERNET >> 8; // hardware type = ethernet
	frame[15] = ARP_HTYPE_ETHERNET;
	frame[16] = ETHERNET_TYPE_IP >> 8;
	frame[17] = ETHERNET_TYPE_IP;
	frame[18] = 6; // hardware size
	frame[19] = 4; // protocol size
	frame[20] = ARP_OPCODE_REQUEST >> 8;
	frame[21] = ARP_OPCODE_REQUEST;
	memcpy(frame + 22, m_common_registers + SHAR0, 6); //sender mac
	memcpy(frame + 28, m_common_registers + SIPR0, 4); // sender ip
	memset(frame + 32, 0, 6); // target mac
	// memcpy(frame + 38, ip, 4); // target ip
	frame[38] = ip >> 24;
	frame[39] = ip >> 16;
	frame[40] = ip >> 8;
	frame[41] = ip >> 0;

	LOGMASKED(LOG_ARP, "Sending ARP request for %s\n", ip_to_string(ip));
	// this could be a callback from a timer
	send_or_queue(frame, FRAME_SIZE);
}


/* build and send the IGMP join/leave frame for multicast UDP socked */
// RFC 1112, Host Extensions for IP Multicasting
// RFC 2236, Internet Group Management Protocol, Version 2
// RFC 2113, IP Router Alert Option
void w5100_base_device::send_igmp(int sn, bool connect)
{
	static const int FRAME_SIZE = 60;
	uint8_t frame[FRAME_SIZE];
	memset(frame, 0, sizeof(frame));

	uint16_t crc;

	const uint8_t *socket = m_socket_registers[sn];

	const int igmpv = socket[Sn_MR] & Sn_MR_MC ? 1 : 2;

	// IGMP v1 doesn't have a leave message.
	if (!connect && igmpv == 1) return;


	memcpy(frame, socket + Sn_DHAR0, 6);
	memcpy(frame + 6, m_common_registers + SHAR0, 6);
	frame[12] = ETHERNET_TYPE_IP >> 8;
	frame[13] = ETHERNET_TYPE_IP;

	++m_identification;

	// ip header

	frame[14] = 0x46; // IPv4, length = 6*4
	frame[15] = socket[Sn_TOS]; // TOS
	frame[16] = 32 >> 8; // total length
	frame[17] = 32;
	frame[18] = m_identification >> 8; // identification
	frame[19] = m_identification;
	frame[20] = 0x40; // flags - don't fragment
	frame[21] = 0x00;
	frame[22] = 1; // ttl
	frame[23] = IP_PROTOCOL_IGMP;
	frame[24] = 0; // checksum...
	frame[25] = 0;
	memcpy(frame + 26, m_common_registers + SIPR0, 4); // source ip
	memcpy(frame + 30, socket + Sn_DIPR0, 4); // destination ip

	// IP Option - Router Alert
	frame[34] = 0x94;
	frame[35] = 0x04;
	frame[36] = 0x00;
	frame[37] = 0x00;


	frame[38] = igmpv == 2 ? IGMP_TYPE_MEMBERSHIP_REPORT_V2 : IGMP_TYPE_MEMBERSHIP_REPORT_V1;
	frame[39] = 0; // max resp time
	frame[40] = 0; // checksum
	frame[41] = 0;
	memcpy(frame + 42, socket + Sn_DIPR0, 4); // multicast address -- destination ip

	if (!connect)
	{
		// IGMP v2 leave messages go to the subnet router.
		static uint8_t eth[] = { 0x01, 0x00, 0x5e, 0x00, 0x00, 0x02 };
		static uint8_t ip[] = { 0xe0, 0x00, 0x00, 0x02 };
		memcpy(frame + 0, eth, 6);
		memcpy(frame + 30, ip, 4);
		frame[34] = IGMP_TYPE_LEAVE_GROUP;
	}

	crc = util::internet_checksum_creator::simple(frame + 14, 20);
	frame[24] = crc >> 8;
	frame[25] = crc;

	crc = util::internet_checksum_creator::simple(frame + 38, 8);
	frame[40] = crc >> 8;
	frame[41] = crc;

	send_or_queue(frame, FRAME_SIZE);
}

uint8_t *w5100_base_device::build_eth_ip_header(const ip_info &info, uint8_t *frame, unsigned length)
{
	const int ip_header_length = 20;

	++m_identification;

	//ethernet header
	memcpy(frame + 0, info.dst_mac, 6);
	memcpy(frame + 6, m_common_registers + SHAR0, 6);
	frame[12] = ETHERNET_TYPE_IP >> 8;
	frame[13] = ETHERNET_TYPE_IP;

	uint8_t *ip_ptr = frame + 14;

	// ip header
	ip_ptr[0] = 0x45; // IPv4, length = 5*4
	ip_ptr[1] = info.tos;
	write16(ip_ptr + 2, ip_header_length + length); // total length
	write16(ip_ptr + 4, m_identification); // identification
	write16(ip_ptr + 6, info.fragment);
	ip_ptr[8] = info.ttl;
	ip_ptr[9] = info.proto;
	ip_ptr[10] = 0; // checksum...
	ip_ptr[11] = 0;
	memcpy(ip_ptr + 12, m_common_registers + SIPR0, 4); // source ip
	memcpy(ip_ptr + 16, info.dst_ip, 4); // destination ip

	uint16_t crc = util::internet_checksum_creator::simple(ip_ptr, ip_header_length);
	write16(ip_ptr + o_IP_CHECKSUM, crc);

	return frame + 14 + ip_header_length;
}

void w5100_base_device::build_ipraw_header(int sn, uint8_t *frame, int data_length)
{
	uint8_t *socket = m_socket_registers[sn];
	ip_info info;
	info.from_socket(socket);

	build_eth_ip_header(info, frame, data_length);
}

void w5100_base_device::build_udp_header(int sn, uint8_t *frame, int data_length)
{
	const int udp_header_length = 8;

	uint8_t *socket = m_socket_registers[sn];
	ip_info info;
	info.from_socket(socket);

	data_length += udp_header_length;

	const uint8_t *ip_ptr = frame + 14;
	uint8_t *udp_ptr = build_eth_ip_header(info, frame, data_length);

	// udp header
	udp_ptr[0] = socket[Sn_PORT0]; // source port
	udp_ptr[1] = socket[Sn_PORT1];
	udp_ptr[2] = socket[Sn_DPORT0]; // dest port
	udp_ptr[3] = socket[Sn_DPORT1];
	write16(udp_ptr + 4, data_length);
	udp_ptr[6] = 0; // checksum - optional
	udp_ptr[7] = 0;

	uint16_t crc = udp_tcp_checksum(IP_PROTOCOL_UDP, ip_ptr, udp_ptr, data_length);
	if (crc == 0) crc = 0xffff;
	write16(udp_ptr + o_UDP_CHECKSUM, crc);
}


void w5100_base_device::build_tcp_header(int sn, uint8_t *frame, int data_length, int flags, util::tcp_sequence seq, util::tcp_sequence ack)
{
	uint8_t *socket = m_socket_registers[sn];
	ip_info info;
	info.from_socket(socket);

	const uint16_t rcv_wnd = m_tcp[sn].rcv_wnd;

	const bool is_syn = flags & TCP_SYN;
	const int tcp_header_length = is_syn ? 24 : 20;

	data_length += tcp_header_length;

	const uint8_t *ip_ptr = frame + 14;
	uint8_t *tcp_ptr = build_eth_ip_header(info, frame, data_length);

	// tcp header
	memcpy(tcp_ptr + 0, socket + Sn_PORT0, 2);
	memcpy(tcp_ptr + 2, socket + Sn_DPORT0, 2);
	write32(tcp_ptr + 4, (uint32_t)seq);
	write32(tcp_ptr + 8, (uint32_t)ack);
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

	uint16_t crc = udp_tcp_checksum(IP_PROTOCOL_TCP, ip_ptr, tcp_ptr, data_length);
	write16(tcp_ptr + o_TCP_CHECKSUM, crc);
}

void w5100_base_device::send_icmp_reply(const uint8_t *buffer, int length)
{
	/*
	   hardware bug: if the icmp size is > 119 bytes, all bytes past 119 are (icmp_size - 12) & 0xff
	   hardware bug: icmp reply can be corrupted if second icmp received before the first reply is sent.
	 */

	uint8_t frame[MAX_FRAME_SIZE];
	memset(frame, 0, sizeof(frame));

	ip_info info;
	info.from_frame(buffer);
	info.proto = IP_PROTOCOL_ICMP;

	int ihl = read_ihl(buffer);
	buffer += 14 + ihl;
	length -= 14 + ihl;
	length = std::min(length, MAX_FRAME_SIZE - 34);

	uint8_t *ptr = build_eth_ip_header(info, frame, length);

	ptr[o_ICMP_TYPE] = ICMP_ECHO_REPLY;
	ptr[o_ICMP_CODE] = 0;
	ptr[o_ICMP_CHECKSUM] = 0;
	ptr[o_ICMP_CHECKSUM+1] = 0;
	memcpy(ptr + 4, buffer + 4, length - 4);

	uint16_t crc = util::internet_checksum_creator::simple(ptr, length);
	ptr[o_ICMP_CHECKSUM] = crc >> 8;
	ptr[o_ICMP_CHECKSUM+1] = crc;

	dump_bytes(frame, length + 34);
	send_or_queue(frame, length + 34);
}

void w5100_base_device::send_icmp_unreachable(uint8_t *buffer, int length)
{
	static const int FRAME_SIZE = 14 + 20 + 8 + 8 + 60; // max ip header is 15 * 4 == 60
	uint8_t frame[FRAME_SIZE];
	memset(frame, 0, sizeof(frame));

	ip_info info;
	info.from_frame(buffer);
	info.proto = IP_PROTOCOL_ICMP;

	int ihl = read_ihl(buffer);
	int new_length = ihl + 8;

	uint8_t *ptr = build_eth_ip_header(info, frame, new_length);

	// icmp header
	ptr[0] = ICMP_DESTINATION_UNREACHABLE;
	ptr[1] = 3; // port unreachable
	ptr[2] = 0; // checksum
	ptr[3] = 0;
	ptr[4] = 0; // unused (4 bytes)
	ptr[5] = 0;
	ptr[6] = 0;
	ptr[7] = 0;

	memcpy(ptr + 8, buffer + 14, 8 + ihl);

	// icmp crc
	uint16_t crc = util::internet_checksum_creator::simple(ptr, 8 + ihl + 8);
	ptr[2] = crc >> 8;
	ptr[3] = crc;

	dump_bytes(frame, new_length + 34);
	send_or_queue(frame, new_length + 34);
}

// w5100s socket-less ping command.
void w5100_base_device::send_icmp_request(void)
{
	static const int FRAME_SIZE = 14 + 20 + 26;
	uint8_t frame[FRAME_SIZE];

	ip_info info;
	memcpy(info.dst_mac, m_common_registers + SLPHAR0, 6);
	memcpy(info.dst_ip, m_common_registers + SLIPR0, 4);
	info.proto = IP_PROTOCOL_ICMP;

	uint8_t *ptr = build_eth_ip_header(info, frame, FRAME_SIZE);

	// icmp header
	ptr[0] = ICMP_ECHO_REQUEST;
	ptr[1] = 0;
	ptr[2] = 0; // checksum
	ptr[3] = 0;
	ptr[4] = m_common_registers[PINGIDR0];
	ptr[5] = m_common_registers[PINGIDR1];
	ptr[6] = m_common_registers[PINGSEQR0];
	ptr[7] = m_common_registers[PINGSEQR1];
	for (int i = 0; i < 18; ++i)
		ptr[8 + i] = 'a' + i;

	uint16_t crc = util::internet_checksum_creator::simple(ptr, 26);
	ptr[2] = crc >> 8;
	ptr[3] = crc;

	dump_bytes(frame, FRAME_SIZE);
	send_or_queue(frame, FRAME_SIZE);
}



[[maybe_unused]] void w5100_base_device::dump_bytes(const uint8_t *buffer, int length)
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


/*

 
 Tx_RD / Tx_WR  are update immediately.
 FSR is decreased immediately
 as data is acknowledged, FSR increases.

send will send the Tx_RD / Tx_WR
retransmissions send all un-acked data.

*/

void w5100_base_device::tcp_send(int sn, bool retransmit)
{
	uint8_t frame[MAX_FRAME_SIZE];

	uint8_t *socket = m_socket_registers[sn];
	const auto sr = socket[Sn_SR];

	const auto snd_una = m_tcp[sn].snd_una;
	const auto snd_wnd = m_tcp[sn].snd_wnd;
	auto &snd_nxt = m_tcp[sn].snd_nxt;
	const auto rcv_nxt = m_tcp[sn].rcv_nxt;
	auto &resend_seq = m_tcp[sn].resend_seq;

	const bool force_psh = m_device_type == dev_type::W5100 || socket[Sn_MR2] & Sn_MR2_BRDB;

	uint16_t read_ptr = retransmit ? (uint32_t)resend_seq : read16(socket + Sn_TX_RD0);
	uint16_t write_ptr = read16(socket + Sn_TX_WR0);

	int mss = read16(socket + Sn_MSSR0);


	const int tx_buffer_offset = m_sockets[sn].tx_buffer_offset;
	const int tx_buffer_size = m_sockets[sn].tx_buffer_size;

	const int mask = tx_buffer_size - 1;


    //                    tx_rd .... tx_wr
	// | ................|...............|
	// snd_una ... snd_nxt

	auto seq = retransmit ? resend_seq : snd_nxt;

	const int total_size = (write_ptr - (uint32_t)seq) & 0xffff;

	bool fin = false;
	bool zwp = false;
	if (sr == Sn_SR_FIN_WAIT || sr == Sn_SR_TIME_WAIT)
		fin = true;

	if (total_size == 0 && retransmit && !fin)
	{
		// shouldn't happen but just in case...
		if (snd_una != snd_nxt)
			socket_tcp_timer(sn, true);

		return;
	}

	// account for snd_wnd
	int window_size = snd_una + snd_wnd - seq;

	if (window_size <= 0)
	{
		window_size = 1; // 1-byte for zero-window probe.
		zwp = true;
	}

	int msize = std::min({total_size, window_size, mss});

	int flags = TCP_ACK;

	if (total_size && total_size <= mss)
		flags |= TCP_PSH;

	if (force_psh)
		flags |= TCP_PSH;

	// hardware bug: FIN will be sent with all segments when the socket disconnects while data is still pending.
	if (fin && total_size == msize)
	{
		flags |= TCP_FIN;
		flags &= ~TCP_PSH;
	}

	copy_from_tx(frame + 54, m_tx_buffer + tx_buffer_offset, msize, read_ptr & mask, tx_buffer_size);

	build_tcp_header(sn, frame, msize, flags, seq, rcv_nxt);

	LOGMASKED(LOG_TCP, "%s %u/%u bytes (window = %u)\n", retransmit ? "Resending" : "Sending", msize, total_size, window_size);

	dump_bytes(frame, msize + 54);
	send(frame, msize + 54);

	if (retransmit)
	{
		if (!zwp)
			resend_seq += msize;

		if (msize == total_size || msize == window_size)
		{
			socket_tcp_timer(sn, true);
		}
		else
		{
			m_sockets[sn].resend_in_progress = true;
		}
	}
	else
	{
		if (msize == total_size || msize == window_size || zwp)
		{
			snd_nxt += total_size;
			if (fin) ++snd_nxt;

			write16(socket + Sn_TX_RD0, write_ptr);
			socket[Sn_IR] |= Sn_IR_SEND_OK;
			update_ethernet_irq();	

			// don't re-send if this was an empty segment.
			if (snd_una != snd_nxt)
				socket_tcp_timer(sn);
		}
		else
		{
			snd_nxt += msize;
			m_sockets[sn].send_in_progress = true;
		}
	}
}

// send or queue a simple (no data) tcp segment.
void w5100_base_device::tcp_send_segment(int sn, int flags, util::tcp_sequence seq, util::tcp_sequence ack)
{

	static const int FRAME_SIZE = 60;
	uint8_t frame[FRAME_SIZE];
	memset(frame, 0, sizeof(frame));

	build_tcp_header(sn, frame, 0, flags, seq, ack);

	LOGMASKED(LOG_TCP, "Sending TCP segment seq=%u, ack=%u, flags=0x%02x\n", (uint32_t)seq, (uint32_t)ack, flags);
	dump_bytes(frame, FRAME_SIZE);

	send_or_queue(frame, FRAME_SIZE);
}


/* RST a TCP packet.  ip address, port, mac take from buffer */
void w5100_base_device::tcp_reset(const uint8_t *buffer, int length)
{
	// pp 65

	static const int FRAME_SIZE = 60;
	uint8_t frame[FRAME_SIZE];
	memset(frame, 0, sizeof(frame));

	ip_info info;
	info.from_frame(buffer);

	int ip_header_length = 0;
	int tcp_header_length = 0;
	int seg_len = 0;


	std::tie(ip_header_length, tcp_header_length, seg_len) = get_tcp_offsets(buffer);

	const uint8_t *src_tcp_ptr = buffer + 14 + ip_header_length;

	int flags = src_tcp_ptr[o_TCP_FLAGS];

	if (flags & TCP_RST) return;

	const uint8_t *ip_ptr = frame + 14;
	uint8_t *tcp_ptr = build_eth_ip_header(info, frame, 0);

	// tcp header
	write16(tcp_ptr + 0, read16(src_tcp_ptr + o_TCP_DEST_PORT));
	write16(tcp_ptr + 2, read16(src_tcp_ptr + o_TCP_SRC_PORT));
	write32(tcp_ptr + 4, 0); // seq
	write32(tcp_ptr + 8, 0); // ack
	tcp_ptr[12] = 0x50; // 4 * 5 bytes
	tcp_ptr[13] = TCP_RST; // flags
	write16(tcp_ptr + 14, 0);
	write16(tcp_ptr + 16, 0); // checksum
	write16(tcp_ptr + 18, 0); // urgent ptr


	// W5100 just sends an RST with 0 as the seq/ack.
	// W5100S is RFC compliant.
	if (m_device_type == dev_type::W5100S)
	{
		if (flags & TCP_ACK)
		{
			uint32_t seg_ack = read32(src_tcp_ptr + o_TCP_ACK_NUMBER);

			tcp_ptr[o_TCP_FLAGS] = TCP_RST;
			write16(tcp_ptr + o_TCP_SEQ_NUMBER, seg_ack);
			write16(tcp_ptr + o_TCP_ACK_NUMBER, 0);
		}
		else
		{
			uint32_t seg_seq = read32(src_tcp_ptr + o_TCP_SEQ_NUMBER);

			tcp_ptr[o_TCP_FLAGS] = TCP_RST | TCP_ACK;
			write16(tcp_ptr + o_TCP_SEQ_NUMBER, 0);
			write16(tcp_ptr + o_TCP_ACK_NUMBER, seg_seq + seg_len);
		}
	}

	uint16_t crc = udp_tcp_checksum(IP_PROTOCOL_TCP, ip_ptr, tcp_ptr, 0);
	write16(tcp_ptr + o_TCP_CHECKSUM, crc);

	LOGMASKED(LOG_TCP, "TCP: Sending RST\n");
	dump_bytes(frame, FRAME_SIZE);
	send_or_queue(frame, FRAME_SIZE);
}

void w5100_base_device::reset_socket_timers(int sn)
{
	m_retry_timers[sn]->enable(false);
	m_keep_alive_timers[sn]->enable(false);
	m_delayed_ack_timers[sn]->enable(false);
}



void w5100_base_device::tcp_parse_options(int sn, const uint8_t *options, int length)
{
	// MSS is the only supported TCP option.

	int ol;

	while (length > 1)
	{
		ol = options[1]; // all except end/nop have a length byte.

		switch (*options)
		{
			case 0: /* end of option list */
				return;

			case 1: /* no operation */
				ol = 1;
				break;

			case 2: /* max segment size */
				if (ol == 4 && length >= 4)
				{
					int mss = read16(options + 2);
					if (mss == 0 || mss > 1460) mss = 1460;
					write16(m_socket_registers[sn] + Sn_MSSR0, mss);
				}
				break;

			default:
				break;

		}
		options += ol;
		length -= ol;
	}
}

uint32_t w5100_base_device::tcp_generate_iss(void)
{
	if (m_device_type == dev_type::W5100S)
		return 1;

	/* The generator is bound to a (possibly fictitious) 32 bit clock
	   whose low order bit is incremented roughly every 4 microseconds.
	 */

	// 1 microsecond = 1e-6 seconds
	return machine().time().as_ticks(1e6 / 4);
}


// page numbers refer to rfc 9293 (pdf version)
// https://www.rfc-editor.org/rfc/rfc9293.pdf
void w5100_base_device::tcp_segment(int sn, const uint8_t *buffer, int length)
{
	int ip_header_length;
	int tcp_header_length;
	int seg_len;

	std::tie(ip_header_length, tcp_header_length, seg_len) = get_tcp_offsets(buffer);

	const uint8_t *ip_ptr = buffer + 14;
	const uint8_t *tcp_ptr = ip_ptr + ip_header_length;


	int flags = tcp_ptr[o_TCP_FLAGS];
	util::tcp_sequence seg_ack = flags & TCP_ACK ? read32(tcp_ptr + o_TCP_ACK_NUMBER) : 0;
	util::tcp_sequence seg_seq = read32(tcp_ptr + o_TCP_SEQ_NUMBER);
	uint32_t seg_wnd = read16(tcp_ptr + o_TCP_WINDOW_SIZE);

	uint8_t *socket = m_socket_registers[sn];
	auto &sr = socket[Sn_SR];
	const auto mr = socket[Sn_MR];

	auto &rcv_nxt = m_tcp[sn].rcv_nxt;
	const auto rcv_wnd = m_tcp[sn].rcv_wnd;
	auto &snd_nxt = m_tcp[sn].snd_nxt;
	auto &snd_una = m_tcp[sn].snd_una;
	auto &snd_wnd = m_tcp[sn].snd_wnd;
	auto &snd_wl1 = m_tcp[sn].snd_wl1;
	auto &snd_wl2 = m_tcp[sn].snd_wl2;
	auto &irs = m_tcp[sn].irs;
	auto &iss = m_tcp[sn].iss;

	LOGMASKED(LOG_TCP, "TCP Segment: %d (%s)\n", sn, sr_to_cstring(sr));
	LOGMASKED(LOG_TCP, "flags=%02x (%s), ack=%u seq=%u length=%u\n",
		flags, tcp_flags_to_string(flags), (uint32_t)seg_ack, (uint32_t)seg_seq, seg_len);

	if (sr == Sn_SR_LISTEN)
	{
		// 3.10.7.2 pp 60
		if (flags & TCP_RST) return;
		if (flags & TCP_ACK)
		{
			tcp_reset(buffer, length);
			return;
		}
		if (flags & TCP_SYN)
		{
			tcp_parse_options(sn, tcp_ptr + 20, tcp_header_length - 20);

			rcv_nxt = seg_seq + 1;
			irs = seg_seq;
			iss = tcp_generate_iss();

			snd_nxt = iss + 1;
			snd_una = iss;

			write16(socket + Sn_TX_RD0, (uint32_t)snd_nxt);
			write16(socket + Sn_TX_WR0, (uint32_t)snd_nxt);
			write16(socket + Sn_DPORT0, read16(tcp_ptr + o_TCP_SRC_PORT));
			write32(socket + Sn_DIPR0, read32(ip_ptr + o_IP_SRC_ADDRESS));
			memcpy(socket + Sn_DHAR0, buffer + o_ETHERNET_SRC, 6);

			//  data in the syn segment is supported.
			if (seg_len && seg_len <= rcv_wnd)
			{
				receive(sn, tcp_ptr + tcp_header_length, seg_len);
				rcv_nxt += seg_len;
			}

			tcp_send_segment(sn, TCP_SYN|TCP_ACK, iss, rcv_nxt);
			sr = Sn_SR_SYNRECV;
			LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(sr));
			socket_tcp_timer(sn);
			return;
		}
		return;
	}


	if (sr == Sn_SR_SYNSENT)
	{
		// 3.10.7.3 pp 61-62

		if (flags & TCP_ACK)
		{
			// If SEG.ACK =< ISS or SEG.ACK > SND.NXT, send a reset (unless
            // the RST bit is set, if so drop the segment and return)
            // and discard the segment.  Return.
            //
			// If SND.UNA < SEG.ACK =< SND.NXT, then the ACK is acceptable.
            // Some deployed TCP code has used the check SEG.ACK == SND.NXT
            // (using "==" rather than "=<"), but this is not appropriate
            // when the stack is capable of sending data on the SYN because
            // the TCP peer may not accept and acknowledge all of the data
            // on the SYN.

			// n.b. snd_una = iss, snd_nxt = iss +1

			// if (!ack_valid_le_le(snd_una, seg_ack, snd_nxt))
			if (seg_ack <= iss || seg_ack > snd_nxt)
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
				socket_close(sn, Sn_IR_DISCON);
				return;
			}
			return;
		}

		if (flags & TCP_SYN)
		{
			rcv_nxt = seg_seq + 1;
			irs = seg_seq;
			if (flags & TCP_ACK)
				snd_una = seg_ack;

			// If SND.UNA > ISS (our SYN has been ACKed)
			if (snd_una > iss)
			{
				snd_wnd = seg_wnd;
				snd_wl1 = seg_seq;
				snd_wl2 = seg_ack;

				write16(socket + Sn_TX_WR0, (uint32_t)snd_nxt);

				if (seg_len && seg_len <= rcv_wnd)
				{
					// process any segment data
					receive(sn, tcp_ptr + tcp_header_length, seg_len);
					rcv_nxt += seg_len;
				}

				tcp_send_segment(sn, TCP_ACK, snd_nxt, rcv_nxt);
				sr = Sn_SR_ESTABLISHED;
				LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(sr));
				socket[Sn_IR] |= Sn_IR_CON;
				update_ethernet_irq();

				m_retry_timers[sn]->enable(false);
				if (m_device_type == dev_type::W5100S && socket[Sn_KPALVTR])
				{
					attotime tm = attotime::from_seconds(socket[Sn_KPALVTR] * 5);
					m_keep_alive_timers[sn]->adjust(tm, sn, tm);
				}
			}
			else
			{
				// n.b. - actual hardware will transition from SYN_SENT to SYN_RECV but will not establish
				// a connection after receiving an ack.
				tcp_send_segment(sn, TCP_SYN|TCP_ACK, iss, rcv_nxt);
				sr = Sn_SR_SYNRECV;
				LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(sr));
				socket_tcp_timer(sn);
				return;
			}

		}
		return;
	}

	// 3.10.74 pp 63

	if (flags & TCP_RST)
	{
		// pp 64-65

		// rst ignored unless seg_seq == rcv_nxt or 0
		if (seg_seq != 0 && seg_seq != rcv_nxt)
			return;

		switch(sr)
		{
			case Sn_SR_SYNRECV:
			case Sn_SR_ESTABLISHED:
			case Sn_SR_FIN_WAIT:
			case Sn_SR_CLOSE_WAIT:
			case Sn_SR_CLOSING:
			case Sn_SR_LAST_ACK:
			case Sn_SR_TIME_WAIT:
				socket_close(sn, Sn_IR_DISCON);
				return;

			default:
				return;
		}
	}


	// out-of order segments are dropped.
	if (seg_seq != rcv_nxt)
	{
		tcp_send_segment(sn, TCP_ACK, snd_nxt, rcv_nxt);
		return;
	}


	if (flags & TCP_SYN)
	{
		// pp 66
		// n.b. - w5100 goes to a closed state instead of a listen state.

		// TODO -- verify 0 vs rcv_nxt
		tcp_send_segment(sn, TCP_RST, snd_nxt, 0);
		socket_close(sn, Sn_IR_DISCON);
		return;
	}

	if (!(flags & TCP_ACK)) return;


	bool update_resend = false;
	switch(sr)
	{
		case Sn_SR_SYNRECV:
			// pp 67
			if (snd_una < seg_ack && seg_ack <= snd_nxt)
			{
				snd_wnd = seg_wnd;
				snd_wl1 = seg_seq;
				snd_wl2 = seg_ack;

				snd_una = seg_ack;

				sr = Sn_SR_ESTABLISHED;
				LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(sr));
				socket[Sn_IR] |= Sn_IR_CON;
				update_ethernet_irq();
			}
			else
			{
				tcp_send_segment(sn, TCP_RST, seg_ack, 0);
				return;
			}
			break;

		case Sn_SR_ESTABLISHED:
		case Sn_SR_FIN_WAIT:
		case Sn_SR_CLOSE_WAIT:
		case Sn_SR_CLOSING:

			// pp 67

			if (seg_ack > snd_nxt)
			{
				// ack for something not sent. drop segment and return.
				tcp_send_segment(sn, TCP_ACK, snd_nxt, rcv_nxt);
				return;
			}

			if (snd_una < seg_ack && seg_ack <= snd_nxt)
			{
				int delta = seg_ack - snd_una;

				snd_una = seg_ack;

				if (snd_una == snd_nxt && sr != Sn_SR_ESTABLISHED && sr != Sn_SR_CLOSE_WAIT)
				{
					// adjust for acknowledgement of FIN.
					delta--;
				}
				if (delta)
				{
					auto fsr = read16(socket + Sn_TX_FSR0);
					fsr += delta;
					write16(socket + Sn_TX_FSR0, fsr);
				}

				// if a re-send timer is in effect, re-set the retry counter.
				update_resend = true;

				if (snd_una == snd_nxt && sr == Sn_SR_CLOSING)
				{
					sr = Sn_SR_TIME_WAIT;
					LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(sr));
					update_resend = false;
				}
			}


			// If SND.UNA =< SEG.ACK =< SND.NXT, the send window should be updated.
			// If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK)),
			// set SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.

			if (snd_una <= seg_ack && seg_ack <= snd_nxt)
			{
				if (snd_wl1 < seg_seq || (snd_wl1 == seg_seq && snd_wl2 <= seg_ack))
				{
					const unsigned mss = read16(socket + Sn_MSSR0);
					if (seg_wnd > snd_wnd && snd_wnd < mss) update_resend = true;

					snd_wnd = seg_wnd;
					snd_wl1 = seg_seq;
					snd_wl2 = seg_ack;
				}
			}

			break;

		case Sn_SR_LAST_ACK:
			// pp 68
			if (seg_ack == snd_nxt)
			{
				// if FIN acknowledged, go to closed state.
				snd_una = seg_ack;
				socket_close(sn, Sn_IR_DISCON);
				return;
			}
			break;

		case Sn_SR_TIME_WAIT:
			break;

		default:
			break;
	}

	if (snd_una == snd_nxt)
	{
		// all data acknowledged, kill the re-send timer.
		m_retry_timers[sn]->enable(false);
		m_sockets[sn].resend_in_progress = false;
	}
	else if (update_resend)
	{
		// data acked or window updated so re-trigger the resend timer.
		socket_tcp_timer(sn);
	}


	// segment text
	int tcp_flags = 0;
	int copied = 0;
	if (seg_len)
	{
		// pp 68
		switch(sr)
		{
			case Sn_SR_ESTABLISHED:
			case Sn_SR_FIN_WAIT:
				if (seg_len > rcv_wnd)
				{
					// no partial stores.
					tcp_send_segment(sn, TCP_ACK, snd_nxt, rcv_nxt);
					return;
				}
				tcp_flags |= TCP_ACK;
				copied = receive(sn, tcp_ptr + tcp_header_length, seg_len);
				rcv_nxt += copied;
				break;

			case Sn_SR_CLOSE_WAIT:
			case Sn_SR_CLOSING:
			case Sn_SR_LAST_ACK:
			case Sn_SR_TIME_WAIT:
				seg_len = 0;
				break;
			default:
				break;
		}

	}

	if (flags & TCP_FIN)
	{
		// pp 69
		switch(sr)
		{
			case Sn_SR_SYNRECV:
			case Sn_SR_ESTABLISHED:

				++rcv_nxt;
				tcp_flags |= TCP_ACK;

				sr = Sn_SR_CLOSE_WAIT;
				LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(sr));
				socket[Sn_IR] |= Sn_IR_DISCON;
				update_ethernet_irq();
				break;

			case Sn_SR_FIN_WAIT:
				// tcp specifies SR_CLOSING state, actual hardware goes to a LAST ACK state.
				if (snd_una == snd_nxt)
				{
					// fin wait 2
					sr = Sn_SR_TIME_WAIT;
				}
				else
				{
					// fin wait 1
					sr = Sn_SR_LAST_ACK;
				}
				tcp_flags |= TCP_ACK;
				LOGMASKED(LOG_SR, "Socket %d -> %s\n", sn, sr_to_cstring(sr));
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
	// exception: if connection is closing, don't delay

	if (seg_len && sr != Sn_SR_TIME_WAIT && (mr & Sn_MR_ND) == 0)
	{
		auto t = m_delayed_ack_timers[sn];
		if (!t->enabled())
		{
			unsigned rcr, rtr;
			read_timeout_registers(sn, rcr, rtr);
			attotime tm = attotime::from_usec(rtr * 100);
			t->reset(tm);
			return;
		}
	}

	if (tcp_flags)
	{
		m_delayed_ack_timers[sn]->enable(false);
		tcp_send_segment(sn, tcp_flags, snd_nxt, rcv_nxt);
	}

	if (sr == Sn_SR_TIME_WAIT)
	{
		// There is no 2msl timer; close immediately.
		socket_close(sn, Sn_IR_DISCON);
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
