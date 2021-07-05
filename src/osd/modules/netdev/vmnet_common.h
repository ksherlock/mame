

enum {
  eth_dest  = 0,  // destination address
  eth_src   = 6,  // source address
  eth_type  = 12, // packet type
  eth_data  = 14, // packet data
};

enum {
  ip_ver_ihl  = 0,
  ip_tos    = 1,
  ip_len    = 2,
  ip_id   = 4,
  ip_frag   = 6,
  ip_ttl    = 8,
  ip_proto    = 9,
  ip_header_cksum = 10,
  ip_src    = 12,
  ip_dest   = 16,
  ip_data   = 20,
};

enum {
  udp_source = 0, // source port
  udp_dest = 2, // destination port
  udp_len = 4, // length
  udp_cksum = 6, // checksum
  udp_data = 8, // total length udp header
};

enum {
  bootp_op = 0, // operation
  bootp_hw = 1, // hardware type
  bootp_hlen = 2, // hardware len
  bootp_hp = 3, // hops
  bootp_transid = 4, // transaction id
  bootp_secs = 8, // seconds since start
  bootp_flags = 10, // flags
  bootp_ipaddr = 12, // ip address knwon by client
  bootp_ipclient = 16, // client ip from server
  bootp_ipserver = 20, // server ip
  bootp_ipgateway = 24, // gateway ip
  bootp_client_hrd = 28, // client mac address
  bootp_spare = 34,
  bootp_host = 44,
  bootp_fname = 108,
  bootp_data = 236, // total length bootp packet
};

enum {
  arp_hw = 14,    // hw type (eth = 0001)
  arp_proto = 16,   // protocol (ip = 0800)
  arp_hwlen = 18,   // hw addr len (eth = 06)
  arp_protolen = 19,  // proto addr len (ip = 04)
  arp_op = 20,    // request = 0001, reply = 0002
  arp_shw = 22,   // sender hw addr
  arp_sp = 28,    // sender proto addr
  arp_thw = 32,   // target hw addr
  arp_tp = 38,    // target protoaddr
  arp_data = 42,  // total length of packet
};

enum {
  dhcp_discover = 1,
  dhcp_offer = 2,
  dhcp_request = 3,
  dhcp_decline = 4,
  dhcp_pack = 5,
  dhcp_nack = 6,
  dhcp_release = 7,
  dhcp_inform = 8,
};

// static uint8_t oo[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static uint8_t ff[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static int is_arp(const uint8_t *packet, unsigned size) {
  return size >= arp_data
    && packet[12] == 0x08 && packet[13] == 0x06 /* ARP */
    && packet[14] == 0x00 && packet[15] == 0x01 /* ethernet */
    && packet[16] == 0x08 && packet[17] == 0x00 /* ipv4 */
    && packet[18] == 0x06 /* hardware size */
    && packet[19] == 0x04 /* protocol size */
  ;
}

static int is_broadcast(const uint8_t *packet, unsigned size) {
  return !memcmp(packet + 0, ff, 6);
}

static int is_unicast(const uint8_t *packet, unsigned size) {
  return (*packet & 0x01) == 0;
}

#if 0
// unused.
static int is_multicast(const uint8_t *packet, unsigned size) {
  return (*packet & 0x01) == 0x01 && !is_broadcast(packet, size);
}
#endif

static int is_dhcp_out(const uint8_t *packet, unsigned size) {
  static uint8_t cookie[] = { 0x63, 0x82, 0x53, 0x63 };
  return size >= 282
    //&& !memcmp(&packet[0], ff, 6) /* broadcast */
    && packet[12] == 0x08 && packet[13] == 0x00
    && packet[14] == 0x45 /* version 4 */
    && packet[23] == 0x11 /* UDP */
    //&& !memcmp(&packet[26], oo, 4)  /* source ip */
    //&& !memcmp(&packet[30], ff, 4)  /* dest ip */
    && packet[34] == 0x00 && packet[35] == 0x44 /* source port */
    && packet[36] == 0x00 && packet[37] == 0x43 /* dest port */
    //&& packet[44] == 0x01 /* dhcp boot req */
    && packet[43] == 0x01 /* ethernet */
    && packet[44] == 0x06 /* 6 byte mac */
    && !memcmp(&packet[278], cookie, 4)
  ;
}


static int is_dhcp_in(const uint8_t *packet, unsigned size) {
  static uint8_t cookie[] = { 0x63, 0x82, 0x53, 0x63 };
  return size >= 282
    //&& !memcmp(&packet[0], ff, 6) /* broadcast */
    && packet[12] == 0x08 && packet[13] == 0x00
    && packet[14] == 0x45 /* version 4 */
    && packet[23] == 0x11 /* UDP */
    //&& !memcmp(&packet[26], oo, 4)  /* source ip */
    //&& !memcmp(&packet[30], ff, 4)  /* dest ip */
    && packet[34] == 0x00 && packet[35] == 0x43 /* source port */
    && packet[36] == 0x00 && packet[37] == 0x44 /* dest port */
    //&& packet[44] == 0x01 /* dhcp boot req */
    && packet[43] == 0x01 /* ethernet */
    && packet[44] == 0x06 /* 6 byte mac */
    && !memcmp(&packet[278], cookie, 4)
  ;
}

#if 0
// unused.
static unsigned ip_checksum(const uint8_t *packet) {
  unsigned x = 0;
  unsigned i;
  for (i = 0; i < ip_data; i += 2) {
    if (i == ip_header_cksum) continue;
    x += packet[eth_data + i + 0 ] << 8;
    x += packet[eth_data + i + 1];
  }

  /* add the carry */
  x += x >> 16;
  x &= 0xffff;
  return ~x & 0xffff;
}
#endif

static void recalc_udp_checksum(uint8_t *packet, unsigned size) {
  if (size < eth_data + ip_data + udp_data) return;

  // checksum optional for UDP.
  if (packet[eth_data+ip_data+udp_cksum+0] == 0 && packet[eth_data+ip_data+udp_cksum+1] == 0)
    return;


  // unsigned ip_version = packet[eth_data + ip_ver_ihl] & 0xf0;
  unsigned packet_len = (packet[eth_data + ip_len + 0] << 8) | (packet[eth_data + ip_len + 1]);
  // unsigned proto = packet[eth_data+ip_proto];

  packet[eth_data+ip_data+udp_cksum+0] = 0;
  packet[eth_data+ip_data+udp_cksum+1] = 0;

  if (packet_len + eth_data < size)
    return;

  packet_len -= ip_data;

  unsigned sum = 0;
  unsigned i;

  // pseudo header = src address, dest address, protocol (17), udp + data length
  sum = 17 + packet_len;
  for (i = 0; i < 4; i += 2) {
    sum += (uint32_t)packet[eth_data+ip_src + i + 0] << 8;
    sum += (uint32_t)packet[eth_data+ip_src + i + 1];
    sum += (uint32_t)packet[eth_data+ip_dest + i + 0] << 8;
    sum += (uint32_t)packet[eth_data+ip_dest + i + 1];
  }

  for(i = 0; i < packet_len; i += 2) {
    sum += (uint32_t)packet[eth_data+ip_data+i + 0] << 8;
    sum += (uint32_t)packet[eth_data+ip_data+i + 1];
  }
  if (packet_len & 0x01) {
    sum += (uint32_t)packet[eth_data+packet_len-1] << 8;
  }

  sum += sum >> 16;
  sum = ~sum & 0xffff;

  packet[eth_data+ip_data+udp_cksum+0] = (sum >> 8) & 0xff;
  packet[eth_data+ip_data+udp_cksum+1] = (sum >> 0) & 0xff;

}


static void fix_incoming_packet(uint8_t *packet, unsigned size, const char real_mac[6], const char fake_mac[6]) {

  if (memcmp(packet + 0, real_mac, 6) == 0)
    memcpy(packet + 0, fake_mac, 6);

  if (is_arp(packet, size)) {
    /* receiver mac address */
    if (!memcmp(packet + 32, real_mac, 6))
      memcpy(packet + 32, fake_mac, 6);
    return;
  }

  /* dhcp request - fix the hardware address */
  if (is_unicast(packet, size) && is_dhcp_in(packet, size)) {
    if (!memcmp(packet + 70, real_mac, 6))
      memcpy(packet + 70, fake_mac, 6);
    return;
  }

}

static void fix_outgoing_packet(uint8_t *packet, unsigned size, const char real_mac[6], const char fake_mac[6]) {



  if (memcmp(packet + 6, fake_mac, 6) == 0)
    memcpy(packet + 6, real_mac, 6);

  if (is_arp(packet, size)) {
    /* sender mac address */
    if (!memcmp(packet + 22, fake_mac, 6))
      memcpy(packet + 22, real_mac, 6);
    return;
  }

  /* dhcp request - fix the hardware address */
  if (is_broadcast(packet, size) && is_dhcp_out(packet, size)) {

    if (!memcmp(packet + 70, fake_mac, 6)) {
      memcpy(packet + 70, real_mac, 6);
      recalc_udp_checksum(packet, size);
    }
    return;
  }

}

static constexpr int ETHERNET_MIN_FRAME = 64;

static u32 finalize_frame(u8 buf[], u32 length)
{
  /*
   * The taptun driver receives frames which are shorter than the Ethernet
   * minimum. Partly this is because it can't see the frame check sequence
   * bytes, but mainly it's because the OS expects the lower level device
   * to add the required padding.
   *
   * We do the equivalent padding here (i.e. pad with zeroes to the
   * minimum Ethernet length minus FCS), so that devices which check
   * for this will not reject these packets.
   */
  if (length < ETHERNET_MIN_FRAME - 4)
  {
    std::fill_n(&buf[length], ETHERNET_MIN_FRAME - length - 4, 0);

    length = ETHERNET_MIN_FRAME - 4;
  }

  // compute and append the frame check sequence
  const u32 fcs = util::crc32_creator::simple(buf, length);

  buf[length++] = (fcs >> 0) & 0xff;
  buf[length++] = (fcs >> 8) & 0xff;
  buf[length++] = (fcs >> 16) & 0xff;
  buf[length++] = (fcs >> 24) & 0xff;

  return length;
}

