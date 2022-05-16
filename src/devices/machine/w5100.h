
#ifndef MAME_MACHINE_W5100_H
#define MAME_MACHINE_W5100_H



class w5100_device : public device_t, public device_network_interface
{
public:

	w5100_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock);

	uint8_t read(uint16_t address);
	void write(uint16_t address, uint8_t data);

	auto irq_handler() { return m_irq_handler.bind(); }

protected:

	w5100_device(const machine_config &mconfig, device_type type, const char *tag, device_t *owner, uint32_t clock);

	virtual void device_start() override;
	virtual void device_reset() override;
	virtual void device_timer(emu_timer &timer, device_timer_id id, int param) override;
	virtual void device_post_load() override;

	virtual void recv_cb(u8 *buffer, int length) override;
	// virtual void send_complete_cb(int result) override;
	// virtual int recv_start_cb(u8 *buf, int length) override;
	// virtual void recv_complete_cb(int result) override;

private:

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
	void socket_connect(int sn);
	void socket_disconnect(int sn);


#if 0
	void get_rmsr(int sn, int &offset, int &size) const;
	void get_tmsr(int sn, int &offset, int &size) const;
#endif

	bool find_mac(int sn);
	void send_arp_request(uint32_t ip);

	void handle_arp_request(uint8_t *buffer, int length);
	void handle_arp_reply(uint8_t *buffer, int length);
	void handle_ping_reply(uint8_t *buffer, int length);

	void receive(int sn, const uint8_t *buffer, int length);


	void build_ethernet_header(int sn, uint8_t *buffer, int length);
	void build_ipraw_header(int sn, uint8_t *buffer, int length);
	void build_udp_header(int sn, uint8_t *buffer, int length);
	void build_tcp_header(int sn, uint8_t *buffer, int length, int flags);

	void send_tcp_packet(int sn, int flags);

	void dump_bytes(const uint8_t *buffer, int length);

	uint16_t m_idm = 0;
	uint16_t m_identification = 0;
	uint8_t m_irq_state = 0;
	emu_timer *m_timers[4]{};

	uint8_t m_memory[0x8000]{};

	devcb_write_line m_irq_handler;

	struct tcp_block
	{
		uint32_t snd_una; // oldest unack seq number
		uint32_t snd_nxt; // next seq number to send
		uint32_t snd_wnd; // send window
		uint32_t snd_up; // send urgent pointer
		uint32_t wl1; // seg seq of last window update
		uint32_t wl2; // seg ack of last window update
		uint32_t iss; // initial send seq

		uint32_t rcv_nxt; // receive next
		uint32_t rcv_wnd; // receive window
		uint32_t rcv_up; // receive urgent ptr
		uint32_t irs; // initial recv seq number
	};

	struct tcp_block m_tcp[4];

	struct socket_info
	{
		int rx_buffer_offset;
		int rx_buffer_size;
		int tx_buffer_offset;
		int tx_buffer_size;

		// arp
		uint32_t arp_ip_address;
		bool arp_ok;

		// arp/tcp retry count
		int retry;


		uint32_t tcp_send_una;
		uint32_t tcp_send_wnd;
		uint32_t tcp_send_nxt;
		uint32_t tcp_send_max;

		uint32_t tcp_recv_wnd;
		uint32_t tcp_rcv_next;
		uint32_t tcp_rcv_adv;


		void reset()
		{
			arp_ok = false;
			arp_ip_address = 0;
			retry = 0;
		}
	};

	socket_info m_sockets[4];


};

DECLARE_DEVICE_TYPE(W5100, w5100_device)

#endif
