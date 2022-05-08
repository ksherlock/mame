
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
	// void socket_close(int sn);
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
	void handle_arp_response(uint8_t *buffer, int length);
	void handle_ping_response(uint8_t *buffer, int length);

	void receive(int sn, const uint8_t *buffer, int length);


	void build_ethernet_header(int sn, uint8_t *buffer, int length);
	void build_ipraw_header(int sn, uint8_t *buffer, int length);
	void build_udp_header(int sn, uint8_t *buffer, int length);
	// void build_tcp_header(int sn, uint8_t *buffer, int length);

	uint16_t m_idm = 0;
	uint8_t m_irq_state = 0;
	emu_timer *m_timers[4]{};

	uint8_t m_memory[0x8000]{};

	devcb_write_line m_irq_handler;

	struct socket_info
	{
		int rx_buffer_offset;
		int rx_buffer_size;
		int tx_buffer_offset;
		int tx_buffer_size;

		uint32_t arp_ip_address;
		bool arp_ok;
		int retry;

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
