#ifndef MAME_APPLE_AMPLE_HOST_H
#define MAME_APPLE_AMPLE_HOST_H


#pragma once

class ample_host_device : public device_t
{
public:
	ample_host_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock);

	void wdm_w(offs_t offset, uint8_t data);

	// inline configuration
	template <typename T>
	void set_cputag(T &&tag) { m_maincpu.set_tag(std::forward<T>(tag)); }

	template <class T>
	void set_space(T &&tag, int spacenum) { m_space.set_tag(std::forward<T>(tag), spacenum); }

	struct file_entry;

protected:
	virtual void device_start() override ATTR_COLD;
	virtual void device_reset() override ATTR_COLD;
	virtual void device_stop() override ATTR_COLD;
	virtual ioport_constructor device_input_ports() const override;


	void host_fst();
	void host_mli();
	void host_print();
	void host_hexdump();

	unsigned fst_startup();
	unsigned fst_shutdown();



	std::string read_string(uint32_t address, unsigned type);
	unsigned write_string(uint32_t address, const std::string &s, unsigned type, bool truncate=false);
	void write_data(uint32_t address, const std::vector<uint8_t> &data);
	void write_data(uint32_t address, const uint8_t * data, size_t length);

	unsigned write_option_list(uint32_t address, unsigned fstID, const uint8_t *data, unsigned size);

	std::string fst_get_path1();
	std::string fst_get_path2();
	file_entry *fst_get_file_entry(unsigned cookie);
	file_entry *mli_get_file_entry(unsigned cookie);

	unsigned fst_change_path(unsigned klass, const std::string &path1, const std::string &path2);
	unsigned fst_clear_backup(unsigned klass, const std::string &path);
	unsigned fst_create(unsigned klass, const std::string &path);
	unsigned fst_destroy(unsigned klass, const std::string &path);
	unsigned fst_get_file_info(unsigned klass, const std::string &path);
	unsigned fst_judge_name(unsigned klass);
	unsigned fst_open(unsigned klass, const std::string &path);
	unsigned fst_set_file_info(unsigned klass, const std::string &path);
	unsigned fst_volume(unsigned klass);
	unsigned fst_read(unsigned klass, file_entry &e);
	unsigned fst_write(unsigned klass, file_entry &e);
	unsigned fst_close(unsigned klass, file_entry &e);
	unsigned fst_flush(unsigned klass, file_entry &e);
	unsigned fst_get_mark(unsigned klass, file_entry &e);
	unsigned fst_set_mark(unsigned klass, file_entry &e);
	unsigned fst_get_eof(unsigned klass, file_entry &e);
	unsigned fst_set_eof(unsigned klass, file_entry &e);
	unsigned fst_get_dir_entry(unsigned klass, file_entry &e);
	unsigned fst_format(unsigned klass);
	unsigned fst_erase(unsigned klass);

	void gsos_return(unsigned acc);
	void mli_return(unsigned acc);

	/* mli */
	int mli_quit(unsigned dcb);
	int mli_close(unsigned dcb);
	int mli_flush(unsigned dcb);
	int mli_rw_block(unsigned dcb);

	int mli_destroy(unsigned dcb, const std::string &path);
	int mli_rename(unsigned dcb, const std::string &path1, const std::string &path2);
	int mli_open(unsigned dcb, const std::string &path);
	int mli_create(unsigned dcb, const std::string &path);
	int mli_get_file_info(unsigned dcb, const std::string &path);
	int mli_set_file_info(unsigned dcb, const std::string &path);


	int mli_read(unsigned dcb, file_entry &e);
	int mli_write(unsigned dcb, file_entry &e);
	int mli_close(unsigned dcb, file_entry &e);
	int mli_flush(unsigned dcb, file_entry &e);
	int mli_get_buf(unsigned dcb, file_entry &e);
	int mli_set_buf(unsigned dcb, file_entry &e);
	int mli_get_eof(unsigned dcb, file_entry &e);
	int mli_set_eof(unsigned dcb, file_entry &e);
	int mli_get_mark(unsigned dcb, file_entry &e);
	int mli_set_mark(unsigned dcb, file_entry &e);
	int mli_newline(unsigned dcb, file_entry &e);

	int mli_get_prefix(unsigned dcb);
	int mli_set_prefix(unsigned dcb);

	int mli_online(unsigned dcb);

	int mli_online_tail(unsigned dcb);
	int mli_set_prefix_tail(unsigned dcb);

	int mli_expand_path(std::string &path);


	std::string m_host_directory;
	std::pair<dev_t, ino_t> m_host_directory_id;


	std::vector<file_entry> m_files;

	/* mli */
	std::string m_mli_prefix;
	uint8_t m_mli_zp_save[16];
	unsigned m_mli_call;
	unsigned m_mli_dcb;
	unsigned m_mli_rts;
	unsigned m_mli_vector;
	unsigned m_mli_unit;

	required_ioport m_sysconfig;
	required_device<class g65816_device> m_maincpu;
	required_address_space m_space;
};

DECLARE_DEVICE_TYPE(APPLE2_HOST, ample_host_device)
#endif
