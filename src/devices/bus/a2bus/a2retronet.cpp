// license:BSD-3-Clause
// copyright-holders: Kelvin Sherlock, Oliver Schmidt
/*********************************************************************

    a2retronet.h

    Implementation of Oliver Schmidt's A2retroNET
    SmartPort mass storage controller.

*********************************************************************/

#include "emu.h"
#include "a2retronet.h"
#include "imagedev/harddriv.h"
#include "multibyte.h"

namespace {

#define A2RETRONET_ROM_REGION  "a2retronet_rom"

ROM_START( a2retronet )
	ROM_REGION(0x4000, A2RETRONET_ROM_REGION, 0)
	ROM_LOAD( "a2retronet.bin", 0x0000, 0x4000, CRC(e34beaed) SHA1(e5dfa4ace24670997d4b3c2834c64e0c3af0b3ab))
ROM_END

const uint32_t IOSEL_OFFSET = 0x1000;
const uint32_t IOSTRB_OFFSET = 0x2000;

#define CONTROL_NONE    0x00
#define CONTROL_PRODOS  0x01
#define CONTROL_SP      0x02
#define CONTROL_DONE    0x80

#define PRODOS_CMD_STATUS   0x00
#define PRODOS_CMD_READ     0x01
#define PRODOS_CMD_WRITE    0x02

#define PRODOS_I_CMD    0
#define PRODOS_I_UNIT   1
#define PRODOS_I_BLOCK  2
#define PRODOS_I_BUFFER 4

#define PRODOS_O_RETVAL 0
#define PRODOS_O_BUFFER 1

#define SP_CMD_STATUS   0x00
#define SP_CMD_READBLK  0x01
#define SP_CMD_WRITEBLK 0x02
#define SP_CMD_FORMAT   0x03
#define SP_CMD_CONTROL  0x04
#define SP_CMD_INIT     0x05
#define SP_CMD_OPEN     0x06
#define SP_CMD_CLOSE    0x07
#define SP_CMD_READ     0x08
#define SP_CMD_WRITE    0x09

#define SP_I_CMD    0
#define SP_I_PARAMS 2
#define SP_I_BUFFER 10

#define SP_O_RETVAL 0
#define SP_O_BUFFER 1

#define SP_PARAM_UNIT   0
#define SP_PARAM_CODE   3
#define SP_PARAM_BLOCK  3

#define SP_STATUS_STS   0x00
#define SP_STATUS_DCB   0x01
#define SP_STATUS_NLS   0x02
#define SP_STATUS_DIB   0x03

#define SP_SUCCESS  0x00
#define SP_BADCMD   0x01
#define SP_BUSERR   0x06
#define SP_BADCTL   0x21

#define SUCCESS     0x00
#define IO_ERROR    0x27
#define WRITE_PROT  0x2B


class a2bus_retronet_device:
	public device_t,
	public device_a2bus_card_interface
{
public:
	a2bus_retronet_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock);

protected:
	// construction/destruction
	a2bus_retronet_device(const machine_config &mconfig, device_type type, const char *tag, device_t *owner, uint32_t clock);

	virtual void device_start() override ATTR_COLD;
	virtual void device_reset() override ATTR_COLD;
	virtual void device_add_mconfig(machine_config &config) override ATTR_COLD;
	virtual const tiny_rom_entry *device_rom_region() const override ATTR_COLD;

	// overrides of standard a2bus slot functions
	virtual uint8_t read_c0nx(uint8_t offset) override;
	virtual void write_c0nx(uint8_t offset, uint8_t data) override;
	virtual uint8_t read_cnxx(uint8_t offset) override;
	virtual uint8_t read_c800(uint16_t offset) override;
	virtual void write_c800(uint16_t offset, uint8_t data) override;
	virtual bool take_c800() const override { return true; }
	virtual void reset_from_bus() override;

	uint8_t read_cffx(uint8_t offset);
	void write_cffx(uint8_t offset, uint8_t data);

	void do_control();

	uint8_t unit_to_drive(uint8_t unit) const;


	uint8_t hdd_read(uint8_t drive, uint32_t block, uint8_t *data);
	uint8_t hdd_write(uint8_t drive, uint32_t block, const uint8_t *data);
	size_t hdd_blocks(uint8_t drive);

	uint8_t pro_stat(void);
	uint8_t pro_read(void);
	uint8_t pro_write(void);

	uint8_t sp_stat(void);
	uint8_t sp_read(void);
	uint8_t sp_write(void);

	required_region_ptr<uint8_t> m_rom;
	required_device_array<harddisk_image_device, 8> m_drive;

private:


	std::error_condition load_hd(device_image_interface &image) const;


	uint8_t m_sp_control = 0;
	uint8_t m_output_mask = 0;
	uint16_t m_sp_read_offset = 0;
	uint16_t m_sp_write_offset = 0;
	uint16_t m_offset = 0;

	uint8_t m_sp_buffer[1024];

};

a2bus_retronet_device::a2bus_retronet_device(const machine_config &mconfig, device_type type, const char *tag, device_t *owner, uint32_t clock) :
	device_t(mconfig, type, tag, owner, clock),
	device_a2bus_card_interface(mconfig, *this),
	m_rom(*this, A2RETRONET_ROM_REGION),
	m_drive(*this, "hdd%u", 0)

{
}

a2bus_retronet_device::a2bus_retronet_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock) :
	a2bus_retronet_device(mconfig, A2BUS_A2RETRONET, tag, owner, clock)
{
}

void a2bus_retronet_device::device_add_mconfig(machine_config &config) {
	for (unsigned i = 0; i < m_drive.size(); ++i) {
		HARDDISK(config, m_drive[i], 0);
		m_drive[i]->set_device_load(FUNC(a2bus_retronet_device::load_hd));
	}
}

/*
 * for now, disk images need to have 512-byte sectors.  
 */
std::error_condition a2bus_retronet_device::load_hd(device_image_interface &image) const
{

	harddisk_image_device *disk = downcast<harddisk_image_device *>(&image);
	if (!disk->exists())
		return image_error::UNSPECIFIED;


	#if 0
	if (!image.set_block_size(512))
		return image_error::INVALIDIMAGE;
	#endif
	if (disk->get_info().sectorbytes != 512)
		return image_error::INVALIDIMAGE;

	#if 0	
	const hard_disk_file::info &info = image->get_info();

	if (info.sectorbytes != 512)
	{
		return image_error::INVALIDIMAGE;
	}
	#endif

	return std::error_condition();
}


const tiny_rom_entry *a2bus_retronet_device::device_rom_region() const
{
	return ROM_NAME( a2retronet );
}

void a2bus_retronet_device::device_start()
{
	save_item(NAME(m_sp_control));
	save_item(NAME(m_output_mask));
	save_item(NAME(m_sp_read_offset));
	save_item(NAME(m_sp_write_offset));
	save_item(NAME(m_offset));
	save_item(NAME(m_sp_buffer));
}

void a2bus_retronet_device::device_reset()
{
	reset_from_bus();
}

void a2bus_retronet_device::reset_from_bus()
{
	m_sp_control = CONTROL_NONE;
	m_output_mask = 0b11111111;
	m_sp_read_offset = 0;
	m_sp_write_offset = 0;
	m_offset = 0;
}


uint8_t a2bus_retronet_device::read_c0nx(uint8_t offset) {
	// ssc emulation, ignore for now.
	return -1;
}

uint8_t a2bus_retronet_device::read_cffx(uint8_t offset) {

	// printf("read_cffx(%02x)\n", offset);

	uint8_t rv = -1;

	switch (offset & 0x0f) {
		case 0:
			rv = m_sp_buffer[m_sp_read_offset];
			if (!machine().side_effects_disabled())
				m_sp_read_offset++;
			break;
		case 1:
			rv = m_sp_control;
			break;
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 8:
			break;
		case 9:
			if (!machine().side_effects_disabled())
			 	m_output_mask = 0b01111111;
			break;
		case 10:
			if (!machine().side_effects_disabled())
				m_output_mask = 0b11111111;
			break;
		case 11:
			if (!machine().side_effects_disabled())
				m_offset &= ~IOSTRB_OFFSET;
			break;
		case 12:
			if (!machine().side_effects_disabled())
				m_offset |= IOSTRB_OFFSET;
			break;
		case 13:
			if (!machine().side_effects_disabled())
				m_offset &= ~IOSEL_OFFSET;
			break;
		case 14:
			if (!machine().side_effects_disabled())
				m_offset |= IOSEL_OFFSET;
			break;

		case 15:
			// m_active = false;
			break;

	}

	return rv;

}

void a2bus_retronet_device::write_c0nx(uint8_t offset, uint8_t data) {
	// ssc emulation, ignore for now.
}

void a2bus_retronet_device::write_cffx(uint8_t offset, uint8_t data) {

	// printf("write_cffx(%02x, %02x)\n", offset, data);


	switch (offset & 0x0f) {
		case 0:
			m_sp_buffer[m_sp_write_offset++] = data;
			break;
		case 1:
			m_sp_control = data;
			do_control();
			break;

		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 8:
			break;

		case 9:
			 m_output_mask = 0b01111111;
			break;
		case 10:
			m_output_mask = 0b11111111;
			break;
		case 11:
			m_offset &= ~IOSTRB_OFFSET;
			break;
		case 12:
			m_offset |= IOSTRB_OFFSET;
			break;
		case 13:
			m_offset &= ~IOSEL_OFFSET;
			break;
		case 14:
			m_offset |= IOSEL_OFFSET;
			break;

		case 15:
			// m_active = false;
			break;
	}
}

// CnXX - /IOSEL
uint8_t a2bus_retronet_device::read_cnxx(uint8_t offset) {

	// printf("read_cnxx %02x\n", offset);
	return m_rom[m_offset | (slotno() << 8) | offset];
}

// C800 - /IOSTB
uint8_t a2bus_retronet_device::read_c800(uint16_t offset) {

	// printf("read_c800 %04x\n", offset);

	if (offset >= 0x7f0) return read_cffx(offset & 0x0f);

	return m_rom[m_offset | 0x0800 | offset];
}


void a2bus_retronet_device::write_c800(uint16_t offset, uint8_t data) {
	// printf("write_c800 %04x %02x\n", offset, data);
	if (offset >= 0x7f0) return write_cffx(offset & 0x0f, data);
}


void a2bus_retronet_device::do_control() {

	printf("do_control %02x\n", m_sp_control);
	switch (m_sp_control) {
	case CONTROL_PRODOS:

		printf("prodos command: %02x\n", m_sp_buffer[PRODOS_I_CMD]);

		switch (m_sp_buffer[PRODOS_I_CMD]) {
		case PRODOS_CMD_STATUS:
			m_sp_buffer[PRODOS_O_RETVAL] = pro_stat();
            break;

		case PRODOS_CMD_READ:
          	m_sp_buffer[PRODOS_O_RETVAL] = pro_read();
            break;

		case PRODOS_CMD_WRITE:
            m_sp_buffer[PRODOS_O_RETVAL] = pro_write();
            break;
		}
		break;

	case CONTROL_SP:

        switch (m_sp_buffer[SP_I_CMD]) {
            case SP_CMD_STATUS:
				printf("SP CmdStatus(Device=$%02X)\n", m_sp_buffer[SP_I_PARAMS]);
                m_sp_buffer[SP_O_RETVAL] = sp_stat();
                break;
            case SP_CMD_READBLK:
				printf("SP CmdReadBlock(Device=$%02X)\n", m_sp_buffer[SP_I_PARAMS]);
				m_sp_buffer[SP_O_RETVAL] = sp_read();
                break;
            case SP_CMD_WRITEBLK:
				printf("SP CmdWriteBlock(Device=$%02X)\n", m_sp_buffer[SP_I_PARAMS]);
				m_sp_buffer[SP_O_RETVAL] = sp_write();
                break;
            case SP_CMD_FORMAT:
                printf("SP CmdFormat(Device=$%02X)\n", m_sp_buffer[SP_I_PARAMS]);
                m_sp_buffer[SP_O_RETVAL] = SP_BADCMD;
                break;
            case SP_CMD_CONTROL:
                printf("SP CmdControl(Device=$%02X)\n", m_sp_buffer[SP_I_PARAMS]);
                m_sp_buffer[SP_O_RETVAL] = SP_BADCMD;
                break;
            case SP_CMD_INIT:
                printf("SP CmdInit(Device=$%02X)\n", m_sp_buffer[SP_I_PARAMS]);
                m_sp_buffer[SP_O_RETVAL] = SP_SUCCESS;
                break;
            case SP_CMD_OPEN:
                printf("SP CmdOpen(Device=$%02X)\n", m_sp_buffer[SP_I_PARAMS]);
                m_sp_buffer[SP_O_RETVAL] = SP_BADCMD;
                break;
            case SP_CMD_CLOSE:
                printf("SP CmdClose(Device=$%02X)\n", m_sp_buffer[SP_I_PARAMS]);
                m_sp_buffer[SP_O_RETVAL] = SP_BADCMD;
                break;
            case SP_CMD_READ:
                printf("SP CmdRead(Device=$%02X)\n", m_sp_buffer[SP_I_PARAMS]);
                m_sp_buffer[SP_O_RETVAL] = SP_BADCMD;
                break;
            case SP_CMD_WRITE:
                printf("SP CmdWrite(Device=$%02X)\n", m_sp_buffer[SP_I_PARAMS]);
                m_sp_buffer[SP_O_RETVAL] = SP_BADCMD;
                break;
        }
		break;
	}

	m_sp_read_offset = 0;
	m_sp_write_offset = 0;
	m_sp_control = CONTROL_DONE;
}



uint8_t a2bus_retronet_device::hdd_read(uint8_t drive, uint32_t block, uint8_t *data) {
	if (drive >= m_drive.size()) return IO_ERROR;

	harddisk_image_device *disk = m_drive[drive];

	if (disk) {
		// TODO -- handle CHD with > 512 blocks?
		if (disk->read(block, data)) return SUCCESS;
	}

	return IO_ERROR;
}

uint8_t a2bus_retronet_device::hdd_write(uint8_t drive, uint32_t block, const uint8_t *data) {
	if (drive >= m_drive.size()) return IO_ERROR;

	harddisk_image_device *disk = m_drive[drive];
	if (disk) {
		// TODO -- handle CHD with > 512 blocks?
		if (disk->write(block, data)) return SUCCESS;
	}

	return IO_ERROR;


}


size_t a2bus_retronet_device::hdd_blocks(uint8_t drive) {
	if (drive >= m_drive.size()) return 0;

	harddisk_image_device *disk = m_drive[drive];
	if (disk) {
		const hard_disk_file::info &info = disk->get_info();
		size_t blocks = (info.sectors * info.sectorbytes ) / 512;
		return blocks;
	}
	return 0;
}



uint8_t a2bus_retronet_device::unit_to_drive(uint8_t unit) const {
    uint8_t drive = unit >> 7;
    if ((unit >> 4 & 0x07) != slotno()) {
        drive += 0x02;
    } 
    return drive;
}


uint8_t a2bus_retronet_device::pro_stat(void) {
	const uint8_t unit = m_sp_buffer[PRODOS_I_UNIT];

	printf("pro_stat(%02x (%02x))\n", unit, unit_to_drive(unit));


	size_t blocks = hdd_blocks(unit_to_drive(unit));
	m_sp_buffer[PRODOS_O_BUFFER + 0] = blocks & 0xff;
	m_sp_buffer[PRODOS_O_BUFFER + 1] = (blocks >> 8) & 0xff;
	return blocks ? SUCCESS : IO_ERROR;
}


uint8_t a2bus_retronet_device::pro_read(void) {
	const uint8_t unit = m_sp_buffer[PRODOS_I_UNIT];
	const uint16_t block = get_u16le(&m_sp_buffer[PRODOS_I_BLOCK]);

	printf("pro_read(%02x (%02x), %04x)\n", unit, unit_to_drive(unit), block);

    return hdd_read(unit_to_drive(unit), block, &m_sp_buffer[PRODOS_O_BUFFER]);	
}

uint8_t a2bus_retronet_device::pro_write(void) {
	const uint8_t unit = m_sp_buffer[PRODOS_I_UNIT];
	const uint16_t block = get_u16le(&m_sp_buffer[PRODOS_I_BLOCK]);

	printf("pro_write(%02x (%02x), %04x)\n", unit, unit_to_drive(unit), block);

    return hdd_write(unit_to_drive(unit), block, &m_sp_buffer[PRODOS_O_BUFFER]);	
}


uint8_t a2bus_retronet_device::sp_stat(void) {
	const uint8_t *params = &m_sp_buffer[SP_I_PARAMS];
	uint8_t *stat_list = &m_sp_buffer[SP_O_BUFFER];
	const uint8_t unit = params[SP_PARAM_UNIT];
	const uint8_t code = params[SP_PARAM_CODE];

	if (unit == 0) {
		if (code == SP_STATUS_STS) {
			memset(stat_list, 0x00, 8);

			unsigned count = 0;
			for (unsigned i = 0; i < m_drive.size(); ++i) {
				if (m_drive[i]) count++;
			}

			put_u16le(&stat_list[0], 8); // size
			stat_list[2 + 0] = count; /* number of drives */
			stat_list[2 + 1] = 0b01000000; // // block, write, read, online
    		return SP_SUCCESS;
		}
	} else {
		if (code == SP_STATUS_STS || code == SP_STATUS_DIB) {
			const bool status = code == SP_STATUS_STS;

			memset(stat_list, 0x00, 26);


			size_t blocks = hdd_blocks(unit - 1);
			if (blocks) {
				stat_list[2 + 0] = 0b11110000;  // block, write, read, online
			} else {
				stat_list[2 + 0] = 0b11100000;  // block, write, read;
			}
			put_u24le(&stat_list[2+1], blocks);

            if (status) {
				put_u16le(&stat_list[0], 4); // size
            } else {
				put_u16le(&stat_list[0], 25); // size

                stat_list[2 +  4] = 10;   // id string length
                memcpy(&stat_list[2 + 5], "A2RETRONET      ", 16);
                stat_list[2 + 21] = 0x02;   // hard disk
                stat_list[2 + 22] = 0x00;   // removable
				put_u16le(&stat_list[2 + 23], 0x01); // firmware version
            }
            return SP_SUCCESS;
		}
	}

	return SP_BADCTL;
}

uint8_t a2bus_retronet_device::sp_read() {
	const uint8_t *params = &m_sp_buffer[SP_I_PARAMS];
	uint8_t *buffer = &m_sp_buffer[SP_O_BUFFER];

	const uint8_t unit = params[SP_PARAM_UNIT];
	const uint32_t block = get_u24le(&params[SP_PARAM_BLOCK]);

	return hdd_read(unit - 1, block, buffer);
}

uint8_t a2bus_retronet_device::sp_write() {
	const uint8_t *params = &m_sp_buffer[SP_I_PARAMS];
	const uint8_t *buffer = &m_sp_buffer[SP_O_BUFFER];

	const uint8_t unit = params[SP_PARAM_UNIT];
	const uint32_t block = get_u24le(&params[SP_PARAM_BLOCK]);

	return hdd_write(unit - 1, block, buffer);
}


} // anonymous namespace

DEFINE_DEVICE_TYPE_PRIVATE(A2BUS_A2RETRONET, device_a2bus_card_interface, a2bus_retronet_device, "a2retronet", "A2retroNET SmartPort Card")
