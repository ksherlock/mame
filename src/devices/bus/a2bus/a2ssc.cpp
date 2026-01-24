// license:BSD-3-Clause
// copyright-holders:R. Belmont
/*********************************************************************

	a2ssc.c

	Apple II Super Serial Card

	The Apricorn Super Serial Imager has separate "Modem" and
	"Printer" pin headers, which carry different arrangements of the
	same RS232 signals. Its GPI mode also features Videx VideoTerm
	support when that card is installed in slot 3.

*********************************************************************/

#include "emu.h"
#include "a2ssc.h"

#include "bus/rs232/rs232.h"
#include "machine/mos6551.h"

#include "imagedev/harddriv.h"
#include "multibyte.h"


#define LOG_CMD      (1U << 1)

#define VERBOSE (0)

// #define LOG_OUTPUT_FUNC osd_printf_info
#include "logmacro.h"

namespace {

//**************************************************************************
//  TYPE DEFINITIONS
//**************************************************************************

class a2bus_ssc_device:
	public device_t,
	public device_a2bus_card_interface
{
public:
	// construction/destruction
	a2bus_ssc_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock);

protected:
	a2bus_ssc_device(const machine_config &mconfig, device_type type, const char *tag, device_t *owner, uint32_t clock);

	virtual void device_start() override ATTR_COLD;
	virtual void device_reset() override ATTR_COLD;
	virtual void device_add_mconfig(machine_config &config) override ATTR_COLD;
	virtual const tiny_rom_entry *device_rom_region() const override ATTR_COLD;
	virtual ioport_constructor device_input_ports() const override ATTR_COLD;

	virtual uint8_t read_c0nx(uint8_t offset) override;
	virtual void write_c0nx(uint8_t offset, uint8_t data) override;
	virtual uint8_t read_cnxx(uint8_t offset) override;
	virtual uint8_t read_c800(uint16_t offset) override;
	virtual bool take_c800() const override { return true; }
	virtual void reset_from_bus() override;

	required_ioport m_dsw1, m_dsw2;
	required_ioport m_dswx;

	required_device<mos6551_device> m_acia;

	required_region_ptr<uint8_t> m_rom;

private:
	void acia_irq_w(int state);
};

class apricorn_ssi_device : public a2bus_ssc_device
{
public:
	// construction/destruction
	apricorn_ssi_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock);

protected:
	virtual void device_start() override ATTR_COLD;
	virtual const tiny_rom_entry *device_rom_region() const override ATTR_COLD;
	virtual ioport_constructor device_input_ports() const override ATTR_COLD;

	virtual void write_c0nx(uint8_t offset, uint8_t data) override;
	virtual uint8_t read_cnxx(uint8_t offset) override;
	virtual void write_cnxx(uint8_t offset, uint8_t data) override;
	virtual uint8_t read_c800(uint16_t offset) override;

private:
	bool m_alt_bank;
};



class a2bus_retronet_device: public a2bus_ssc_device
{
public:
	a2bus_retronet_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock);

protected:
	// construction/destruction
	a2bus_retronet_device(const machine_config &mconfig, device_type type, const char *tag, device_t *owner, uint32_t clock);

	virtual void device_start() override ATTR_COLD;
	// virtual void device_reset() override ATTR_COLD;
	virtual void device_add_mconfig(machine_config &config) override ATTR_COLD;
	virtual const tiny_rom_entry *device_rom_region() const override ATTR_COLD;
	// virtual ioport_constructor device_input_ports() const override ATTR_COLD;

	// overrides of standard a2bus slot functions
	// virtual uint8_t read_c0nx(uint8_t offset) override;
	// virtual void write_c0nx(uint8_t offset, uint8_t data) override;
	virtual uint8_t read_cnxx(uint8_t offset) override;
	virtual uint8_t read_c800(uint16_t offset) override;
	virtual void write_c800(uint16_t offset, uint8_t data) override;
	virtual bool take_c800() const override { return true; }
	virtual void reset_from_bus() override;

private:

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

	// required_region_ptr<uint8_t> m_rom;
	required_device_array<harddisk_image_device, 8> m_drive;


	std::error_condition load_hd(device_image_interface &image) const;


	uint8_t m_sp_control = 0;
	uint8_t m_output_mask = 0;
	uint16_t m_sp_read_offset = 0;
	uint16_t m_sp_write_offset = 0;
	uint16_t m_offset = 0;

	uint8_t m_sp_buffer[1024];


	enum
	{
		IOSEL_OFFSET    = 0x1000,
		IOSTRB_OFFSET   = 0x2000,

		CONTROL_NONE    = 0x00,
		CONTROL_PRODOS  = 0x01,
		CONTROL_SP      = 0x02,
		CONTROL_DONE    = 0x80,

		PRODOS_CMD_STATUS   = 0x00,
		PRODOS_CMD_READ     = 0x01,
		PRODOS_CMD_WRITE    = 0x02,

		PRODOS_I_CMD    = 0,
		PRODOS_I_UNIT   = 1,
		PRODOS_I_BLOCK  = 2,
		PRODOS_I_BUFFER = 4,

		PRODOS_O_RETVAL = 0,
		PRODOS_O_BUFFER = 1,

		SP_CMD_STATUS   = 0x00,
		SP_CMD_READBLK  = 0x01,
		SP_CMD_WRITEBLK = 0x02,
		SP_CMD_FORMAT   = 0x03,
		SP_CMD_CONTROL  = 0x04,
		SP_CMD_INIT     = 0x05,
		SP_CMD_OPEN     = 0x06,
		SP_CMD_CLOSE    = 0x07,
		SP_CMD_READ     = 0x08,
		SP_CMD_WRITE    = 0x09,

		SP_I_CMD    = 0,
		SP_I_PARAMS = 2,
		SP_I_BUFFER = 10,

		SP_O_RETVAL = 0,
		SP_O_BUFFER = 1,

		SP_PARAM_UNIT   = 0,
		SP_PARAM_CODE   = 3,
		SP_PARAM_BLOCK  = 3,

		SP_STATUS_STS   = 0x00,
		SP_STATUS_DCB   = 0x01,
		SP_STATUS_NLS   = 0x02,
		SP_STATUS_DIB   = 0x03,

		SP_SUCCESS  = 0x00,
		SP_BADCMD   = 0x01,
		SP_BUSERR   = 0x06,
		SP_BADCTL   = 0x21,

		SUCCESS     = 0x00,
		IO_ERROR    = 0x27,
		WRITE_PROT  = 0x2B,
	};


};




/***************************************************************************
	PARAMETERS
***************************************************************************/

ROM_START( ssc )
	ROM_REGION(0x800, "program", 0)
	ROM_LOAD( "341-0065-a.bin", 0x000000, 0x000800, CRC(b7539d4c) SHA1(6dab633470c6bc4cb3e81d09fda46597caf8ee57) )
ROM_END

ROM_START( ssi )
	ROM_REGION(0x2000, "program", 0) // "SSI Version 1.1"
	ROM_LOAD( "apricorn super serial imager - rom.bin", 0x0000, 0x2000, CRC(d251f7f1) SHA1(19f2bc1e60c3fd5e179c4a38f7ca4e3221553562) )
ROM_END


ROM_START( a2retronet ) // 2025-07-10
	ROM_REGION(0x4000, "program", 0)
	ROM_LOAD( "a2retronet-2025-07-08.bin", 0x0000, 0x4000, CRC(e34beaed) SHA1(e5dfa4ace24670997d4b3c2834c64e0c3af0b3ab))
ROM_END

static INPUT_PORTS_START( ssc )
	PORT_START("DSW1")
	PORT_DIPNAME( 0xf0, 0xe0, "Baud Rate" ) PORT_DIPLOCATION("SW1:4,3,2,1")
	PORT_DIPSETTING(    0x00, "Undefined/115200" )
	PORT_DIPSETTING(    0x10, "50" )
	PORT_DIPSETTING(    0x20, "75" )
	PORT_DIPSETTING(    0x30, "110" )
	PORT_DIPSETTING(    0x40, "135" )
	PORT_DIPSETTING(    0x50, "150" )
	PORT_DIPSETTING(    0x60, "300" )
	PORT_DIPSETTING(    0x70, "600" )
	PORT_DIPSETTING(    0x80, "1200" )
	PORT_DIPSETTING(    0x90, "1800" )
	PORT_DIPSETTING(    0xa0, "2400" )
	PORT_DIPSETTING(    0xb0, "3600" )
	PORT_DIPSETTING(    0xc0, "4800" )
	PORT_DIPSETTING(    0xd0, "7200" )
	PORT_DIPSETTING(    0xe0, "9600" )
	PORT_DIPSETTING(    0xf0, "19200" )
	PORT_BIT( 0x0c, IP_ACTIVE_LOW, IPT_UNUSED )
	PORT_DIPNAME( 0x03, 0x00, "Mode" ) PORT_DIPLOCATION("SW1:6,5")
	PORT_DIPSETTING(    0x00, "Communications Mode" )
	PORT_DIPSETTING(    0x01, "SIC P8 Emulation Mode" )
	PORT_DIPSETTING(    0x02, "Printer Mode" )
	PORT_DIPSETTING(    0x03, "SIC P8A Emulation Mode" )

	PORT_START("DSW2")
	PORT_DIPNAME( 0x80, 0x00, "Stop Bits" ) PORT_DIPLOCATION("SW2:1")
	PORT_DIPSETTING(    0x00, "1")
	PORT_DIPSETTING(    0x80, "2")
	PORT_DIPNAME( 0x20, 0x00, "Data Bits" ) PORT_DIPLOCATION("SW2:2") PORT_CONDITION("DSW1", 0x03, NOTEQUALS, 0x02)
	PORT_DIPSETTING(    0x20, "7")
	PORT_DIPSETTING(    0x00, "8")
	PORT_DIPNAME( 0x20, 0x00, "Delay After CR" ) PORT_DIPLOCATION("SW2:2") PORT_CONDITION("DSW1", 0x03, EQUALS, 0x02)
	PORT_DIPSETTING(    0x20, DEF_STR(None))
	PORT_DIPSETTING(    0x00, "1/4 sec")
	PORT_BIT( 0x50, IP_ACTIVE_LOW, IPT_UNUSED )
	PORT_DIPNAME( 0x0c, 0x00, "Parity" ) PORT_DIPLOCATION("SW2:4,3") PORT_CONDITION("DSW1", 0x03, NOTEQUALS, 0x02)
	PORT_DIPSETTING(    0x00, DEF_STR(None))
	PORT_DIPSETTING(    0x08, "None (2)")
	PORT_DIPSETTING(    0x04, "Odd")
	PORT_DIPSETTING(    0x0c, "Even")
	PORT_DIPNAME( 0x0c, 0x00, "Line Width" ) PORT_DIPLOCATION("SW2:4,3") PORT_CONDITION("DSW1", 0x03, EQUALS, 0x02)
	PORT_DIPSETTING(    0x00, "40 Characters")
	PORT_DIPSETTING(    0x04, "72 Characters")
	PORT_DIPSETTING(    0x08, "80 Characters")
	PORT_DIPSETTING(    0x0c, "132 Characters")
	PORT_DIPNAME( 0x02, 0x02, "End of Line" ) PORT_DIPLOCATION("SW2:5")
	PORT_DIPSETTING(    0x00, "Add LF after CR")
	PORT_DIPSETTING(    0x02, "Don't add LF after CR")
	PORT_BIT( 0x01, IP_ACTIVE_HIGH, IPT_CUSTOM ) PORT_READ_LINE_DEVICE_MEMBER("rs232", FUNC(rs232_port_device::cts_r))

	PORT_START("DSWX") // Non-memory-mapped DIP switches
	PORT_DIPNAME( 0x04, 0x04, "Interrupts" ) PORT_DIPLOCATION("SW2:6")
	PORT_DIPSETTING(    0x04, DEF_STR(Off))
	PORT_DIPSETTING(    0x00, DEF_STR(On))
	PORT_DIPNAME( 0x02, 0x00, "DCD Connected" ) PORT_DIPLOCATION("SW1:7")
	PORT_DIPSETTING(    0x00, DEF_STR(On))
	PORT_DIPNAME( 0x01, 0x01, "Secondary CTS Connected" ) PORT_DIPLOCATION("SW2:7")
	PORT_DIPSETTING(    0x01, DEF_STR(Off))
INPUT_PORTS_END

static INPUT_PORTS_START( ssi )
	PORT_START("DSW1")
	PORT_DIPNAME( 0x100, 0x100, "Emulation Mode" ) PORT_DIPLOCATION("SW1:8")
	PORT_DIPSETTING(     0x100, "Off (GPI)" )
	PORT_DIPSETTING(     0x000, "On (SSC)" )
	PORT_DIPNAME( 0xf0, 0xe0, "Baud Rate" ) PORT_DIPLOCATION("SW1:4,3,2,1")
	PORT_DIPSETTING(    0x00, "Undefined" )
	PORT_DIPSETTING(    0x10, "50" )
	PORT_DIPSETTING(    0x20, "75" )
	PORT_DIPSETTING(    0x30, "110" )
	PORT_DIPSETTING(    0x40, "135" )
	PORT_DIPSETTING(    0x50, "150" )
	PORT_DIPSETTING(    0x60, "300" )
	PORT_DIPSETTING(    0x70, "600" )
	PORT_DIPSETTING(    0x80, "1200" )
	PORT_DIPSETTING(    0x90, "1800" )
	PORT_DIPSETTING(    0xa0, "2400" )
	PORT_DIPSETTING(    0xb0, "3600" )
	PORT_DIPSETTING(    0xc0, "4800" )
	PORT_DIPSETTING(    0xd0, "7200" )
	PORT_DIPSETTING(    0xe0, "9600" )
	PORT_DIPSETTING(    0xf0, "19200" )
	PORT_BIT( 0x0c, IP_ACTIVE_LOW, IPT_UNUSED )
	PORT_DIPNAME( 0x03, 0x02, "SSC Mode" ) PORT_DIPLOCATION("SW1:6,5") PORT_CONDITION("DSW1", 0x100, EQUALS, 0x000)
	PORT_DIPSETTING(    0x00, "Communications" )
	PORT_DIPSETTING(    0x02, "Printer" )
	PORT_DIPNAME( 0x02, 0x02, "XON/XOFF Handshaking" ) PORT_DIPLOCATION("SW1:5") PORT_CONDITION("DSW1", 0x100, EQUALS, 0x100)
	PORT_DIPSETTING(    0x02, DEF_STR(Off))
	PORT_DIPSETTING(    0x00, DEF_STR(On))
	PORT_DIPNAME( 0x01, 0x00, "LF After CR" ) PORT_DIPLOCATION("SW1:6") PORT_CONDITION("DSW1", 0x100, EQUALS, 0x100)
	PORT_DIPSETTING(    0x01, DEF_STR(Off))
	PORT_DIPSETTING(    0x00, DEF_STR(On))

	PORT_START("DSW2")
	PORT_DIPNAME( 0x80, 0x80, "Stop Bits" ) PORT_DIPLOCATION("SW2:1") PORT_CONDITION("DSW1", 0x100, EQUALS, 0x000)
	PORT_DIPSETTING(    0x00, "1")
	PORT_DIPSETTING(    0x80, "2")
	PORT_DIPNAME( 0x40, 0x40, DEF_STR(Unused)) PORT_DIPLOCATION("SW2:7") PORT_CONDITION("DSW1", 0x100, EQUALS, 0x000)
	PORT_DIPSETTING(    0x40, DEF_STR(Off))
	PORT_DIPSETTING(    0x00, DEF_STR(On))
	PORT_DIPNAME( 0x20, 0x00, "Data Bits" ) PORT_DIPLOCATION("SW2:2") PORT_CONDITION("DSW1", 0x103, EQUALS, 0x000)
	PORT_DIPSETTING(    0x20, "7")
	PORT_DIPSETTING(    0x00, "8")
	PORT_DIPNAME( 0x20, 0x00, "CR Delay" ) PORT_DIPLOCATION("SW2:2") PORT_CONDITION("DSW1", 0x103, EQUALS, 0x002)
	PORT_DIPSETTING(    0x20, DEF_STR(None))
	PORT_DIPSETTING(    0x00, "32 ms")
	PORT_DIPNAME( 0x10, 0x10, DEF_STR(Unused)) PORT_DIPLOCATION("SW2:8") PORT_CONDITION("DSW1", 0x100, EQUALS, 0x000)
	PORT_DIPSETTING(    0x10, DEF_STR(Off))
	PORT_DIPSETTING(    0x00, DEF_STR(On))
	PORT_DIPNAME( 0x0c, 0x08, "Parity" ) PORT_DIPLOCATION("SW2:4,3") PORT_CONDITION("DSW1", 0x103, EQUALS, 0x000)
	PORT_DIPSETTING(    0x00, DEF_STR(None))
	PORT_DIPSETTING(    0x08, "None (2)")
	PORT_DIPSETTING(    0x04, "Odd")
	PORT_DIPSETTING(    0x0c, "Even")
	PORT_DIPNAME( 0x0c, 0x00, "Line Width" ) PORT_DIPLOCATION("SW2:4,3") PORT_CONDITION("DSW1", 0x103, EQUALS, 0x002)
	PORT_DIPSETTING(    0x00, "40 Characters (Echo On)")
	PORT_DIPSETTING(    0x04, "72 Characters (Echo Off)")
	PORT_DIPSETTING(    0x08, "80 Characters (Echo Off)")
	PORT_DIPSETTING(    0x0c, "132 Characters (Echo Off)")
	PORT_DIPNAME( 0x02, 0x00, "LF After CR" ) PORT_DIPLOCATION("SW2:5") PORT_CONDITION("DSW1", 0x100, EQUALS, 0x000)
	PORT_DIPSETTING(    0x02, DEF_STR(Off))
	PORT_DIPSETTING(    0x00, DEF_STR(On))
	PORT_DIPNAME( 0xa8, 0x88, "Printer Type" ) PORT_DIPLOCATION("SW2:3,2,1") PORT_CONDITION("DSW1", 0x100, EQUALS, 0x100)
	PORT_DIPSETTING(    0x08, "ImageWriter" )
	PORT_DIPSETTING(    0x88, "Epson" )
	PORT_DIPSETTING(    0x80, "Star Micronics" )
	PORT_DIPSETTING(    0x20, "Okidata" )
	PORT_DIPSETTING(    0x00, "C. Itoh" )
	PORT_DIPSETTING(    0x28, "Unknown (1)" )
	PORT_DIPSETTING(    0xa0, "Unknown (2)" )
	PORT_DIPSETTING(    0xa8, "Unknown (3)" )
	PORT_DIPNAME( 0x40, 0x40, "Video Echo" ) PORT_DIPLOCATION("SW2:7") PORT_CONDITION("DSW1", 0x100, EQUALS, 0x100)
	PORT_DIPSETTING(    0x40, DEF_STR(Off))
	PORT_DIPSETTING(    0x00, DEF_STR(On))
	PORT_DIPNAME( 0x10, 0x10, "Transparent Mode" ) PORT_DIPLOCATION("SW2:8") PORT_CONDITION("DSW1", 0x100, EQUALS, 0x100)
	PORT_DIPSETTING(    0x10, DEF_STR(Off))
	PORT_DIPSETTING(    0x00, DEF_STR(On))
	PORT_DIPNAME( 0x04, 0x04, DEF_STR(Unused)) PORT_DIPLOCATION("SW2:4") PORT_CONDITION("DSW1", 0x100, EQUALS, 0x100)
	PORT_DIPSETTING(    0x04, DEF_STR(Off))
	PORT_DIPSETTING(    0x00, DEF_STR(On))
	PORT_DIPNAME( 0x02, 0x00, "MSB Output" ) PORT_DIPLOCATION("SW2:5") PORT_CONDITION("DSW1", 0x100, EQUALS, 0x100)
	PORT_DIPSETTING(    0x02, "Clear 8th Bit" )
	PORT_DIPSETTING(    0x00, "Pass 8th Bit" )
	PORT_BIT( 0x01, IP_ACTIVE_HIGH, IPT_CUSTOM ) PORT_READ_LINE_DEVICE_MEMBER("rs232", FUNC(rs232_port_device::cts_r)) // TBD: implemented on SSI or not?

	PORT_START("DSWX")
	PORT_DIPNAME( 0x04, 0x04, "Interrupts" ) PORT_DIPLOCATION("SW2:6")
	PORT_DIPSETTING(    0x04, DEF_STR(Off))
	PORT_DIPSETTING(    0x00, DEF_STR(On))
	PORT_DIPNAME( 0x02, 0x00, "DCD Connected" ) PORT_DIPLOCATION("SW1:7")
	PORT_DIPSETTING(    0x00, DEF_STR(On))
	PORT_BIT( 0x01, IP_ACTIVE_LOW, IPT_UNUSED )
INPUT_PORTS_END

//-------------------------------------------------
//  input_ports - device-specific input ports
//-------------------------------------------------

ioport_constructor a2bus_ssc_device::device_input_ports() const
{
	return INPUT_PORTS_NAME( ssc );
}

ioport_constructor apricorn_ssi_device::device_input_ports() const
{
	return INPUT_PORTS_NAME( ssi );
}


//-------------------------------------------------
//  device_add_mconfig - add device configuration
//-------------------------------------------------

void a2bus_ssc_device::device_add_mconfig(machine_config &config)
{
	MOS6551(config, m_acia);
	m_acia->set_xtal(1.8432_MHz_XTAL);
	m_acia->irq_handler().set(FUNC(a2bus_ssc_device::acia_irq_w));
	m_acia->txd_handler().set("rs232", FUNC(rs232_port_device::write_txd));
	m_acia->rts_handler().set("rs232", FUNC(rs232_port_device::write_rts));
	m_acia->dtr_handler().set("rs232", FUNC(rs232_port_device::write_dtr));

	rs232_port_device &rs232(RS232_PORT(config, "rs232", default_rs232_devices, nullptr));
	rs232.rxd_handler().set(m_acia, FUNC(mos6551_device::write_rxd));
	rs232.dcd_handler().set(m_acia, FUNC(mos6551_device::write_dcd));
	rs232.dsr_handler().set(m_acia, FUNC(mos6551_device::write_dsr));
	rs232.cts_handler().set(m_acia, FUNC(mos6551_device::write_cts));
}

void a2bus_retronet_device::device_add_mconfig(machine_config &config)
{
	a2bus_ssc_device::device_add_mconfig(config);

	for (unsigned i = 0; i < m_drive.size(); ++i)
	{
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

	if (disk->get_info().sectorbytes != 512)
		return image_error::INVALIDIMAGE;

	return std::error_condition();
}


//-------------------------------------------------
//  rom_region - device-specific ROM region
//-------------------------------------------------

const tiny_rom_entry *a2bus_ssc_device::device_rom_region() const
{
	return ROM_NAME( ssc );
}

const tiny_rom_entry *apricorn_ssi_device::device_rom_region() const
{
	return ROM_NAME( ssi );
}

const tiny_rom_entry *a2bus_retronet_device::device_rom_region() const
{
	return ROM_NAME( a2retronet );
}


//**************************************************************************
//  LIVE DEVICE
//**************************************************************************

a2bus_ssc_device::a2bus_ssc_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock) :
		a2bus_ssc_device(mconfig, A2BUS_SSC, tag, owner, clock)
{
}

a2bus_ssc_device::a2bus_ssc_device(const machine_config &mconfig, device_type type, const char *tag, device_t *owner, uint32_t clock) :
		device_t(mconfig, type, tag, owner, clock),
		device_a2bus_card_interface(mconfig, *this),
		m_dsw1(*this, "DSW1"),
		m_dsw2(*this, "DSW2"),
		m_dswx(*this, "DSWX"),
		m_acia(*this, "acia"),
		m_rom(*this, "program")
{
}

apricorn_ssi_device::apricorn_ssi_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock) :
		a2bus_ssc_device(mconfig, APRICORN_SSI, tag, owner, clock),
		m_alt_bank(false)
{
}

a2bus_retronet_device::a2bus_retronet_device(const machine_config &mconfig, device_type type, const char *tag, device_t *owner, uint32_t clock) :
	a2bus_ssc_device(mconfig, type, tag, owner, clock),
	m_drive(*this, "hdd%u", 0)
{
}

a2bus_retronet_device::a2bus_retronet_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock) :
		a2bus_retronet_device(mconfig, A2BUS_A2RETRONET, tag, owner, clock)
{
}

//-------------------------------------------------
//  device_start - device-specific startup
//-------------------------------------------------

void a2bus_ssc_device::device_start()
{
}

void apricorn_ssi_device::device_start()
{
	save_item(NAME(m_alt_bank));
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

void a2bus_ssc_device::device_reset()
{
}


void a2bus_ssc_device::reset_from_bus()
{
	m_acia->reset();
}

void a2bus_retronet_device::reset_from_bus()
{
	a2bus_ssc_device::reset_from_bus();

	m_sp_control = CONTROL_NONE;
	m_output_mask = 0b11111111;
	m_sp_read_offset = 0;
	m_sp_write_offset = 0;
	m_offset = 0;
}


/*-------------------------------------------------
	read_cnxx - called for reads from this card's cnxx space
-------------------------------------------------*/

uint8_t a2bus_ssc_device::read_cnxx(uint8_t offset)
{
	return m_rom[(offset&0xff)+0x700];
}

uint8_t apricorn_ssi_device::read_cnxx(uint8_t offset)
{
	if (!machine().side_effects_disabled())
		m_alt_bank = false;
	return m_rom[offset | (BIT(m_dsw1->read(), 8) ? 0x1700 : 0x0700)];
}

uint8_t a2bus_retronet_device::read_cnxx(uint8_t offset)
{
	return m_rom[m_offset | (slotno() << 8) | offset];
}


void apricorn_ssi_device::write_cnxx(uint8_t offset, uint8_t data)
{
	// TBD: behavior guessed
	m_alt_bank = false;
}

/*-------------------------------------------------
	read_c800 - called for reads from this card's c800 space
-------------------------------------------------*/

uint8_t a2bus_ssc_device::read_c800(uint16_t offset)
{
	return m_rom[offset];
}

uint8_t apricorn_ssi_device::read_c800(uint16_t offset)
{
	if (BIT(m_dsw1->read(), 8))
		offset |= 0x1000;
	if (m_alt_bank)
		offset |= 0x800;
	return m_rom[offset];
}

uint8_t a2bus_retronet_device::read_c800(uint16_t offset)
{
	if (offset >= 0x7f0) return read_cffx(offset & 0x0f);

	return m_rom[m_offset | 0x0800 | offset];
}

void a2bus_retronet_device::write_c800(uint16_t offset, uint8_t data)
{
	if (offset >= 0x7f0) return write_cffx(offset & 0x0f, data);
}




/*-------------------------------------------------
	read_c0nx - called for reads from this card's c0nx space
-------------------------------------------------*/

uint8_t a2bus_ssc_device::read_c0nx(uint8_t offset)
{
	// dips at C0n1/C0n2, ACIA at C0n8/9/A/B

	if (BIT(offset, 3))
		return m_acia->read(offset & 3);
	else
	{
		uint8_t buffer = 0xff;
		if (!BIT(offset, 1))
			buffer &= m_dsw1->read();
		if (!BIT(offset, 0))
			buffer &= m_dsw2->read();
		return buffer;
	}
}

/*-------------------------------------------------
	write_c0nx - called for writes to this card's c0nx space
-------------------------------------------------*/

void a2bus_ssc_device::write_c0nx(uint8_t offset, uint8_t data)
{
	if (BIT(offset, 3))
		m_acia->write(offset & 3, data);
}

void apricorn_ssi_device::write_c0nx(uint8_t offset, uint8_t data)
{
	if (BIT(offset, 3))
		m_acia->write(offset & 3, data);
	else
		m_alt_bank = true;
}

void a2bus_ssc_device::acia_irq_w(int state)
{
	if (machine().ioport().safe_to_read())
	{
		if (!(m_dswx->read() & 4))
		{
			if (state)
			{
				raise_slot_irq();
			}
			else
			{
				lower_slot_irq();
			}
		}
	}
}

uint8_t a2bus_retronet_device::read_cffx(uint8_t offset)
{
	uint8_t rv = -1;

	switch (offset & 0x0f)
	{
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
			break;
	}

	return rv;
}

void a2bus_retronet_device::write_cffx(uint8_t offset, uint8_t data)
{
	switch (offset & 0x0f)
	{
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



void a2bus_retronet_device::do_control()
{
	unsigned command;
	[[maybe_unused]] unsigned unit;
	unsigned rv;

	switch (m_sp_control)
	{
		case CONTROL_PRODOS:

			command = m_sp_buffer[PRODOS_I_CMD];
			unit = m_sp_buffer[PRODOS_I_UNIT];
			rv = IO_ERROR;

			switch (command) {
			case PRODOS_CMD_STATUS:
				LOGMASKED(LOG_CMD, "PD CmdStatus(Device=$%02X)", unit);
				rv = pro_stat();
				break;

			case PRODOS_CMD_READ:
				LOGMASKED(LOG_CMD, "PD CmdRead(Device=$%02X)", unit);
				rv = pro_read();
				break;

			case PRODOS_CMD_WRITE:
				LOGMASKED(LOG_CMD, "PD CmdWrite(Device=$%02X)", unit);
				rv = pro_write();
				break;
			}
			m_sp_buffer[PRODOS_O_RETVAL] = rv;
			break;

		case CONTROL_SP:

			command = m_sp_buffer[SP_I_CMD];
			unit = m_sp_buffer[SP_I_PARAMS + SP_PARAM_UNIT];

			rv = SP_BADCMD;
			switch (command) {
				case SP_CMD_STATUS:
					LOGMASKED(LOG_CMD, "SP CmdStatus(Device=$%02X)", unit);
					rv = sp_stat();
					break;
				case SP_CMD_READBLK:
					LOGMASKED(LOG_CMD, "SP CmdReadBlock(Device=$%02X)", unit);
					rv = sp_read();
					break;
				case SP_CMD_WRITEBLK:
					LOGMASKED(LOG_CMD, "SP CmdWriteBlock(Device=$%02X)", unit);
					rv = sp_write();
					break;
				case SP_CMD_FORMAT:
					LOGMASKED(LOG_CMD, "SP CmdFormat(Device=$%02X)", unit);
					break;
				case SP_CMD_CONTROL:
					LOGMASKED(LOG_CMD, "SP CmdControl(Device=$%02X)", unit);
					break;
				case SP_CMD_INIT:
					LOGMASKED(LOG_CMD, "SP CmdInit(Device=$%02X)", unit);
					rv = SP_SUCCESS;
					break;
				case SP_CMD_OPEN:
					LOGMASKED(LOG_CMD, "SP CmdOpen(Device=$%02X)", unit);
					break;
				case SP_CMD_CLOSE:
					LOGMASKED(LOG_CMD, "SP CmdClose(Device=$%02X)", unit);
					break;
				case SP_CMD_READ:
					LOGMASKED(LOG_CMD, "SP CmdRead(Device=$%02X)", unit);
					break;
				case SP_CMD_WRITE:
					LOGMASKED(LOG_CMD, "SP CmdWrite(Device=$%02X)", unit);
					break;
			}
			m_sp_buffer[SP_O_RETVAL] = rv;
			break;
	}

	m_sp_read_offset = 0;
	m_sp_write_offset = 0;
	m_sp_control = CONTROL_DONE;
}



uint8_t a2bus_retronet_device::hdd_read(uint8_t drive, uint32_t block, uint8_t *data)
{
	if (drive >= m_drive.size()) return IO_ERROR;

	harddisk_image_device *disk = m_drive[drive];

	if (disk && disk->exists())
	{
		// TODO -- handle CHD with > 512 blocks?
		if (disk->read(block, data)) return SUCCESS;
	}

	return IO_ERROR;
}

uint8_t a2bus_retronet_device::hdd_write(uint8_t drive, uint32_t block, const uint8_t *data)
{
	if (drive >= m_drive.size()) return IO_ERROR;

	harddisk_image_device *disk = m_drive[drive];
	if (disk && disk->exists())
	{
		// TODO -- handle CHD with > 512 blocks?
		if (disk->write(block, data)) return SUCCESS;
	}

	return IO_ERROR;
}


size_t a2bus_retronet_device::hdd_blocks(uint8_t drive)
{
	if (drive >= m_drive.size()) return 0;

	harddisk_image_device *disk = m_drive[drive];
	if (disk && disk->exists())
	{
		const hard_disk_file::info &info = disk->get_info();
		size_t blocks = (info.cylinders * info.heads * info.sectors * info.sectorbytes ) / 512;

		return blocks;
	}
	return 0;
}



uint8_t a2bus_retronet_device::unit_to_drive(uint8_t unit) const
{
	uint8_t drive = unit >> 7;
	if ((unit >> 4 & 0x07) != slotno()) {
		drive += 0x02;
	}
	return drive;
}


uint8_t a2bus_retronet_device::pro_stat(void)
{
	const uint8_t unit = m_sp_buffer[PRODOS_I_UNIT];

	size_t blocks = hdd_blocks(unit_to_drive(unit));
	put_u16le(&m_sp_buffer[PRODOS_O_BUFFER], blocks);
	return blocks ? SUCCESS : IO_ERROR;
}


uint8_t a2bus_retronet_device::pro_read(void)
{
	const uint8_t unit = m_sp_buffer[PRODOS_I_UNIT];
	const uint16_t block = get_u16le(&m_sp_buffer[PRODOS_I_BLOCK]);

	return hdd_read(unit_to_drive(unit), block, &m_sp_buffer[PRODOS_O_BUFFER]);
}

uint8_t a2bus_retronet_device::pro_write(void)
{
	const uint8_t unit = m_sp_buffer[PRODOS_I_UNIT];
	const uint16_t block = get_u16le(&m_sp_buffer[PRODOS_I_BLOCK]);

	return hdd_write(unit_to_drive(unit), block, &m_sp_buffer[PRODOS_I_BUFFER]);
}


uint8_t a2bus_retronet_device::sp_stat(void)
{
	const uint8_t unit = m_sp_buffer[SP_I_PARAMS + SP_PARAM_UNIT];
	const uint8_t code = m_sp_buffer[SP_I_PARAMS + SP_PARAM_CODE];
	uint8_t *stat_list = &m_sp_buffer[SP_O_BUFFER];

	if (unit == 0)
	{
		if (code == SP_STATUS_STS)
		{
			memset(stat_list, 0x00, 8);

			unsigned count = 0;
			for (unsigned i = 0; i < m_drive.size(); ++i)
			{
				if (m_drive[i] && m_drive[i]->exists()) count++;
			}

			put_u16le(&stat_list[0], 8); // size
			stat_list[2 + 0] = count; /* number of drives */
			stat_list[2 + 1] = 0b01000000; // // block, write, read, online
			return SP_SUCCESS;
		}
	}
	else
	{
		if (code == SP_STATUS_STS || code == SP_STATUS_DIB)
		{
			const bool status = code == SP_STATUS_STS;

			memset(stat_list, 0x00, 26);

			size_t blocks = hdd_blocks(unit - 1);
			if (blocks)
				stat_list[2 + 0] = 0b11110000;  // block, write, read, online
			else
				stat_list[2 + 0] = 0b11100000;  // block, write, read;
			
			put_u24le(&stat_list[2+1], blocks);

			if (status)
			{
				put_u16le(&stat_list[0], 4); // size
			}
			else
			{
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

uint8_t a2bus_retronet_device::sp_read()
{
	const uint8_t *params = &m_sp_buffer[SP_I_PARAMS];
	uint8_t *buffer = &m_sp_buffer[SP_O_BUFFER];

	const uint8_t unit = params[SP_PARAM_UNIT];
	const uint32_t block = get_u24le(&params[SP_PARAM_BLOCK]);

	return hdd_read(unit - 1, block, buffer);
}

uint8_t a2bus_retronet_device::sp_write()
{
	const uint8_t *params = &m_sp_buffer[SP_I_PARAMS];
	const uint8_t *buffer = &m_sp_buffer[SP_I_BUFFER];

	const uint8_t unit = params[SP_PARAM_UNIT];
	const uint32_t block = get_u24le(&params[SP_PARAM_BLOCK]);

	return hdd_write(unit - 1, block, buffer);
}


} // anonymous namespace


//**************************************************************************
//  GLOBAL VARIABLES
//**************************************************************************

DEFINE_DEVICE_TYPE_PRIVATE(A2BUS_SSC,    device_a2bus_card_interface, a2bus_ssc_device,    "a2ssc",   "Apple Super Serial Card")
DEFINE_DEVICE_TYPE_PRIVATE(APRICORN_SSI, device_a2bus_card_interface, apricorn_ssi_device, "aprissi", "Apricorn Super Serial Imager")
DEFINE_DEVICE_TYPE_PRIVATE(A2BUS_A2RETRONET, device_a2bus_card_interface, a2bus_retronet_device, "a2retronet", "A2retroNET SmartPort Card")
