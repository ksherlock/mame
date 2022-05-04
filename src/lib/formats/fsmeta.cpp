// license:BSD-3-Clause
// copyright-holders:Olivier Galibert

// Filesystem metadata management

#include "fsmeta.h"

#include "strformat.h"

#include <optional>

namespace fs {

const char *meta_data::entry_name(meta_name name)
{
	switch(name) {
	case meta_name::basic: return "basic";
	case meta_name::creation_date: return "creation_date";
	case meta_name::length: return "length";
	case meta_name::loading_address: return "loading_address";
	case meta_name::locked: return "locked";
	case meta_name::modification_date: return "modification_date";
	case meta_name::name: return "name";
	case meta_name::os_minimum_version: return "os_minimum_version";
	case meta_name::os_version: return "os_version";
	case meta_name::rsrc_length: return "rsrc_length";
	case meta_name::sequential: return "sequential";
	case meta_name::size_in_blocks: return "size_in_blocks";
	case meta_name::file_type: return "file_type";
	case meta_name::ascii_flag: return "ascii_flag";
	case meta_name::owner_id: return "owner_id";
	case meta_name::attributes: return "attributes";
	case meta_name::oem_name: return "oem_name";
	}
	return "";
}

#if __APPLE__ && __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ < 101400
meta_type meta_value::type() const
{
	// MacOS < 10.14 doesn't have a complete std::variant
	// this is only used in the floppy tool so it doesn't affect Ample MAME.
	// std::variant<std::string, uint64_t, bool, util::arbitrary_datetime> value;
	switch(value.index())
	{
		case 0: return meta_type::string;
		case 1: return meta_type::number;
		case 2: return meta_type::flag;
		case 3: return meta_type::date;
		default: return meta_type::number;
	}
}

std::string meta_value::to_string() const
{
	switch(value.index())
	{
		case 0: return as_string();
		case 1: return util::string_format("0x%x", as_number());
		case 2: return as_flag() ? "t" : "f";
		case 3: {
			auto dt = as_date();
			return util::string_format("%04d-%02d-%02d %02d:%02d:%02d",
 				dt.year, dt.month, dt.day_of_month,
 				dt.hour, dt.minute, dt.second);
		}
		default: return util::string_format("0x%x", as_number());
	}
}

#else

template <class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template <class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

meta_type meta_value::type() const
{
	std::optional<meta_type> result;
	std::visit(
			overloaded{
				[&result] (const std::string &)              { result = meta_type::string; },
				[&result] (std::uint64_t)                    { result = meta_type::number; },
				[&result] (bool)                             { result = meta_type::flag; },
				[&result] (const util::arbitrary_datetime &) { result = meta_type::date; } },
			value);
	return *result;
}

std::string meta_value::to_string() const
{
	std::string result;
	std::visit(
			overloaded{
				[&result] (const std::string &val)              { result = val; },
				[&result] (std::uint64_t val)                   { result = util::string_format("0x%x", val); },
				[&result] (bool val)                            { result = val ? "t" : "f"; },
				[&result] (const util::arbitrary_datetime &val)
				{
					result = util::string_format("%04d-%02d-%02d %02d:%02d:%02d",
						val.year, val.month, val.day_of_month,
						val.hour, val.minute, val.second);
				} },
			value);
	return result;
}
#endif

} // namespace fs
