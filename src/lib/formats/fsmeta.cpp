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

std::optional<meta_name> meta_data::from_entry_name(const char *name)
{
	for (int i = 0; i <= (int)meta_name::max; i++)
	{
		if (!strcmp(name, entry_name((meta_name)i)))
			return (meta_name)i;
	}
	return {};
}

#if __APPLE__ && __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ < 101400

namespace {
	template <class V>
	const std::string &v_string(const V &value) { return *std::get_if<std::string>(&value); }

	template <class V>
	util::arbitrary_datetime v_date(const V &value) { return *std::get_if<util::arbitrary_datetime>(&value); }

	template <class V>
	bool v_flag(const V &value) { return *std::get_if<bool>(&value); }

	template <class V>
	uint64_t v_number(const V &value) { return *std::get_if<uint64_t>(&value); }


}

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

util::arbitrary_datetime meta_value::as_date() const
{
	util::arbitrary_datetime result = { 0, };

	switch(value.index()) {
		case 0:
			sscanf(v_string(value).c_str(), "%d-%d-%d %d:%d:%d", &result.year, &result.month, &result.day_of_month, &result.hour, &result.minute, &result.second);
			break;
		case 3:return v_date(value);
	}
	return result;
}


bool meta_value::as_flag() const
{
	bool result = false;

	switch(value.index()) {
		case 0: {
			const auto &s = v_string(value);
			return !s.empty() && s != "f";
		}
		case 2: return v_flag(value);
	}
	return result;
}

std::string meta_value::as_string() const
{
	switch(value.index())
	{
		case 0: return v_string(value);
		case 1: return util::string_format("0x%x", v_number(value));
		case 2: return v_flag(value) ? "t" : "f";
		case 3: {
			auto dt = v_date(value);
			return util::string_format("%04d-%02d-%02d %02d:%02d:%02d",
 				dt.year, dt.month, dt.day_of_month,
 				dt.hour, dt.minute, dt.second);
		}
		default: return util::string_format("0x%x", v_number(value));
	}
}

uint64_t meta_value::as_number() const
{
	switch(value.index())
	{
		case 0: return std::stoull(v_string(value));
		case 1: return v_number(value);
		case 2: return 0;
		case 3: return 0;
		case 4: return 0;
		default: return 0;
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

util::arbitrary_datetime meta_value::as_date() const
{
	util::arbitrary_datetime result = { 0, };

	std::visit(
		overloaded
		{
			[&result](const std::string &s)
			{
				sscanf(s.c_str(), "%d-%d-%d %d:%d:%d", &result.year, &result.month, &result.day_of_month, &result.hour, &result.minute, &result.second);
			},
			[&result](const util::arbitrary_datetime &dt) { result = dt; },
			[](std::uint64_t) { /* nonsensical */ },
			[](bool) { /* nonsensical */ }
		}, value);

	return result;
}

bool meta_value::as_flag() const
{
	bool result = false;

	std::visit(
		overloaded
		{
			[&result](const std::string &s) { result = !s.empty() && s != "f"; },
			[&result](bool b) { result = b; },
			[](std::uint64_t) { /* nonsensical */ },
			[](const util::arbitrary_datetime &) { /* nonsensical */ }
		}, value);
	return result;
}

std::string meta_value::as_string() const
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

uint64_t meta_value::as_number() const
{
	uint64_t result = 0;

	std::visit(overloaded
	{
		[&result](const std::string &s)             { result = std::stoull(s); },
		[&result](uint64_t i)                       { result = i; },
		[](const util::arbitrary_datetime &)        { /* nonsensical */ },
		[](bool)                                    { /* nonsensical */ }
	}, value);
	return result;
}

#endif

} // namespace fs
