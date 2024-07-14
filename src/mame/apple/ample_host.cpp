#include "emu.h"
#include "emuopts.h"
#include "corestr.h"
#include "cpu/g65816/g65816.h"

#include "ample_host.h"


#include <cstring>
#include <cstdio>
#include <cctype>

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/paths.h>
#include <sys/xattr.h>
#include <sys/attr.h>

#include "fst.h"
#include "gsos.h"
#include "mli.h"

#include <iostream>
#include <algorithm>

#define VERBOSE -1
#define LOG_FST 2
#define LOG_MLI 4
#define LOG_OUTPUT_STREAM std::cout
#include "logmacro.h"

enum {
	file_none,
	file_regular,
	file_resource,
	file_directory,
};

enum {
	translate_none,
	translate_crlf,
	translate_merlin,
};

enum {
	BIT_HOST_ENABLE,
	BIT_HOST_READ_ONLY,
	BIT_HOST_TRANSLATE_TEXT,
	BIT_HOST_TRANSLATE_MERLIN
};




struct ample_host_device::file_entry {

	file_entry() = default;
	file_entry(const file_entry &) = delete;
	file_entry(file_entry &&rhs) {
		path = std::move(rhs.path);
		dir_entries = std::move(rhs.dir_entries);
		dir_file = std::move(rhs.dir_file);

		fd = rhs.fd;
		offset = rhs.offset;
		type = rhs.type;
		access = rhs.access;
		translate = rhs.translate;
		buffer = rhs.buffer;
		level = rhs.level;
		newline_mask = rhs.newline_mask;
		newline_char = rhs.newline_char;

		rhs.fd = -1;
		rhs.close();
	}

	~file_entry() {
		if (fd >= 0) ::close(fd);
	}

	file_entry &operator=(const file_entry &) = delete;
	file_entry &operator=(file_entry &&rhs) {
		std::swap(fd, rhs.fd);

		path = std::move(rhs.path);
		dir_entries = std::move(rhs.dir_entries);
		dir_file = std::move(rhs.dir_file);
		offset = rhs.offset;
		type = rhs.type;
		access = rhs.access;
		translate = rhs.translate;
		buffer = rhs.buffer;
		level = rhs.level;
		newline_mask = rhs.newline_mask;
		newline_char = rhs.newline_char;

		rhs.close();
		return *this;
	} 

	constexpr operator bool() const {
		return type != file_none;
	}
	constexpr bool operator!() const {
		return type == file_none;
	}

	void close() {
		if (fd >= 0) ::close(fd);
		fd = -1;
		type = file_none;
		path.clear();
		dir_entries.clear();
		dir_file.clear();
	}

	std::string path;
	std::vector<std::string> dir_entries; // for gs/os fst
	std::vector<uint8_t> dir_file; // for prodos mli

	int fd = -1;
	off_t offset = 0;
	unsigned type = file_none;
	unsigned access = 0;
	unsigned translate = translate_none;

	/* mli */
	unsigned buffer = 0;
	unsigned level = 0;
	unsigned newline_mask = 0;
	unsigned newline_char = 0;
};




namespace {

	const unsigned dp_call_number = 0x30;
	const unsigned dp_param_blk_ptr = 0x32;
	const unsigned dp_dev1_num = 0x36;
	const unsigned dp_dev2_num = 0x38;
	const unsigned dp_path1_ptr = 0x3a;
	const unsigned dp_path2_ptr = 0x3e;
	const unsigned dp_path_flag = 0x42;

	const unsigned global_buffer = 0x009a00;

	enum {
		// important prodos locations
		MLI_ENTRY = 0xBF00,
		MLI_LEVEL = 0xBFD8,   // current file level
		MLI_DEVNUM = 0xBF30,  // last slot / drive
		MLI_DEVCNT = 0xBF31,  // count - 1
		MLI_DEVLST = 0xBF32,  // active device list
		MLI_PFIXPTR = 0xbf9a, // active prefix?
	};

	enum {
		path_absolute_host,
		path_absolute,
		path_relative,
	};




	#ifdef _WIN32
	typedef FILETIME host_time_t;
	typedef struct AFP_Info host_finder_info_t;
	#else
	typedef time_t host_time_t;
	typedef unsigned char host_finder_info_t[32];
	#endif

	struct file_info {
		host_time_t create_date;
		host_time_t modified_date;
		uint16_t access;
		uint16_t storage_type;
		uint16_t file_type;
		uint32_t aux_type;
		uint32_t eof;
		uint32_t blocks;
		uint32_t resource_eof;
		uint32_t resource_blocks;
		int has_fi;
		#ifdef _WIN32
		struct AFP_Info afp;
		#else
		uint8_t finder_info[32];
		#endif
	};


	/* check for .. path components */
	bool dotdot(const std::string &s) {
		unsigned st = 1;
		for (unsigned c : s) {
			switch(st) {
			case 0:
				if (c == '/') ++st;
				break;
			case 1:
			case 2:
				if (c == '/') { st = 1; break; }
				if (c == '.') { ++st; break; }
				st = 0;
				break;
			case 3:
				if (c == '/') return true;
				st = 0;
				break;
			}
		}
		if (st == 3) return true;
		return false;	
	}

	unsigned check_path(std::string &s) {
		/* block any path with .. components */
		/* if this is an absolute path, skip over the :Host: part */

		while (!s.empty() && s.back() == '/') s.pop_back();
		if (s.empty()) return 0;

		if (dotdot(s)) return badPathSyntax;

		if (s.front() != '/') return 0;
		if (s.length() < 5) return volNotFound;
		if (core_strnicmp("/host", s.c_str(), 5)) return volNotFound;
		if (s.length() > 5 && s[5] != '/') return volNotFound;

		auto pos = s.find_first_not_of('/', 5);
		if (pos == std::string::npos) s.clear();
		else s = s.substr(pos);
		return 0;
	}

	[[maybe_unused]] int classify_path(const std::string &s) {
		if (s[0] != '/') return path_relative;
		if (s.length() < 5) return path_absolute;
		if (core_strnicmp("/host", s.c_str(), 5)) return path_absolute;
		if (s.length() == 5 || s[5] == '/') return path_absolute_host;
		return path_absolute;
	}


	unsigned map_errno(int xerrno) {
		switch(xerrno) {
		case 0: return 0;
		case EBADF:
			return invalidRefNum;
		#ifdef EDQUOT
		case EDQUOT:
		#endif
		case EFBIG:
			return volumeFull;
		case ENOENT:
			return fileNotFound;
		case ENOTDIR:
			return pathNotFound;
		case ENOMEM:
			return outOfMem;
		case EEXIST:
			return dupPathname;
		case ENOTEMPTY:
			return invalidAccess;

		default:
			return drvrIOError;
		}
	}

	unsigned map_enoent(const std::string &path) {
		/*
		      ENOENT could be fileNotFound or pathNotFound
		*/
		std::string p(path);

		// for(;;) {
		struct stat st;
		// p = dirname(p);
		while (!p.empty() && p.back() != '/') p.pop_back();
		if (!p.empty()) p.pop_back();
		if (!p.empty() && ::stat(p.c_str(), &st) < 0) return pathNotFound;
		// }
		return fileNotFound;
	}

	unsigned map_errno(int xerrno, const std::string &path) {
		if (xerrno == ENOENT) return map_enoent(path);
		return map_errno(xerrno);
	}


	/* time to prodos 16 date/time */
	[[maybe_unused]] uint32_t time_to_prodos(time_t t) {

		uint32_t rv = 0;
		if (time == 0) return rv;

		struct tm *tm = localtime(&t);

		rv |= (tm->tm_year % 100) << 9;
		rv |= (tm->tm_mon + 1) << 5;
		rv |= tm->tm_mday;

		rv |= tm->tm_hour << 24;
		rv |= tm->tm_min << 16;
		return rv;
	}

	time_t prodos_to_time(uint32_t t) {

		if (!t) return 0;

		struct tm tm{};

		tm.tm_year = (t >> 9) & 0x7f;
		tm.tm_mon = ((t >> 5) & 0x0f) - 1;
		tm.tm_mday = (t >> 0) & 0x1f;

		tm.tm_hour = (t >> 24) & 0x1f;
		tm.tm_min = (t >> 16) & 0x3f;
		tm.tm_sec = 0;

		tm.tm_isdst = -1;

		// 00 - 39 => 2000-2039
		// 40 - 99 => 1940-1999
		if (tm.tm_year < 40) tm.tm_year += 100;

		return mktime(&tm);
	}

	[[maybe_unused]] time_t hextime_to_time(uint64_t t) {

		if (!t) return 0;
		struct tm tm{};

		tm.tm_sec = t & 0xff; t >>= 8;
		tm.tm_min = t & 0xff; t >>= 8;
		tm.tm_hour = t & 0xff; t >>= 8;
		tm.tm_year = t & 0xff; t >>= 8;
		tm.tm_mday = (t & 0xff) + 1; t >>= 8;
		tm.tm_mon = t & 0xff;
		tm.tm_isdst = -1;

		return mktime(&tm);
	}


	/* time to gs/os date/time */
	uint64_t time_to_hextime(time_t t) {
		uint64_t rv = 0;

		if (time == 0) return rv;
		struct tm *tm = localtime(&t);
		if (tm->tm_sec == 60) tm->tm_sec = 59;       /* leap second */

		rv = (rv << 8) | (tm->tm_wday + 1);
		rv = (rv << 8) | 0;
		rv = (rv << 8) | tm->tm_mon;
		rv = (rv << 8) | (tm->tm_mday - 1);
		rv = (rv << 8) | tm->tm_year;
		rv = (rv << 8) | tm->tm_hour;
		rv = (rv << 8) | tm->tm_min;
		rv = (rv << 8) | tm->tm_sec;


		return rv;
	}




	off_t get_offset(const ample_host_device::file_entry &e, unsigned base, uint32_t displacement) {

		off_t eof = ::lseek(e.fd, 0, SEEK_END);

		switch (base) {
		case startPlus:
			return displacement;
			break;
		case eofMinus:
			if (eof < 0) return -1;
			return eof - displacement;
			break;
		case markPlus:
			return e.offset + displacement;
			break;
		case markMinus:
			return e.offset - displacement;
			break;
		default:
			return -1;
		}
	}


	int open_data_fork(const std::string &path, unsigned &access, unsigned &terr) {

		int fd = -1;
		for (;;) {

			switch(access) {
			case readEnableAllowWrite:
			case readWriteEnable:
				fd = open(path.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC);
				break;
			case readEnable:
				fd = open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
				break;
			case writeEnable:
				fd = open(path.c_str(), O_WRONLY | O_NONBLOCK | O_CLOEXEC);
				break;
			}

			if (access == readEnableAllowWrite) {
				if (fd < 0) {
					access = readEnable;
					continue;
				}
				access = readWriteEnable;
			}
			break;
		}

		if (fd < 0)
			terr = map_errno(errno, path);

		return fd;
	}


	int open_resource_fork(const std::string &path, unsigned &access, unsigned &terr) {

		int fd = -1;

		/* under HFS, files have a resource fork.  under APFS, it may need to be created */

		std::string rpath = path + _PATH_RSRCFORKSPEC;
		for (;;) {

			switch(access) {
			case readEnableAllowWrite:
			case readWriteEnable:
				fd = open(rpath.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC | O_CREAT, 0666);
				break;
			case readEnable:
				fd = open(rpath.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
				break;
			case writeEnable:
				fd = open(rpath.c_str(), O_WRONLY | O_NONBLOCK | O_CLOEXEC | O_CREAT, 0666);
				break;
			}

			if (access == readEnableAllowWrite) {
				if (fd < 0) {
					access = readEnable;
					continue;
				}
				access = readWriteEnable;
			}
			break;
		}

		if (fd < 0)
			terr = map_errno(errno, path);

		return fd;
	}

	std::vector<std::string> read_directory(const std::string &path, unsigned &terr, bool mli=false) {


		std::vector<std::string> dirs;

		terr = 0;
		DIR *dp = opendir(path.c_str());
		if (!dp) {
			terr = map_errno(errno, path);
			return dirs;
		}

		for(;;) {
			struct dirent *d = readdir(dp);
			if (!d) break;

			if (d->d_name[0] == '.') continue;
			int len = strlen(d->d_name);
			if (mli && len > 15) continue;

			// exclude names with extended characters.
			if (std::any_of(d->d_name, d->d_name + len, [](char c){ return c > 0x7f; }))
				continue;


			switch(d->d_type) {
			case DT_DIR:
			case DT_REG:
				break;

			case DT_UNKNOWN:
			case DT_LNK: {
				struct stat st;
				int ok;
				std::string tmp = path;
				tmp += "/";
				tmp += d->d_name;
				ok = ::stat(tmp.c_str(), &st);
				if (ok == 0) {
					if (S_ISREG(st.st_mode)) break;
					if (S_ISDIR(st.st_mode)) break;
				}
			}
			/* drop through */
			default:
				continue;
			}
			dirs.push_back(d->d_name);
		}
		closedir(dp);

		std::sort(dirs.begin(), dirs.end(), [](const auto &a, const auto &b){
			return core_stricmp(a.c_str(), b.c_str()) < 0;
		});
		return dirs;
	}


	// see also path.cpp core_filename_extract_base()
	std::string basename(const std::string &filename) noexcept {

		auto loc = filename.find_last_of('/');
		if (loc != std::string::npos)
			return filename.substr(loc + 1);
		else
			return std::string();

	}

	unsigned lowercase_bits(const std::string &name) {
		unsigned rv = 0x8000;
		unsigned bit = 0x4000;

		for (auto c : name) {
			if (std::islower(c)) rv |= bit;
			bit >>= 1;
			if (!bit) break;
		}

		return rv;
	}



	void write_8(std::vector<uint8_t>::iterator &v, uint8_t x) {
		*v++ = x;
	}

	void write_16(std::vector<uint8_t>::iterator &v, uint16_t x) {
		*v++ = x & 0xff;
		*v++ = (x >> 8) & 0xff;
	}

	void write_24(std::vector<uint8_t>::iterator &v, uint32_t x) {
		*v++ = x & 0xff;
		*v++ = (x >> 8) & 0xff;
		*v++ = (x >> 16) & 0xff;
	}

	void write_32(std::vector<uint8_t>::iterator &v, uint32_t x) {
		*v++ = x & 0xff;
		*v++ = (x >> 8) & 0xff;
		*v++ = (x >> 16) & 0xff;
		*v++ = (x >> 24) & 0xff;
	}

	void write_string_15(std::vector<uint8_t>::iterator &v, const std::string &s) {
		int i;
		int l = std::min(15, (int)s.length());
		for (i = 0; i < l; ++i) *v++ = toupper(s[i]);
		for(; i < 15; ++i) *v++ = 0;
	}




	unsigned hex(uint8_t c) {
		if (c >= '0' && c <= '9') return c - '0';
		if (c >= 'a' && c <= 'f') return c + 10 - 'a';
		if (c >= 'A' && c <= 'F') return c + 10 - 'A';
		return 0;
	}


	int finder_info_to_filetype(const uint8_t *buffer, uint16_t &file_type, uint32_t &aux_type) {

		if (!memcmp("pdos", buffer + 4, 4))
		{
			if (buffer[0] == 'p') {
				file_type = buffer[1];
				aux_type = (buffer[2] << 8) | buffer[3];
				return 0;
			}
			if (!memcmp("PSYS", buffer, 4)) {
				file_type = 0xff;
				aux_type = 0x0000;
				return 0;
			}
			if (!memcmp("PS16", buffer, 4)) {
				file_type = 0xb3;
				aux_type = 0x0000;
				return 0;
			}

			// old mpw method for encoding.
			if (!isxdigit(buffer[0]) && isxdigit(buffer[1]) && buffer[2] == ' ' && buffer[3] == ' ')
			{
				file_type = (hex(buffer[0]) << 8) | hex(buffer[1]);
				aux_type = 0;
				return 0;
			}
		}
		if (!memcmp("TEXT", buffer, 4)) {
			file_type = 0x04;
			aux_type = 0x0000;
			return 0;
		}
		if (!memcmp("BINA", buffer, 4)) {
			file_type = 0x00;
			aux_type = 0x0000;
			return 0;
		}
		if (!memcmp("dImgdCpy", buffer, 8)) {
			file_type = 0xe0;
			aux_type = 0x0005;
			return 0;
		}

		if (!memcmp("MIDI", buffer, 4)) {
			file_type = 0xd7;
			aux_type = 0x0000;
			return 0;
		}

		if (!memcmp("AIFF", buffer, 4)) {
			file_type = 0xd8;
			aux_type = 0x0000;
			return 0;
		}

		if (!memcmp("AIFC", buffer, 4)) {
			file_type = 0xd8;
			aux_type = 0x0001;
			return 0;
		}

		return -1;
	}

	[[maybe_unused]] int file_type_to_finder_info(uint8_t *buffer, uint16_t file_type, uint32_t aux_type) {
		if (file_type > 0xff || aux_type > 0xffff) return -1;

		if (!file_type && aux_type == 0x0000) {
			memcpy(buffer, "BINApdos", 8);
			return 0;
		}

		if (file_type == 0x04 && aux_type == 0x0000) {
			memcpy(buffer, "TEXTpdos", 8);
			return 0;
		}

		if (file_type == 0xff && aux_type == 0x0000) {
			memcpy(buffer, "PSYSpdos", 8);
			return 0;
		}

		if (file_type == 0xb3 && aux_type == 0x0000) {
			memcpy(buffer, "PS16pdos", 8);
			return 0;
		}

		if (file_type == 0xd7 && aux_type == 0x0000) {
			memcpy(buffer, "MIDIpdos", 8);
			return 0;
		}
		if (file_type == 0xd8 && aux_type == 0x0000) {
			memcpy(buffer, "AIFFpdos", 8);
			return 0;
		}
		if (file_type == 0xd8 && aux_type == 0x0001) {
			memcpy(buffer, "AIFCpdos", 8);
			return 0;
		}
		if (file_type == 0xe0 && aux_type == 0x0005) {
			memcpy(buffer, "dImgdCpy", 8);
			return 0;
		}

		memcpy(buffer, "p   pdos", 8);
		buffer[1] = (file_type) & 0xff;
		buffer[2] = (aux_type >> 8) & 0xff;
		buffer[3] = (aux_type) & 0xff;
		return 0;
	}



	#undef _
	#define _(a, b, c) { a, sizeof(a) - 1, b, c }
	struct ftype_entry {
		const char *ext;
		unsigned length;
		unsigned file_type;
		unsigned aux_type;
	};

	static struct ftype_entry suffixes[] = {
		_("c",    0xb0, 0x0008),
		_("cc",   0xb0, 0x0008),
		_("h",    0xb0, 0x0008),
		_("rez",  0xb0, 0x0015),
		_("asm",  0xb0, 0x0003),
		_("mac",  0xb0, 0x0003),
		_("pas",  0xb0, 0x0005),
		_("txt",  0x04, 0x0000),
		_("text", 0x04, 0x0000),
		_("s",    0x04, 0x0000),
	};

	[[maybe_unused]] static struct ftype_entry prefixes[] = {
		_("m16.",  0xb0, 0x0003),
		_("e16.",  0xb0, 0x0003),
	};

	#undef _

	void synthesize_file_xinfo(const std::string &path, struct file_info &fi) {

		/* guess the file type / auxtype based on extension */

		auto dot = path.find_last_of("./");
		if (dot == std::string::npos) return;
		if (path[dot] != '/') return;
		// auto slash = path.find_last_of('/', dot);

		++dot;
		for (int n = 0; n < sizeof(suffixes) / sizeof(suffixes[0]); ++n) {
			if (!core_stricmp(path.c_str() + dot, suffixes[n].ext)) {
				fi.file_type = suffixes[n].file_type;
				fi.aux_type = suffixes[n].aux_type;
				return;
			}
		}
		return;
	}

	void get_file_xinfo(const std::string &path, struct file_info &fi) {

		ssize_t tmp;
		tmp = getxattr(path.c_str(), XATTR_RESOURCEFORK_NAME, NULL, 0, 0, 0);
		if (tmp < 0) tmp = 0;
		fi.resource_eof = tmp;
		fi.resource_blocks = (tmp + 511) / 512;

		tmp = ::getxattr(path.c_str(), XATTR_FINDERINFO_NAME, fi.finder_info, 32, 0, 0);
		if (tmp == 16 || tmp == 32) {
			fi.has_fi = 1;
			finder_info_to_filetype(fi.finder_info, fi.file_type, fi.aux_type);
		}
	}

	unsigned get_file_info(const std::string &path, struct file_info &fi, const std::pair<dev_t, ino_t>& host_folder_id) {
		struct stat st;
		memset(&fi, 0, sizeof(fi));

		int ok = ::stat(path.c_str(), &st);
		if (ok < 0) return map_errno(errno, path);

		fi.eof = st.st_size;
		fi.blocks = st.st_blocks;

		fi.create_date = st.st_ctime;
		fi.modified_date = st.st_mtime;

		#if defined(__APPLE__)
		fi.create_date = st.st_birthtime;
		#endif


		if (S_ISDIR(st.st_mode)) {
			fi.storage_type = directoryFile;
			fi.file_type = 0x0f;

			if (std::make_pair(st.st_dev, st.st_ino) == host_folder_id)
				fi.storage_type = 0x0f; // volume.
		} else if (S_ISREG(st.st_mode)) {
			fi.file_type = 0x06;
			if (st.st_size < 0x200) fi.storage_type = seedling;
			else if (st.st_size < 0x20000) fi.storage_type = sapling;
			else fi.storage_type = tree;
		} else {
			fi.storage_type = st.st_mode & S_IFMT;
			fi.file_type = 0;
		}
		// 0x01 = read enable
		// 0x02 = write enable
		// 0x04 = invisible
		// 0x08 = reserved
		// 0x10 = reserved
		// 0x20 = backup needed
		// 0x40 = rename enable
		// 0x80 = destroy enable

		fi.access = 0xc3;       // placeholder...

		if (S_ISREG(st.st_mode)) {
			get_file_xinfo(path, fi);

			if (!fi.has_fi) {
				synthesize_file_xinfo(path, fi);
			}
		}

		// get file type/aux type

		if (fi.resource_eof) fi.storage_type = extendedFile;

		return 0;
	}

	/* does not set eof/resource_eof */
	unsigned set_file_info(const std::string &path, const file_info &fi) {

		int ok;
		struct attrlist list;
		unsigned i = 0;
		struct timespec dates[2];

		if (fi.has_fi) {
			struct stat st;
			ok = stat(path.c_str(), &st);
			if (ok == 0 && S_ISREG(st.st_mode)) {
				ok = setxattr(path.c_str(), XATTR_FINDERINFO_NAME, fi.finder_info, 32, 0, 0);
				if (ok < 0) return map_errno(errno);
			}
		}

		memset(&list, 0, sizeof(list));
		memset(dates, 0, sizeof(dates));

		list.bitmapcount = ATTR_BIT_MAP_COUNT;
		list.commonattr  = 0;

		if (fi.create_date)
		{
			dates[i++].tv_sec = fi.create_date;
			list.commonattr |= ATTR_CMN_CRTIME;
		}

		if (fi.modified_date)
		{
			dates[i++].tv_sec = fi.modified_date;
			list.commonattr |= ATTR_CMN_MODTIME;
		}

		ok = 0;
		if (i) ok = setattrlist(path.c_str(), &list, dates, i * sizeof(struct timespec), 0);
		return 0;
	}


	std::vector<uint8_t> read_mli_directory(const std::string &path, const std::pair<dev_t, ino_t>& host_folder_id, unsigned &terr) {

		// synthesize some fake prodos directory entries.
		// blocks consist of forward/backward pointers, a directory header entry (first block only),
		// and file entries


		const unsigned entries_per_block = 0x0d;
		const unsigned entry_length = 0x27;

		std::vector<uint8_t> rv;

		std::vector<std::string> dirs = read_directory(path, terr, true);

		const unsigned blocks = (1 + dirs.size() + entries_per_block - 1) / entries_per_block;
		rv.resize(blocks * 512);

		file_info fi {};

		auto iter = rv.begin();
		terr = get_file_info(path, fi, host_folder_id);
		if (terr) {
			rv.clear();
			return rv;
		}

		bool root = fi.storage_type == 0x0f;
		std::string dirname = basename(path);
		if (dirname.empty()) dirname = 'HOST';
		if (dirname.length() > 15) dirname.resize(15);
		size_t len = dirname.length();

		// prev/next ptrs.
		write_16(iter, 0);
		write_16(iter, 0);

		if (root) {
			write_8(iter, 0xf0 | len);
		} else {
			write_8(iter, 0xd0 | len);
		}
		write_string_15(iter, dirname);

		if (root) {
			// reserved
			write_16(iter, 0);

			// last modified
			write_32(iter, time_to_prodos(fi.modified_date));

			// lowercase bits
			write_16(iter, lowercase_bits(dirname));
		} else {
			write_8(iter, 0x75); // password enabled
			iter += 7; // password
		}

		// creation date
		write_32(iter, time_to_prodos(fi.create_date));

		write_8(iter, 0); // version
		write_8(iter, 0); // min version
		write_8(iter, fi.access);
		write_8(iter, entry_length);
		write_8(iter, entries_per_block);

		// file counter (filled in later)
		write_16(iter, 0);

		// bitmap ptr / total blocks / parent_pointer / parent entry info
		write_16(iter, 0);
		write_16(iter, 0);

		unsigned count = 1;

		// now synthesize ....
		for (auto &leaf : dirs) {

			if (leaf.length() > 15) continue;

			std::string p = path + "/" + leaf;

			unsigned xerr = get_file_info(p, fi, host_folder_id);
			if (xerr) continue; //?


			if ((count % entries_per_block) == 0) {

				// move to the next block.
				auto fudge = 0x200 - 4 - (entries_per_block * entry_length);
				iter += fudge;

				// prev/next ptr
				write_16(iter, 0);
				write_16(iter, 0);
			}

			len = leaf.length();
			if (fi.storage_type == extendedFile)
				fi.storage_type = sapling;
			write_8(iter, (fi.storage_type << 4) | len);
			write_string_15(iter, leaf);
			write_8(iter, fi.file_type);
			write_16(iter, 0); // key pointer
			write_16(iter, fi.blocks);
			write_24(iter, fi.eof);
			write_32(iter, time_to_prodos(fi.create_date));
			write_16(iter, lowercase_bits(leaf));
			write_8(iter, fi.access);
			write_16(iter, fi.aux_type);
			write_32(iter, time_to_prodos(fi.modified_date));
			write_16(iter, 0); // header ptr.

			++count;
		}
		--count; // don't include header
		// update the count
		rv[4 + 0x21] = count & 0xff;
		rv[4 + 0x22] = (count >> 8) & 0xff;

		return rv;
	}




	void translate_in(std::vector<uint8_t> &data, unsigned tr) {
		if (tr == translate_crlf) {
			for (auto &c : data) {
				if (c == '\n') c = '\r';
			}
		}
		if (tr == translate_merlin) {
			for (auto &c : data) {
	          if (c == '\t') c = 0xa0;
	          if (c == '\n') c = '\r';
	          if (c != ' ') c |= 0x80;
			}
		}
	}

	void translate_out(std::vector<uint8_t> &data, unsigned tr) {
		if (tr == translate_crlf) {
			for (auto &c : data) {
				if (c == '\r') c = '\n';
			}
		}
		if (tr == translate_merlin) {
			for (auto &c : data) {
				if (c == 0xa0) c = '\t';
				c &= 0x7f;
				if (c == '\r') c = '\n';
			}
		}
	}
	unsigned mli_expected_pcount(unsigned call) {
		switch (call) {
		case CREATE: return 7;
		case DESTROY: return 1;
		case RENAME: return 2;
		case SET_FILE_INFO: return 7;
		case GET_FILE_INFO: return 10;
		case ONLINE: return 2;
		case ONLINE | 0x20: return 2;
		case SET_PREFIX: return 1;
		case SET_PREFIX | 0x20 : return 1;
		case GET_PREFIX: return 1;
		case OPEN: return 3;
		case NEWLINE: return 3;
		case READ: return 4;
		case WRITE: return 4;
		case CLOSE: return 1;
		case FLUSH: return 1;
		case SET_MARK: return 2;
		case GET_MARK: return 2;
		case SET_EOF: return 2;
		case GET_EOF: return 2;
		case SET_BUF: return 2;
		case GET_BUF: return 2;

		case HOST_INIT: return 4;

		default: return 0;
		}
	}

	const char *error_name(unsigned error) {
		static const char *errors[] = {
			"",
			"badSystemCall",
			"",
			"",
			"invalidPcount",
			"",
			"",
			"gsosActive",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			// 0x10
			"devNotFound",
			"invalidDevNum",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			// 0x20
			"drvrBadReq",
			"drvrBadCode",
			"drvrBadParm",
			"drvrNotOpen",
			"drvrPriorOpen",
			"irqTableFull",
			"drvrNoResrc",
			"drvrIOError",
			"drvrNoDevice",
			"drvrBusy",
			"",
			"drvrWrtProt",
			"drvrBadCount",
			"drvrBadBlock",
			"drvrDiskSwitch",
			"drvrOffLine",
			// 0x30
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			// 0x40
			"badPathSyntax",
			"",
			"tooManyFilesOpen",
			"invalidRefNum",
			"pathNotFound",
			"volNotFound",
			"fileNotFound",
			"dupPathname",
			"volumeFull",
			"volDirFull",
			"badFileFormat",
			"badStoreType",
			"eofEncountered",
			"outOfRange",
			"invalidAccess",
			"buffTooSmall",
			// 0x50
			"fileBusy",
			"dirError",
			"unknownVol",
			"paramRangeErr",
			"outOfMem",
			"",
			"badBufferAddress",             /* P8 MLI only */
			"dupVolume",
			"notBlockDev",
			"invalidLevel",
			"damagedBitMap",
			"badPathNames",
			"notSystemFile",
			"osUnsupported",
			"",
			"stackOverflow",
			// 0x60
			"dataUnavail",
			"endOfDir",
			"invalidClass",
			"resForkNotFound",
			"invalidFSTID",
			"invalidFSTop",
			"fstCaution",
			"devNameErr",
			"defListFull",
			"supListFull",
			"fstError",
			"",
			"",
			"",
			"",
			"",
			//0x70
			"resExistsErr",
			"resAddErr",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			//0x80
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"networkError"
		};

		if (error < sizeof(errors) / sizeof(errors[0]))
			return errors[error];
		return "";
	}



}


ample_host_device::ample_host_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock) :
	device_t(mconfig, APPLE2_HOST, tag, owner, clock),
	m_sysconfig(*this, "ample_config"),
	m_maincpu(*this, finder_base::DUMMY_TAG),
	m_space(*this, finder_base::DUMMY_TAG, -1)
{
}

INPUT_PORTS_START( ample_host )
	PORT_START("ample_config")
	PORT_CONFNAME( 0x01, 0x01, "Host FST Enabled")
	PORT_CONFSETTING(    0x00, DEF_STR(No))
	PORT_CONFSETTING(    0x01, DEF_STR(Yes))
	PORT_CONFNAME( 0x02, 0x00, "Read Only")
	PORT_CONFSETTING(    0x00, DEF_STR(No))
	PORT_CONFSETTING(    0x03, DEF_STR(Yes))
	PORT_CONFNAME( 0x04, 0x04, "CR/LF Translation")
	PORT_CONFSETTING(    0x00, DEF_STR(No))
	PORT_CONFSETTING(    0x04, DEF_STR(Yes))
	PORT_CONFNAME( 0x08, 0x00, "Merlin Translation")
	PORT_CONFSETTING(    0x00, DEF_STR(No))
	PORT_CONFSETTING(    0x08, DEF_STR(Yes))
INPUT_PORTS_END

ioport_constructor ample_host_device::device_input_ports() const
{
	return INPUT_PORTS_NAME(ample_host);
}

void ample_host_device::device_start()
{
	m_host_directory.clear();
	m_host_directory_id = {0, 0}; // std::make_pair<dev_t, ino_t>(0, 0);
}

void ample_host_device::device_reset()
{
	m_host_directory.clear();
	m_host_directory_id = {0, 0};

	/* close open files */
	m_files.clear();
}

void ample_host_device::device_stop()
{
	m_host_directory.clear();
	m_host_directory_id = { 0, 0 };

	/* close open files */
	m_files.clear();
}


void ample_host_device::wdm_w(offs_t offset, uint8_t data)
{
	/* data = wdm byte, offset = address */

	if (!BIT(m_sysconfig->read(), BIT_HOST_ENABLE)) return ;

	switch(data) {
	case 0xa0: host_print(); break;
	case 0xa1: host_hexdump(); break;
	case 0xfc: host_mli(); break;
	case 0xff: host_fst(); break;
	}

}

std::string ample_host_device::read_string(uint32_t address, unsigned type, bool sevenbit) {

	std::string rv;
	unsigned length = 0;
	if (!address) return rv;

	switch(type) {
	case 0:
		/* c-string */
		for(;;) {
			unsigned char c = m_space->read_byte(address++);
			if (!c) break;
			if (sevenbit && c == 0) break;
			rv.push_back(c);
		}
		break;
	case 1:
		length = m_space->read_byte(address);
		address += 1;
		break;
	case 2:
		length = m_space->read_word(address);
		address += 2;
		break;
	}
	if (length) {
		rv.reserve(length);
		for (unsigned i = 0; i < length; ++i)
			rv.push_back(m_space->read_byte(address++));
	}
	if (sevenbit) for (auto &c : rv) c &= 0x7f;
	return rv;
}

unsigned ample_host_device::write_string(uint32_t address, const std::string &str, unsigned type, bool truncate) {

	address &= 0x00ffffff;
	if (!address) return 0;
	unsigned rv = 0;

	size_t l = str.length();
	size_t capacity;

	switch(type) {
	case 0:
		/* c-string */
		capacity = l;
		break;
	case 1:
		/* p-string */
		capacity = 255;
		if (l > 255) {
			l = 255;
		}
		m_space->write_byte(address++, l);
		break;
	case 2:
		/* gs-os output string */
		capacity = m_space->read_dword(address);
		address += 2;
		if (capacity < 4) return paramRangeErr;
		capacity -= 4;
		m_space->write_word(address, std::min(l, (size_t)0xffff));
		address += 2;
		if (capacity < l) {
			rv = buffTooSmall;
			if (!truncate) return rv;
		}
		break;
	}

	for (size_t i = 0; i < l; ++i) {
		m_space->write_byte(address++, str[i]);
	}
	if (type == 0) m_space->write_byte(address, 0);
	return rv;
}

void ample_host_device::write_data(uint32_t address, const std::vector<uint8_t> &data) {
	if (!address) return;
	for (auto &c : data) {
		m_space->write_byte(address++, c);
	}
}

void ample_host_device::write_data(uint32_t address, const uint8_t * data, size_t size) {
	if (!address) return;
	while (size--) {
		m_space->write_byte(address++, *data++);
	}
}

unsigned ample_host_device::write_option_list(uint32_t address, unsigned fstID, const uint8_t *data, unsigned size) {

	address &= 0x00ffffff;
	if (!address) return 0;

	unsigned cap = m_space->read_word(address);
	address += 2;

	if (cap < 4) return paramRangeErr;
	// required size
	m_space->write_word(address, size + 2);
	address += 2;
	if (cap < size + 6) return buffTooSmall;

	m_space->write_word(address, fstID);
	address += 2;

	while (size--)
		m_space->write_byte(address++, *data++);
	return 0;
}


bool ample_host_device::common_start()
{
	struct stat st;

	std::string tmp = machine().options().share_directory();
	if (tmp.empty()) return false;

	if (::stat(tmp.c_str(), &st) < 0) return false;
	if (!S_ISDIR(st.st_mode)) return false;

	if (tmp.back() != '/') tmp.push_back('/');

	m_host_directory = std::move(tmp);
	m_host_directory_id = std::make_pair(st.st_dev, st.st_ino);

	return true;
}



unsigned ample_host_device::fst_startup()
{
	LOGMASKED(LOG_FST, "fst_startup()\n");
	/* called during the initial boot into GS/OS */

	return common_start() ? 0 : invalidFSTop;
}

unsigned ample_host_device::fst_shutdown()
{

	LOGMASKED(LOG_FST, "fst_shutdown()\n");
	/* called when switching to p8 */

	/* close open files */
	for (auto &f : m_files) {
		f.close();
	}
	m_files.clear();

	return 0;
}

void ample_host_device::gsos_return(unsigned acc) {
	unsigned p = m_maincpu->g65816_get_reg(g65816_device::G65816_P);
	/* semi-simulate cmp #1 */
	if (acc) {
		p |= 1; // SEC
		p &= ~2; // CLZ
	} else {
		p &= ~1; // CLC
		p |= 2; // SEZ
	}
	m_maincpu->g65816_set_reg(g65816_device::G65816_P, p);
	m_maincpu->g65816_set_reg(g65816_device::G65816_A, acc);
}

void ample_host_device::mli_return(unsigned err) {
	unsigned p = m_maincpu->g65816_get_reg(g65816_device::G65816_P);
	unsigned a = m_maincpu->g65816_get_reg(g65816_device::G65816_A);
	err &= 0xff;
	/* semi-simulate cmp #1 */
	if (err) {
		p |= 1; // SEC
		p &= ~2; // CLZ
	} else {
		p &= ~1; // CLC
		p |= 2; // SEZ
	}
	a = (a & 0xff00) | err;
	m_maincpu->g65816_set_reg(g65816_device::G65816_P, p);
	m_maincpu->g65816_set_reg(g65816_device::G65816_A, a);
}

std::string ample_host_device::fst_get_path1() {
	std::string rv;
	unsigned dp = m_maincpu->g65816_get_reg(g65816_device::G65816_D);
	unsigned flags = m_space->read_word(dp + dp_path_flag);
	if (flags & (1 << 14)) {
		uint32_t address = m_space->read_dword(dp + dp_path1_ptr) & 0xffffff;
		rv = read_string(address, 2);
		// std::replace(rv.begin(), rv.end(), ':', '/');
		strreplacechr(rv, ':', '/');
	}
	return rv;
}

std::string ample_host_device::fst_get_path2() {
	std::string rv;
	unsigned dp = m_maincpu->g65816_get_reg(g65816_device::G65816_D);
	unsigned flags = m_space->read_word(dp + dp_path_flag);
	if (flags & (1 << 6)) {
		uint32_t address = m_space->read_dword(dp + dp_path2_ptr) & 0xffffff;
		rv = read_string(address, 2);
		// std::replace(rv.begin(), rv.end(), ':', '/');
		strreplacechr(rv, ':', '/');
	}
	return rv;
}

void ample_host_device::host_fst()
{
  /*
   * input:
   * c = set
   * a = default error code
   * x = gs/os callnum
   * y = [varies]
   *
   * output:
   * c = set/clear
   * a = error code/0
   * x = varies
   * y = varies
   */

	unsigned call = m_maincpu->g65816_get_reg(g65816_device::G65816_X);
	unsigned terr = 0;

	LOG("host fst: x=%04x\n", call);

	if (call & 0x8000) {
		// system level.
		switch(call) {
		case 0x8001:
			terr = fst_startup();
			break;
		case 0x8002:
			terr = fst_shutdown();
			break;
		default:
			terr = badSystemCall;
			break;
		}
		gsos_return(terr);
		return;
	}

	if (m_host_directory.empty()) {
		gsos_return(networkError);
		return;
	}

    unsigned klass = call >> 13;
    call &= 0x1fff;
    if (klass > 1) {
    	gsos_return(invalidClass);
    	return;
    }


    std::string path1;
    std::string path2;
    file_entry *e = nullptr;
    switch(call & 0xff) {
      case 0x01:
      case 0x02:
      case 0x05:
      case 0x06:
      case 0x0b:
      case 0x10:
        path1 = fst_get_path1();
        terr = check_path(path1);
        if (terr) {
        	gsos_return(terr);
        	return;
        }
        break;

      case 0x04:
        path1 = fst_get_path1();
        path2 = fst_get_path2();

        terr = check_path(path1);
        if (terr) {
        	gsos_return(terr);
        	return;
        }

        terr = check_path(path2);
        if (terr) {
        	gsos_return(terr);
        	return;
        }

        break;

      case 0x14: // close
      case 0x15: // flush
      	e = fst_get_file_entry(m_maincpu->g65816_get_reg(g65816_device::G65816_Y));
      	if (!e) {
      		gsos_return(invalidRefNum);
      		return;
      	}
      	break;

      case 0x12: // read
      case 0x13: // write
      case 0x16: // set mark
      case 0x17: // get mark
      case 0x18: // set eof
      case 0x19: // get eof
      	e = fst_get_file_entry(m_maincpu->g65816_get_reg(g65816_device::G65816_Y));
      	if (!e) {
      		gsos_return(invalidRefNum);
      		return;
      	}
      	if (e->type == file_directory) {
      		gsos_return(badStoreType);
      		return;
      	}
      	break;

      case 0x1c: // get dir entry
      	e = fst_get_file_entry(m_maincpu->g65816_get_reg(g65816_device::G65816_Y));
      	if (!e) {
      		gsos_return(invalidRefNum);
      		return;
      	}
      	if (e->type != file_directory) {
      		gsos_return(badStoreType);
      		return;
      	}
      	break;
    }

    switch(call & 0xff) {
      case 0x01:
        terr = fst_create(klass, m_host_directory + path1);
        break;
      case 0x02:
        terr = fst_destroy(klass, m_host_directory + path1);
        break;
      case 0x04:
        terr = fst_change_path(klass, m_host_directory + path1, m_host_directory + path2);
        break;
      case 0x05:
        terr = fst_set_file_info(klass, m_host_directory + path1);
        break;
      case 0x06:
        terr = fst_get_file_info(klass, m_host_directory + path1);
        break;
      case 0x07:
        terr = fst_judge_name(klass);
        break;
      case 0x08:
        terr = fst_volume(klass);
        break;
      case 0x0b:
        terr = fst_clear_backup(klass, m_host_directory + path1);
        break;
      case 0x10:
        terr = fst_open(klass, m_host_directory + path1);
        break;
      case 0x012:
        terr = fst_read(klass, *e);
        break;
      case 0x013:
        terr = fst_write(klass, *e);
        break;
      case 0x14:
        terr = fst_close(klass, *e);
        break;
      case 0x15:
        terr = fst_flush(klass, *e);
        break;
      case 0x16:
        terr = fst_set_mark(klass, *e);
        break;
      case 0x17:
        terr = fst_get_mark(klass, *e);
        break;
      case 0x18:
        terr = fst_set_eof(klass, *e);
        break;
      case 0x19:
        terr = fst_get_eof(klass, *e);
        break;
      case 0x1c:
        terr = fst_get_dir_entry(klass, *e);
        break;
      case 0x24:
        terr = fst_format(klass);
        break;
      case 0x25:
        terr = fst_erase(klass);
        break;

      default:
        terr = invalidFSTop;
        break;
    }

    if (terr) {
    	LOGMASKED(LOG_FST, " --> %04x (%s)\n", terr, error_name(terr));
    }
    gsos_return(terr);
}

ample_host_device::file_entry *ample_host_device::fst_get_file_entry(unsigned cookie)
{
	if (cookie == 0 || cookie > m_files.size()) return nullptr;

	auto &e = m_files[cookie-1];
	if (!e) return nullptr;
	return &e;
}

ample_host_device::file_entry *ample_host_device::mli_get_file_entry(unsigned cookie)
{
	cookie = cookie - 0x80;
	if (cookie == 0 || cookie > m_files.size()) return nullptr;

	auto &e = m_files[cookie-1];
	if (!e) return nullptr;
	return &e;
}

unsigned ample_host_device::fst_close(unsigned klass, file_entry &e)
{
	LOGMASKED(LOG_FST, "fst_close(%s)\n", e.path.c_str());

	e.close();
	if (&m_files.back() == &e) m_files.pop_back(); 
	return 0;
}


unsigned ample_host_device::fst_flush(unsigned klass, file_entry &e)
{
	LOGMASKED(LOG_FST, "fst_flush(%s)\n", e.path.c_str());

	if (e.type == file_directory) return 0;

	int ok = ::fsync(e.fd);
	if (ok < 0) return map_errno(errno);
	return 0;
}



unsigned ample_host_device::fst_read(unsigned klass, file_entry &e)
{
	LOGMASKED(LOG_FST, "fst_read(%s)\n", e.path.c_str());

	unsigned dp = m_maincpu->g65816_get_reg(g65816_device::G65816_D);
	uint32_t pb = m_space->read_dword(dp + dp_param_blk_ptr) & 0x00ffffff;

	uint32_t data_buffer = 0;
	uint32_t request_count = 0;
	uint32_t transfer_count = 0;

	if (klass) {
		data_buffer = m_space->read_dword(pb + IORecGS_dataBuffer) & 0x00ffffff;
		request_count = m_space->read_dword(pb + IORecGS_requestCount) & 0x00ffffff;
		// pre-zero transfer count
		m_space->write_dword(pb + IORecGS_transferCount, 0);
	} else {
		data_buffer = m_space->read_dword(pb + FileIORec_dataBuffer) & 0x00ffffff;
		request_count = m_space->read_dword(pb + FileIORec_requestCount) & 0x00ffffff;
		m_space->write_dword(pb + FileIORec_transferCount, 0);
	}

	if (request_count == 0) return 0;

	std::vector<uint8_t> buffer(request_count);


	ssize_t ok = ::pread(e.fd, buffer.data(), request_count, e.offset);
	if (ok < 0) return map_errno(errno);
	if (ok == 0) return eofEncountered;

	transfer_count = ok;
	buffer.resize(transfer_count);


	translate_in(buffer, e.translate);

	unsigned newline_mask;
	newline_mask = m_space->read_word(global_buffer);
	if (newline_mask) {
		uint8_t newline_table[256];
		for (int i = 0; i < 256; ++i)
			newline_table[i] = m_space->read_byte(global_buffer + 2 + i);

		for (uint32_t i = 0; i < ok; ++i) {
			uint8_t c = buffer[i];
			if (newline_table[c & newline_mask]) {
				transfer_count = i + 1;
				buffer.resize(transfer_count);
				break;
			}
		}
	}

	for (auto c : buffer)
		m_space->write_byte(data_buffer++, c);

	e.offset += transfer_count;
	if (klass)
		m_space->write_dword(pb + IORecGS_transferCount, transfer_count);
	else
		m_space->write_dword(pb + FileIORec_transferCount, transfer_count);

	return 0;
}



unsigned ample_host_device::fst_write(unsigned klass, file_entry &e)
{

	LOGMASKED(LOG_FST, "fst_write(%s)\n", e.path.c_str());

	unsigned dp = m_maincpu->g65816_get_reg(g65816_device::G65816_D);
	uint32_t pb = m_space->read_dword(dp + dp_param_blk_ptr) & 0x00ffffff;

	uint32_t data_buffer = 0;
	uint32_t request_count = 0;
	uint32_t transfer_count = 0;

	if (klass) {
		data_buffer = m_space->read_dword(pb + IORecGS_dataBuffer) & 0x00ffffff;
		request_count = m_space->read_dword(pb + IORecGS_requestCount) & 0x00ffffff;
		// pre-zero transfer count
		m_space->write_dword(pb + IORecGS_transferCount, 0);
	} else {
		data_buffer = m_space->read_dword(pb + FileIORec_dataBuffer) & 0x00ffffff;
		request_count = m_space->read_dword(pb + FileIORec_requestCount) & 0x00ffffff;
		m_space->write_dword(pb + FileIORec_transferCount, 0);
	}

	if (request_count == 0) return 0;

	std::vector<uint8_t> buffer(request_count);
	for (size_t i = 0; i < request_count; ++i) {
		buffer[i] = m_space->read_byte(data_buffer++);
	}

	translate_out(buffer, e.translate);

	ssize_t ok = ::pwrite(e.fd, buffer.data(), request_count, e.offset);
	if (ok < 0) return map_errno(errno);

	transfer_count = ok;
	e.offset += transfer_count;

	if (klass)
		m_space->write_dword(pb + IORecGS_transferCount, transfer_count);
	else
		m_space->write_dword(pb + FileIORec_transferCount, transfer_count);

	return 0;
}


unsigned ample_host_device::fst_get_eof(unsigned klass, file_entry &e)
{

	LOGMASKED(LOG_FST, "fst_get_eof(%s)\n", e.path.c_str());

	unsigned dp = m_maincpu->g65816_get_reg(g65816_device::G65816_D);
	uint32_t pb = m_space->read_dword(dp + dp_param_blk_ptr) & 0x00ffffff;

	off_t eof = ::lseek(e.fd, 0, SEEK_END);
	if (eof < 0) return map_errno(errno);

	if (klass) {
		m_space->write_dword(pb + PositionRecGS_position, eof);
	} else {
		m_space->write_dword(pb + MarkRec_position, eof);
	}
	return 0;
}

unsigned ample_host_device::fst_get_mark(unsigned klass, file_entry &e)
{

	LOGMASKED(LOG_FST, "fst_get_mark(%s)\n", e.path.c_str());

	unsigned dp = m_maincpu->g65816_get_reg(g65816_device::G65816_D);
	uint32_t pb = m_space->read_dword(dp + dp_param_blk_ptr) & 0x00ffffff;

	if (klass) {
		m_space->write_dword(pb + PositionRecGS_position, e.offset);
	} else {
		m_space->write_dword(pb + MarkRec_position, e.offset);
	}
	return 0;
}


unsigned ample_host_device::fst_set_eof(unsigned klass, file_entry &e)
{

	LOGMASKED(LOG_FST, "fst_set_eof(%s)\n", e.path.c_str());

	// if (BIT(m_sysconfig->read(), BIT_HOST_READ_ONLY) return drvrWrtProt;

	unsigned dp = m_maincpu->g65816_get_reg(g65816_device::G65816_D);
	uint32_t pb = m_space->read_dword(dp + dp_param_blk_ptr) & 0x00ffffff;

	unsigned base = 0;
	uint32_t displacement = 0;

	if (klass) {
		base = m_space->read_word(pb + SetPositionRecGS_base);
		displacement = m_space->read_dword(pb + SetPositionRecGS_displacement);
	} else {
		displacement = m_space->read_dword(pb + MarkRec_position);
	}
	if (base > markMinus) return paramRangeErr;

	off_t offset = get_offset(e, base, displacement);
	if (offset < 0) return outOfRange;

	off_t ok = ::ftruncate(e.fd, offset);
	if (ok < 0) return map_errno(errno);
	return 0;
}

unsigned ample_host_device::fst_set_mark(unsigned klass, file_entry &e)
{

	LOGMASKED(LOG_FST, "fst_set_mark(%s)\n", e.path.c_str());

	unsigned dp = m_maincpu->g65816_get_reg(g65816_device::G65816_D);
	uint32_t pb = m_space->read_dword(dp + dp_param_blk_ptr) & 0x00ffffff;

	unsigned base = 0;
	uint32_t displacement = 0;

	if (klass) {
		base = m_space->read_word(pb + SetPositionRecGS_base);
		displacement = m_space->read_dword(pb + SetPositionRecGS_displacement);
	} else {
		displacement = m_space->read_dword(pb + MarkRec_position);
	}
	if (base > markMinus) return paramRangeErr;

	off_t offset = get_offset(e, base, displacement);
	if (offset < 0) return outOfRange;

	e.offset = offset;
	return 0;
}

unsigned ample_host_device::fst_volume(unsigned klass) {

	LOGMASKED(LOG_FST, "fst_volume()\n");

	unsigned dp = m_maincpu->g65816_get_reg(g65816_device::G65816_D);
	uint32_t pb = m_space->read_dword(dp + dp_param_blk_ptr) & 0x00ffffff;

	unsigned rv = 0;
	if (klass) {
		unsigned pcount = m_space->read_word(pb);
		if (pcount >= 2) rv = write_string(m_space->read_dword(pb + VolumeRecGS_volName), ":Host", 2);
		// finder bug -- if used blocks is 0, doesn't display header.
		if (pcount >= 3) m_space->write_dword(pb + VolumeRecGS_totalBlocks, 0x007fffff);
		if (pcount >= 4) m_space->write_dword(pb + VolumeRecGS_freeBlocks, 0x007fffff-1);
		if (pcount >= 5) m_space->write_word(pb + VolumeRecGS_fileSysID, mfsFSID);
		if (pcount >= 6) m_space->write_word(pb + VolumeRecGS_blockSize, 512);
		// handled via gs/os
		//if (pcount >= 7) m_space->write_word(pb + VolumeRecGS_characteristics);
		//if (pcount >= 8) m_space->write_word(pb + VolumeRecGS_deviceID);
	} else {

		// prodos 16 uses / sep.
		rv = write_string(m_space->read_dword(pb + VolumeRec_volName), "/Host", 1);
		m_space->write_dword(pb + VolumeRec_totalBlocks, 0x007fffff);
		m_space->write_dword(pb + VolumeRec_freeBlocks, 0x007fffff-1);
		m_space->write_word(pb + VolumeRec_fileSysID, mfsFSID);
	}

	return rv;
}


unsigned ample_host_device::fst_get_dir_entry(unsigned klass, file_entry &e) {

	LOGMASKED(LOG_FST, "fst_get_dir_entry(%s)\n", e.path.c_str());

	unsigned dp = m_maincpu->g65816_get_reg(g65816_device::G65816_D);
	uint32_t pb = m_space->read_dword(dp + dp_param_blk_ptr) & 0x00ffffff;


	unsigned base = 0;
	unsigned pcount = 0;
	uint32_t displacement = 0;
	uint32_t name = 0;

	if (klass) {
		pcount = m_space->read_word(pb);
		base = m_space->read_word(pb + DirEntryRecGS_base);
		displacement = m_space->read_word(pb + DirEntryRecGS_displacement);
		name = m_space->read_dword(pb + DirEntryRecGS_name);
	} else {
		base = m_space->read_word(pb + DirEntryRec_base);
		displacement = m_space->read_word(pb + DirEntryRec_displacement);
		name = m_space->read_dword(pb + DirEntryRec_nameBuffer);
	}

	unsigned num_entries = e.dir_entries.size();
	if (base == 0 && displacement == 0) {
		// count them up.
		e.offset = 0;

		if (klass) {
			if (pcount >= 6) m_space->write_word(pb + DirEntryRecGS_entryNum, num_entries);
		}
		else {
			m_space->write_word(pb + DirEntryRec_entryNum, num_entries);
		}

		return 0;
	}

	int dir_displacement = e.offset;
	switch (base) {
	case 0: // displacement is absolute entry number.
		break;
	case 1: // displacement is added to the current displacement.
		displacement = dir_displacement + displacement;
		break;
	case 2: // displacement is substracted from current displacement.
		displacement = dir_displacement - displacement;
		break;
	default:
		return paramRangeErr;
	}
	--displacement;
	if (displacement < 0) return endOfDir;
	if (displacement >= num_entries) return endOfDir;

	const auto &dname = e.dir_entries[displacement++];
	e.offset = displacement;
	std::string fullpath = e.path + "/" + dname;

	struct file_info fi = {};
	unsigned rv = get_file_info(fullpath, fi, m_host_directory_id);

	// p16 and gs/os both use truncating c1 output string.
	rv = write_string(name, dname, 2, true);

	if (klass) {

		if (pcount > 2) m_space->write_word(pb + DirEntryRecGS_flags, fi.storage_type == 0x05 ? 0x8000 : 0);

		if (pcount >= 6) m_space->write_word(pb + DirEntryRecGS_entryNum, displacement);
		if (pcount >= 7) m_space->write_word(pb + DirEntryRecGS_fileType, fi.file_type);
		if (pcount >= 8) m_space->write_dword(pb + DirEntryRecGS_eof, fi.eof);
		if (pcount >= 9) m_space->write_dword(pb + DirEntryRecGS_blockCount, fi.blocks);

		if (pcount >= 10) m_space->write_qword(pb + DirEntryRecGS_createDateTime, time_to_hextime(fi.create_date));
		if (pcount >= 11) m_space->write_qword(pb + DirEntryRecGS_modDateTime, time_to_hextime(fi.modified_date));

		if (pcount >= 12) m_space->write_word(pb + DirEntryRecGS_access, fi.access);
		if (pcount >= 13) m_space->write_dword(pb + DirEntryRecGS_auxType, fi.aux_type);
		if (pcount >= 14) m_space->write_word(pb + DirEntryRecGS_fileSysID, mfsFSID);

		if (pcount >= 15) {
			unsigned fst_id = hfsFSID;
			//if (fi.storage_type == 0x0f) fst_id = mfsFSID;
			uint32_t option_list = m_space->read_dword(pb + DirEntryRecGS_optionList);
			unsigned tmp = write_option_list(option_list, fst_id, fi.finder_info, fi.has_fi ? 32 : 0);
			if (!rv) rv = tmp;
		}

		if (pcount >= 16) m_space->write_dword(pb + DirEntryRecGS_resourceEOF, fi.resource_eof);
		if (pcount >= 17) m_space->write_dword(pb + DirEntryRecGS_resourceBlocks, fi.resource_blocks);
	}
	else {
		m_space->write_word(pb + DirEntryRec_flags, fi.storage_type == 0x05 ? 0x8000 : 0);

		m_space->write_word(pb + DirEntryRec_entryNum, displacement);
		m_space->write_word(pb + DirEntryRec_fileType, fi.file_type);
		m_space->write_dword(pb + DirEntryRec_endOfFile, fi.eof);
		m_space->write_dword(pb + DirEntryRec_blockCount, fi.blocks);

		/* yes, this is a gs/os date time for p16 */
		m_space->write_qword(pb + DirEntryRec_createTime, time_to_hextime(fi.create_date));
		m_space->write_qword(pb + DirEntryRec_modTime, time_to_hextime(fi.modified_date));

		m_space->write_word(pb + DirEntryRec_access, fi.access);
		m_space->write_dword(pb + DirEntryRec_auxType, fi.aux_type);
		m_space->write_word(pb + DirEntryRec_fileSysID, mfsFSID);
	}

	return rv;
}


unsigned ample_host_device::fst_judge_name(unsigned klass) {

	LOGMASKED(LOG_FST, "fst_judge_name()\n");

	if (klass == 0) return invalidClass;

	unsigned dp = m_maincpu->g65816_get_reg(g65816_device::G65816_D);
	uint32_t pb = m_space->read_dword(dp + dp_param_blk_ptr) & 0x00ffffff;

	unsigned pcount = m_space->read_word(pb);
	// unsigned name_type = m_space->read_word(pb + JudgeNameRecGS_nameType);
	uint32_t name = pcount >= 5 ? m_space->read_dword(pb + JudgeNameRecGS_name) : 0;

	// 255 max length.
	if (pcount >= 4) m_space->write_word(pb + JudgeNameRecGS_maxLen, 255);
	if (pcount >= 6) m_space->write_word(pb + JudgeNameRecGS_nameFlags, 0);

	unsigned nameFlags = 0;
	unsigned rv = 0;
	bool delta = false;

	if (name) {
		/* name is a gs-os output string but it also has the name in it */
		unsigned cap = m_space->read_word(name);
		if (cap < 4) return buffTooSmall;

		std::string s = read_string(name + 2, 2);
		if (s.empty()) {
			nameFlags |= 1 << 13;
			s = "A";
			delta = true;
		} else {
			if (s.length() > 255) nameFlags |= 1 << 14;
			for (auto &c : s) {
				if (c == 0 || c == ':' || c == '\\' || c == '/') {
					nameFlags |= 1 << 15;
					c = '.';
					delta = true;
				}
			}
		}
		if (delta)
			rv = write_string(name, s, 2);
	}

	if (pcount >= 6) m_space->write_word(pb + JudgeNameRecGS_nameFlags, nameFlags);
	return rv;
}


unsigned ample_host_device::fst_change_path(unsigned klass, const std::string &path1, const std::string &path2) {

	LOGMASKED(LOG_FST, "fst_change_path(%s, %s)\n", path1.c_str(), path2.c_str());

	if (BIT(m_sysconfig->read(), BIT_HOST_READ_ONLY)) return drvrWrtProt;

	struct stat st;
	int ok;

	/* don't allow renaming the volume... */
	ok = ::stat(path1.c_str(), &st);
	if (ok < 0) return map_errno(errno, path1);
	if (std::make_pair(st.st_dev, st.st_ino) == m_host_directory_id)
		return invalidAccess;

	/* rename will destroy any existing file but ChangePath will not */
	ok = ::stat(path2.c_str(), &st);
	if (ok == 0) return dupPathname;

	if (::rename(path1.c_str(), path2.c_str()) < 0)
		return map_errno(errno, path2);
	return 0;
}


int ample_host_device::mli_rename(unsigned dcb, const std::string &path1, const std::string &path2) {
	LOGMASKED(LOG_MLI, "mli_rename(%s, %s)\n", path1.c_str(), path2.c_str());

	if (BIT(m_sysconfig->read(), BIT_HOST_READ_ONLY)) return drvrWrtProt;

	// n.b. p8 rename is only allowed within the same directory.

	struct stat st;
	int ok;

	/* don't allow renaming the volume... */
	ok = ::stat(path1.c_str(), &st);
	if (ok < 0) return map_errno(errno, path1);
	if (std::make_pair(st.st_dev, st.st_ino) == m_host_directory_id)
		return invalidAccess;

	/* rename will destroy any existing file but ChangePath will not */
	ok = ::stat(path2.c_str(), &st);
	if (ok == 0) return dupPathname;

	if (::rename(path1.c_str(), path2.c_str()) < 0)
		return map_errno(errno, path2);
	return 0;	
}



// m_mli_prefix includes /host/ and a trailing slash.
// returned value excludes leading/trailing slash

/* returns -1 (volNotFound?) if not a /host/ path */
int ample_host_device::mli_expand_path(std::string &s) {

	// bool absolute = false;

	if (s.empty()) return -1;
	if (dotdot(s)) return badPathSyntax;

	if (s[0] == '/') {
		if (s.length() < 5 || core_strnicmp(s.c_str(), "/host", 5)) 
			return -1;
		if (s.length() > 5 && s[5] != '/')
			return -1;
		// absolute = true;
		s = s.length() > 6 ? s.substr(6) : std::string("");
	} else {
		if (m_mli_prefix.empty()) return -1;
		// absolute = false;
		s = m_mli_prefix.substr(6) + s;
	}

	while (!s.empty() && s.back() == '/') s.pop_back();

	return 0;
}


unsigned ample_host_device::fst_destroy(unsigned klass, const std::string &path) {

	LOGMASKED(LOG_FST, "fst_destroy(%s)\n", path.c_str());

	if (BIT(m_sysconfig->read(), BIT_HOST_READ_ONLY)) return drvrWrtProt;

	struct stat st;

	if (::stat(path.c_str(), &st) < 0) {
		return map_errno(errno, path);
	}

	// can't delete volume root.
	if (std::make_pair(st.st_dev, st.st_ino) == m_host_directory_id)
		return badStoreType;


	int ok = S_ISDIR(st.st_mode) ? ::rmdir(path.c_str()) : ::unlink(path.c_str());

	if (ok < 0) return map_errno(errno, path);
	return 0;
}

int ample_host_device::mli_destroy(unsigned dcb, const std::string &path) {
	LOGMASKED(LOG_MLI, "mli_destroy(%s)\n", path.c_str());

	if (BIT(m_sysconfig->read(), BIT_HOST_READ_ONLY)) return drvrWrtProt;

	struct stat st;

	if (::stat(path.c_str(), &st) < 0) {
		return map_errno(errno, path);
	}

	// can't delete volume root.
	if (std::make_pair(st.st_dev, st.st_ino) == m_host_directory_id)
		return badStoreType;


	int ok = S_ISDIR(st.st_mode) ? ::rmdir(path.c_str()) : ::unlink(path.c_str());

	if (ok < 0) return map_errno(errno, path);
	return 0;
}

unsigned ample_host_device::fst_open(unsigned klass, const std::string &path) {

	LOGMASKED(LOG_FST, "fst_open(%s)\n", path.c_str());

	unsigned dp = m_maincpu->g65816_get_reg(g65816_device::G65816_D);
	uint32_t pb = m_space->read_dword(dp + dp_param_blk_ptr) & 0x00ffffff;


	struct file_info fi;

	unsigned rv = get_file_info(path, fi, m_host_directory_id);
	if (rv) return rv;



	file_entry e;
	e.type = file_regular;
	e.path = path;

	unsigned pcount = 0;
	unsigned request_access = readEnableAllowWrite;
	unsigned resource_number = 0;
	if (klass) {
		pcount = m_space->read_word(pb);
		if (pcount >= 3) request_access = m_space->read_word(pb + OpenRecGS_requestAccess);
		if (pcount >= 4) resource_number = m_space->read_word(pb + OpenRecGS_resourceNumber);
	}

	if (resource_number) {
		if (resource_number > 1) return paramRangeErr;
		e.type = file_resource;
	}

	if (request_access > 3) return paramRangeErr;

	// special access checks for directories.
	if (fi.storage_type == 0x0d || fi.storage_type == 0x0f) {
		if (resource_number) return resForkNotFound;
		switch (request_access) {
		case readEnableAllowWrite:
			request_access = readEnable;
			break;
		case writeEnable:
		case readWriteEnable:
			return invalidAccess;
			break;
		}
		e.type = file_directory;
	}


	if (BIT(m_sysconfig->read(), BIT_HOST_READ_ONLY)) {
		switch (request_access) {
		case readEnableAllowWrite:
			request_access = readEnable;
			break;
		case readWriteEnable:
		case writeEnable:
			return invalidAccess;
			break;
		}
	}

	unsigned access = request_access;
	switch(e.type) {
	case file_regular:
		e.fd = open_data_fork(path, access, rv);
		break;
	case file_resource:
		e.fd = open_resource_fork(path, access, rv);
		break;
	case file_directory:
		e.dir_entries = read_directory(path, rv);
		break;
	}

	if (rv) return rv;


	if (klass) {
		if (pcount >= 5) m_space->write_word(pb + OpenRecGS_access, access);
		if (pcount >= 6) m_space->write_word(pb + OpenRecGS_fileType, fi.file_type);
		if (pcount >= 7) m_space->write_dword(pb + OpenRecGS_auxType, fi.aux_type);
		if (pcount >= 8) m_space->write_word(pb + OpenRecGS_storageType, fi.storage_type);

		if (pcount >= 9) m_space->write_qword(pb + OpenRecGS_createDateTime, time_to_hextime(fi.create_date));
		if (pcount >= 10) m_space->write_qword(pb + OpenRecGS_modDateTime, time_to_hextime(fi.modified_date));

		if (pcount >= 11) {
			unsigned fst_id = hfsFSID;
			//if (fi.storage_type == 0x0f) fst_id = mfsFSID;

			uint32_t option_list = m_space->read_dword(pb + OpenRecGS_optionList) & 0x00ffffff;
			uint32_t tmp = write_option_list(option_list, fst_id, fi.finder_info, fi.has_fi ? 32 : 0);
			if (!rv) rv = tmp;
		}

		if (pcount >= 12) m_space->write_dword(pb + OpenRecGS_eof, fi.eof);
		if (pcount >= 13) m_space->write_dword(pb + OpenRecGS_blocksUsed, fi.blocks);
		if (pcount >= 14) m_space->write_dword(pb + OpenRecGS_resourceEOF, fi.resource_eof);
		if (pcount >= 15) m_space->write_dword(pb + OpenRecGS_resourceBlocks, fi.resource_blocks);
	}
	// prodos 16 doesn't return anything in the parameter block.


	/* bit 14 of access is a resource flag */
	/* bit 15 of access is a clean (1) / dirty(0) flag */
	access |= 0x8000;
	if (resource_number) access |= 0x4000;

	e.access = access;

	if (e.type == file_regular && BIT(m_sysconfig->read(), BIT_HOST_TRANSLATE_TEXT)) {
		if (fi.file_type == 0x04 || fi.file_type == 0xb0)
			e.translate = translate_crlf;
	}
	if (e.type == file_regular && fi.file_type == 0x04 && BIT(m_sysconfig->read(), BIT_HOST_TRANSLATE_MERLIN)) {
		size_t n = path.length();
		if (n >= 3 && toupper(path[n-1]) == 'S' && path[n-2] == '.')
			e.translate = translate_merlin; 
	}


	unsigned cookie = 0;
	auto iter = std::find_if(m_files.begin(), m_files.end(), [](const auto &e){
		return !e;
	});
	if (iter == m_files.end()) {
		m_files.emplace_back(std::move(e));
		cookie = m_files.size();
	} else {
		*iter = std::move(e);
		cookie = std::distance(m_files.begin(), iter) + 1;
	}

	m_maincpu->g65816_set_reg(g65816_device::G65816_X, cookie);
	m_maincpu->g65816_set_reg(g65816_device::G65816_Y, access); // actual access needed in fcr
	return rv;
}

int ample_host_device::mli_open(unsigned dcb, const std::string &path) {
	LOGMASKED(LOG_MLI, "mli_open(%s)\n", path.c_str());


	struct file_info fi;

	unsigned rv = get_file_info(path, fi, m_host_directory_id);
	if (rv) return rv;

	file_entry e;
	e.type = file_regular;
	e.path = path;
	e.buffer = m_space->read_word(dcb + 3);

	unsigned access = readEnableAllowWrite;
	unsigned terr = 0;
	if (BIT(m_sysconfig->read(), BIT_HOST_READ_ONLY)) {
		access = readEnable;
	}

	if (fi.storage_type == 0x0d || fi.storage_type == 0x0f) {
		e.access = readEnable;
		e.type = file_directory;

		unsigned terr = 0;
		e.dir_file = read_mli_directory(path, m_host_directory_id, terr);
		if (terr) return terr;
	} else {

		int fd = open_data_fork(path, access, terr);
		if (fd < 0) return terr;

		e.access = access;
		e.fd = fd;

		if (BIT(m_sysconfig->read(), BIT_HOST_TRANSLATE_TEXT)) {
			if (fi.file_type == 0x04 || fi.file_type == 0xb0)
				e.translate = translate_crlf;
		}
		if (fi.file_type == 0x04 && BIT(m_sysconfig->read(), BIT_HOST_TRANSLATE_MERLIN)) {
			size_t n = path.length();
			if (n >= 3 && toupper(path[n-1]) == 'S' && path[n-2] == '.')
				e.translate = translate_merlin; 
		}
	}

	unsigned cookie = 0;
	auto iter = std::find_if(m_files.begin(), m_files.end(), [](const auto &e){
		return !e;
	});
	if (iter == m_files.end()) {
		m_files.emplace_back(std::move(e));
		cookie = m_files.size();
	} else {
		*iter = std::move(e);
		cookie = std::distance(m_files.begin(), iter) + 1;
	}

	m_space->write_byte(dcb + 5, cookie + 0x80);
	return 0;
}


unsigned ample_host_device::fst_get_file_info(unsigned klass, const std::string &path) {

	LOGMASKED(LOG_FST, "fst_get_file_info(%s)\n", path.c_str());

	unsigned dp = m_maincpu->g65816_get_reg(g65816_device::G65816_D);
	uint32_t pb = m_space->read_dword(dp + dp_param_blk_ptr) & 0x00ffffff;

	struct file_info fi{};
	int rv = 0;

	rv = get_file_info(path, fi, m_host_directory_id);
	if (rv) return rv;

	if (klass) {

		unsigned pcount = m_space->read_word(pb);

		if (pcount >= 2) m_space->write_word(pb + FileInfoRecGS_access, fi.access);
		if (pcount >= 3) m_space->write_word(pb + FileInfoRecGS_fileType, fi.file_type);
		if (pcount >= 4) m_space->write_dword(pb + FileInfoRecGS_auxType, fi.aux_type);
		if (pcount >= 5) m_space->write_word(pb + FileInfoRecGS_storageType, fi.storage_type);

		if (pcount >= 6) m_space->write_qword(pb + FileInfoRecGS_createDateTime, time_to_hextime(fi.create_date));
		if (pcount >= 7) m_space->write_qword(pb + FileInfoRecGS_modDateTime, time_to_hextime(fi.modified_date));

		if (pcount >= 8) {
			unsigned fst_id = hfsFSID;
			//if (fi.storage_type == 0x0f) fst_id = mfsFSID;
			uint32_t option_list = m_space->read_dword(pb + FileInfoRecGS_optionList);
			rv = write_option_list(option_list,  fst_id, fi.finder_info, fi.has_fi ? 32 : 0);
		}
		if (pcount >= 9) m_space->write_dword(pb + FileInfoRecGS_eof, fi.eof);
		if (pcount >= 10) m_space->write_dword(pb + FileInfoRecGS_blocksUsed, fi.blocks);
		if (pcount >= 11) m_space->write_dword(pb + FileInfoRecGS_resourceEOF, fi.resource_eof);
		if (pcount >= 12) m_space->write_dword(pb + FileInfoRecGS_resourceBlocks, fi.resource_blocks);

	} else {

		m_space->write_word(pb + FileRec_fAccess, fi.access);
		m_space->write_word(pb + FileRec_fileType, fi.file_type);
		m_space->write_dword(pb + FileRec_auxType, fi.aux_type);
		m_space->write_word(pb + FileRec_storageType, fi.storage_type);

		m_space->write_dword(pb + FileRec_createDate, time_to_prodos(fi.create_date));
		m_space->write_dword(pb + FileRec_modDate, time_to_prodos(fi.modified_date));

		m_space->write_dword(pb + FileRec_blocksUsed, fi.blocks);
	}

	return rv;
}

int ample_host_device::mli_get_file_info(unsigned dcb, const std::string &path) {
	LOGMASKED(LOG_MLI, "mli_get_file_info(%s)\n", path.c_str());

	struct file_info fi{};
	int rv = 0;

	rv = get_file_info(path, fi, m_host_directory_id);
	if (rv) return rv;


	m_space->write_byte(dcb + 3, fi.access);
	m_space->write_byte(dcb + 4, fi.file_type);
	m_space->write_word(dcb + 5, fi.aux_type);
	m_space->write_byte(dcb + 7, fi.storage_type);
	m_space->write_word(dcb + 8, fi.blocks);
	m_space->write_dword(dcb + 10, time_to_prodos(fi.modified_date));
	m_space->write_dword(dcb + 14, time_to_prodos(fi.create_date));

	return 0;
}


unsigned ample_host_device::fst_create(unsigned klass, const std::string &path) {

	LOGMASKED(LOG_FST, "fst_create(%s)\n", path.c_str());

	if (BIT(m_sysconfig->read(), BIT_HOST_READ_ONLY)) return drvrWrtProt;

	unsigned dp = m_maincpu->g65816_get_reg(g65816_device::G65816_D);
	uint32_t pb = m_space->read_dword(dp + dp_param_blk_ptr) & 0x00ffffff;

	struct file_info fi {};

	unsigned pcount = 0;
	if (klass) {
		pcount = m_space->read_word(pb);
		if (pcount >= 2) fi.access = m_space->read_word(pb + CreateRecGS_access);
		if (pcount >= 3) fi.file_type = m_space->read_word(pb + CreateRecGS_fileType);
		if (pcount >= 4) fi.aux_type = m_space->read_dword(pb + CreateRecGS_auxType);
		if (pcount >= 5) fi.storage_type = m_space->read_word(pb + CreateRecGS_storageType);
		if (pcount >= 6) fi.eof = m_space->read_dword(pb + CreateRecGS_eof);
		if (pcount >= 7) fi.resource_eof = m_space->read_dword(pb + CreateRecGS_resourceEOF);

		if (pcount >= 4) {
			file_type_to_finder_info(fi.finder_info, fi.file_type, fi.aux_type);
			fi.has_fi = 1;
		}
	} else {
		fi.access = m_space->read_word(pb + CreateRec_fAccess);
		fi.file_type = m_space->read_word(pb + CreateRec_fileType);
		fi.aux_type = m_space->read_dword(pb + CreateRec_auxType);
		fi.storage_type = m_space->read_word(pb + CreateRec_storageType);
		fi.create_date = prodos_to_time(m_space->read_dword(pb + CreateRec_createDate));

		file_type_to_finder_info(fi.finder_info, fi.file_type, fi.aux_type);
		fi.has_fi = 1;
	}

	switch(fi.storage_type) {
	case 0x00:
		if (fi.file_type == 0x0f)
			fi.storage_type = 0x0d;
		else fi.storage_type = 1;
		break;

	case 0x01:
	case 0x05:
	case 0x8005:
		break;

	case 0x0d:
		fi.file_type = 0x0f;
		break;

	case 0x02:
	case 0x03:
		fi.storage_type = 1;
		break;
	default:
		return badStoreType;
	}

	if (fi.storage_type == 0x0d) {
		int ok = ::mkdir(path.c_str(), 0777);
		if (ok < 0)
			return map_errno(errno, path);

		if (klass) {
			if (pcount >= 5) m_space->write_word(pb + CreateRecGS_storageType, fi.storage_type);
		} else {
			m_space->write_word(pb + CreateRec_storageType, fi.storage_type);
		}
		return 0;
	}

	if (fi.storage_type <= 3 || fi.storage_type == 0x05) {
		int ok = ::open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_NONBLOCK, 0666);
		if (ok < 0) return map_errno(errno, path);


		if (fi.eof) {
			::ftruncate(ok, fi.eof);
		}
		// set auxtype, filetype, etc.
		set_file_info(path, fi);
		::close(ok);


		if (fi.storage_type == 5 && fi.resource_eof) {
			unsigned terr;
			unsigned access = writeEnable;
			int ok = open_data_fork(path, access, terr);
			if  (ok >= 0) {
				::ftruncate(ok, fi.resource_eof);
				::close(ok);
			}
		}

		if (klass) {
			if (pcount >= 5) m_space->write_word(pb + CreateRecGS_storageType, fi.storage_type);
		} else {
			m_space->write_word(pb + CreateRec_storageType, fi.storage_type);
		}
		return 0;
	}

	/* 0x8005 converts an existing file to a resource file */
	if (fi.storage_type == 0x8005) {

		struct stat st;
		int ok = ::stat(path.c_str(), &st);
		if (ok < 0) return map_errno(errno, path);
		if (!S_ISREG(st.st_mode)) return resAddErr;

		file_info rfi{};
		get_file_xinfo(path, rfi);
		if (rfi.resource_eof) return resExistsErr;

		struct rfi{};
		if (fi.resource_eof) {
			unsigned terr;
			unsigned access = writeEnable;
			int ok = open_data_fork(path, access, terr);
			if (ok < 0) return resAddErr;
			::ftruncate(ok, fi.resource_eof);
			::close(ok);
		}
		return 0;
	}
	return badStoreType;
}

int ample_host_device::mli_create(unsigned dcb, const std::string &path) {
	LOGMASKED(LOG_MLI, "mli_create(%s)\n", path.c_str());

	if (BIT(m_sysconfig->read(), BIT_HOST_READ_ONLY)) return drvrWrtProt;

	struct file_info fi {};

	fi.access = m_space->read_byte(dcb + 3);
	fi.file_type = m_space->read_byte(dcb + 4);
	fi.aux_type = m_space->read_word(dcb + 5);
	fi.storage_type = m_space->read_byte(dcb + 7);
	fi.create_date = prodos_to_time(m_space->read_dword(dcb + 8));

	file_type_to_finder_info(fi.finder_info, fi.file_type, fi.aux_type);
	fi.has_fi = 1;

	switch (fi.storage_type) {
	case 0:
		fi.storage_type = fi.file_type == 0x0f ? 0x0d : 0x01;
		break;
	case 0x01:
	case 0x02:
	case 0x03:
	case 0x0d:
		break;
	default:
		return badStoreType;
	}

	if (fi.storage_type == 0x0d) {
		int ok = ::mkdir(path.c_str(), 0777);
		if (ok < 0)
			return map_errno(errno, path);

		return 0;
	}

	int ok = ::open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_NONBLOCK, 0666);
	if (ok < 0) return map_errno(errno, path);


	// set auxtype, filetype, etc.
	set_file_info(path, fi);
	::close(ok);

	return 0;
}

unsigned ample_host_device::fst_set_file_info(unsigned klass, const std::string &path) {

	LOGMASKED(LOG_FST, "fst_set_file_info(%s)\n", path.c_str());

	if (BIT(m_sysconfig->read(), BIT_HOST_READ_ONLY)) return drvrWrtProt;

	unsigned dp = m_maincpu->g65816_get_reg(g65816_device::G65816_D);
	uint32_t pb = m_space->read_dword(dp + dp_param_blk_ptr) & 0x00ffffff;

	struct file_info fi{};

	// load up existing file types / finder info.
	get_file_xinfo(path, fi);

	uint32_t option_list = 0;
	if (klass) {
		unsigned pcount = m_space->read_word(pb);

		if (pcount >= 2) fi.access = m_space->read_word(pb + FileInfoRecGS_access);
		if (pcount >= 3) fi.file_type = m_space->read_word(pb + FileInfoRecGS_fileType);
		if (pcount >= 4) fi.aux_type = m_space->read_dword(pb + FileInfoRecGS_auxType);
		// reserved.
		//if (pcount >= 5) fi.storage_type = m_space->read_word(pb + FileInfoRecGS_storageType);
		if (pcount >= 6) fi.create_date = hextime_to_time(m_space->read_qword(pb + FileInfoRecGS_createDateTime));
		if (pcount >= 7) fi.modified_date = hextime_to_time(m_space->read_qword(pb + FileInfoRecGS_modDateTime));
		if (pcount >= 8) option_list = m_space->read_dword(pb + FileInfoRecGS_optionList) & 0x00ffffff;
		// remainder reserved

		if (pcount >= 4) {
			file_type_to_finder_info(fi.finder_info, fi.file_type, fi.aux_type);
			fi.has_fi = 1;
		}
	} else {
		fi.access = m_space->read_word(pb + FileRec_fAccess);
		fi.file_type = m_space->read_word(pb + FileRec_fileType);
		fi.aux_type = m_space->read_dword(pb + FileRec_auxType);
		// reserved.
		//fi.storage_type = m_space->read_dword(pb + FileRec_storageType);
		fi.create_date = prodos_to_time(m_space->read_dword(pb + FileRec_createDate));
		fi.modified_date = prodos_to_time(m_space->read_dword(pb + FileRec_modDate));

		file_type_to_finder_info(fi.finder_info, fi.file_type, fi.aux_type);
		fi.has_fi = 1;
	}

	if (option_list) {
		// total size, req size, fst id, data...
		// int total_size = m_space->read_word(option_list + 0);
		int req_size = m_space->read_word(option_list + 2);
		int fst_id = m_space->read_word(option_list + 4);

		int size = req_size - 6;
		if ((fst_id == proDOSFSID || fst_id == hfsFSID || fst_id == appleShareFSID) && size >= 32) {
			fi.has_fi = 1;
			for (int i = 0; i <32; ++i)
				fi.finder_info[i] = m_space->read_byte(option_list + 6 + i);
		}
	}

	return set_file_info(path, fi);
}

int ample_host_device::mli_set_file_info(unsigned dcb, const std::string &path) {
	LOGMASKED(LOG_MLI, "mli_set_file_info(%s)\n", path.c_str());

	if (BIT(m_sysconfig->read(), BIT_HOST_READ_ONLY)) return drvrWrtProt;

	struct file_info fi{};

	fi.access = m_space->read_byte(dcb + 3);
	fi.file_type = m_space->read_byte(dcb + 4);
	fi.aux_type = m_space->read_word(dcb + 5);
	fi.modified_date = prodos_to_time(m_space->read_dword(dcb + 10));

	file_type_to_finder_info(fi.finder_info, fi.file_type, fi.aux_type);
	fi.has_fi = 1;

	return set_file_info(path, fi);
}



unsigned ample_host_device::fst_format(unsigned klass) {
	LOGMASKED(LOG_FST, "fst_format()\n");

	return notBlockDev;
}

unsigned ample_host_device::fst_erase(unsigned klass) {
	LOGMASKED(LOG_FST, "fst_erase()\n");

	return notBlockDev;
}

unsigned ample_host_device::fst_clear_backup(unsigned klass, const std::string &path) {
	LOGMASKED(LOG_FST, "fst_clear_backup(%s)\n", path.c_str());

	return invalidFSTop;
}


#pragma mark - mli


void ample_host_device::host_mli() {

	unsigned s = m_maincpu->g65816_get_reg(g65816_device::G65816_S);
	// unsigned p = m_maincpu->g65816_get_reg(g65816_device::G65816_P);
	unsigned rts = m_space->read_word(0x0100 | s + 1) + 1;
	unsigned call = m_space->read_byte(rts);
	unsigned dcb = m_space->read_word(rts + 1);

	unsigned pcount = m_space->read_byte(dcb);

	LOGMASKED(LOG_MLI, "host_mli(%02x, %04x)\n", call, dcb);


	if (m_mli_vector == 0 && call != HOST_INIT) {
		return;
	}

	if (pcount != mli_expected_pcount(call)) {
		/* invalidPcount but let prodos deal with it */
		m_maincpu->g65816_set_reg(g65816_device::G65816_PC, m_mli_vector);
		return;
	}


	unsigned pp;
	unsigned refNum = 0;
	int err = 0;
	std::string path1;
	std::string path2;
	file_entry *e = nullptr;

	switch (call) {

	case CREATE:
	case DESTROY:
	case SET_FILE_INFO:
	case GET_FILE_INFO:
	case OPEN:
		/* path-based.... */
		pp = m_space->read_word(dcb + 1);
		path1 = read_string(pp, 1, true);
		err = mli_expand_path(path1);
		break;
	case RENAME:
		/* path-based.... */
		pp = m_space->read_word(dcb + 1);
		path1 = read_string(pp, 1, true);
		err = mli_expand_path(path1);
		if (err) break;
		pp = m_space->read_word(dcb + 3);
		path2 = read_string(pp, 1, true);
		err = mli_expand_path(path2);
		break;

		/* refNum based */
    case NEWLINE:
    case READ:
    case WRITE:
    case SET_MARK:
    case GET_MARK:
    case SET_EOF:
    case GET_EOF:
    case SET_BUF:
    case GET_BUF:
    	refNum = m_space->read_byte(dcb + 1);
    	e = mli_get_file_entry(refNum);
    	if (!e) err = -1;
    	break;

    case CLOSE:
    case FLUSH:
    	/* these may also have a 0 refnum. */
    	refNum = m_space->read_byte(dcb + 1);
    	if (refNum == 0) break;
    	e = mli_get_file_entry(refNum);
    	if (!e) err = -1;
    	break;
	}


	bool tail = false;
	if (err) call = 0;

	switch (call) {
	default:
		err = -1;
		break;


	case HOST_INIT:
		err = mli_start(dcb);
		break;

	case OPEN:
		err = mli_open(dcb, m_host_directory + path1);
		break;

	case CREATE:
		err = mli_create(dcb, m_host_directory + path1);
		break;

	case DESTROY:
		err = mli_destroy(dcb, m_host_directory + path1);
		break;

	case SET_FILE_INFO:
		err = mli_set_file_info(dcb, m_host_directory + path1);
		break;

	case GET_FILE_INFO:
		err = mli_get_file_info(dcb, m_host_directory + path1);
		break;

	case RENAME:
		err = mli_rename(dcb, m_host_directory + path1, m_host_directory + path2);
		break;

	case CLOSE:
		err = e ? mli_close(dcb, *e) : mli_close(dcb);
		break;
	case FLUSH:
		err = e ? mli_flush(dcb, *e) : mli_flush(dcb);
		break;
	case READ:
		err = mli_read(dcb, *e);
		break;
	case WRITE:
		err = mli_write(dcb, *e);
		break;
	case NEWLINE:
		err = mli_newline(dcb, *e);
		break;

	case SET_MARK:
		err = mli_set_mark(dcb, *e);
		break;

	case GET_MARK:
		err = mli_get_mark(dcb, *e);
		break;

	case SET_EOF:
		err = mli_set_eof(dcb, *e);
		break;

	case GET_EOF:
		err = mli_get_eof(dcb, *e);
		break;

	case SET_BUF:
		err = mli_set_buf(dcb, *e);
		break;

	case GET_BUF:
		err = mli_get_buf(dcb, *e);
		break;

	case WRITE_BLOCK:
	case READ_BLOCK:
		err = mli_rw_block(dcb);
		break;

	case QUIT:
		err = mli_quit(dcb);
		break;

	case ONLINE:
		err = mli_online(dcb);
		break;

	case SET_PREFIX:
		err = mli_set_prefix(dcb);
		break;

	case GET_PREFIX:
		err = mli_get_prefix(dcb);
		break;

	case ONLINE | 0x20:
		tail = true;
		err = mli_online_tail(dcb);
		break;

	case SET_PREFIX | 0x20:
		tail = true;
		err = mli_set_prefix_tail(dcb);
		break;
	}

	if (tail) {
		/* use the error code from prodos. */
		for (unsigned i = 0; i <16; ++i) {
			m_space->write_byte(0x80 + i, m_mli_zp_save[i]);
		}
		m_maincpu->g65816_set_reg(g65816_device::G65816_PC, m_mli_rts + 3);
		m_maincpu->g65816_set_reg(g65816_device::G65816_S, s + 2); // pop rts address.
		return;
	}


	if (err == -1) {
		/* let prodos handle it */
		m_maincpu->g65816_set_reg(g65816_device::G65816_PC, m_mli_vector);
		return;
	}

	if (err == -2) {

		enum {
			JMP = 0x4c,
			JSR = 0x20,
			WDM = 0x42,
		};

		/* set up our tail patch */
		for (unsigned i = 0; i < 16; ++i) {
			m_mli_zp_save[i] = m_space->read_byte(0x80 + i);
		}
		m_mli_call = call;
		m_mli_dcb = dcb;
		m_mli_rts = rts;
		m_space->write_byte(0x80 + 0, JSR);
		m_space->write_word(0x80 + 1, m_mli_vector);
		m_space->write_byte(0x80 + 3, call);
		m_space->write_word(0x80 + 4, dcb);

		m_space->write_byte(0x80 + 6, JSR);
		m_space->write_word(0x80 + 7, MLI_ENTRY);
		m_space->write_byte(0x80 + 9, call | 0x20);
		m_space->write_word(0x80 + 10, dcb);
		m_space->write_byte(0x80 + 12, JMP);
		m_space->write_word(0x80 + 12, rts + 4);

		/* replace the rts address */
		m_space->write_word(0x0100 | s + 1, 0x0082);
		m_maincpu->g65816_set_reg(g65816_device::G65816_PC, m_mli_vector);
		return;		
	}

	if (err == 0) {
		switch(call) {
		case CREATE:
		case DESTROY:
		case RENAME:
		case SET_FILE_INFO:
		case GET_FILE_INFO:
		case ONLINE:
		case SET_PREFIX:
		case GET_PREFIX:
		case OPEN:
		case NEWLINE:
		case READ:
		case WRITE:
		case CLOSE:
		case FLUSH:
		case SET_MARK:
		case GET_MARK:
		case SET_EOF:
		case GET_EOF:
		case SET_BUF:
		case GET_BUF:
			// last accessed device.
			m_space->write_byte(MLI_DEVNUM, m_mli_unit);
			break;
		}
	}

	if (err >= 0) {
		/* we handled it */
		m_maincpu->g65816_set_reg(g65816_device::G65816_PC, rts + 3);
		m_maincpu->g65816_set_reg(g65816_device::G65816_S, s + 2); // pop rts address.
		mli_return(err);
	}
}


int ample_host_device::mli_start(unsigned dcb) {
	LOGMASKED(LOG_MLI, "mli_start()\n");

	unsigned version = m_space->read_byte(dcb + 1);
	unsigned vector = m_space->read_word(dcb + 2);
	// unsigned patch_address = m_space->read_word(dcb + 4);
	unsigned unit = m_space->read_byte(dcb + 6);

	LOGMASKED(LOG_MLI, "mli_start(version = %02x, address=%04x, unit=%02x)\n", version, vector, unit);


	// gsplus uses version 1.
	// ample mame uses version 2.

	if (version != 2) return badSystemCall;

	// $bf00 looks like jmp real_address
	// we replace that with a wdm xx nop

	if (common_start() && vector != 0) {
		m_mli_prefix.clear();
		m_mli_vector = m_space->read_word(dcb + 2);
		m_mli_unit = m_space->read_byte(dcb + 6);
		return 0;
	}
	return badSystemCall;
}


int ample_host_device::mli_quit(unsigned dcb) {
	LOGMASKED(LOG_MLI, "mli_quit()\n");

	m_files.clear();
	return -1;
}


int ample_host_device::mli_rw_block(unsigned dcb) {
	LOGMASKED(LOG_MLI, "mli_rw_block()\n");

	return -1;
}

int ample_host_device::mli_newline(unsigned dcb, file_entry &e) {
	LOGMASKED(LOG_MLI, "mli_newline()\n");

	e.newline_mask = m_space->read_byte(dcb + 2);
	e.newline_char = m_space->read_byte(dcb + 3);
	return 0;
}


int ample_host_device::mli_close(unsigned dcb) {
	LOGMASKED(LOG_MLI, "mli_close()\n");

	unsigned level = m_space->read_byte(MLI_LEVEL);
	for (auto &e : m_files) {
		if (e && e.level < level) {
			e.close();
		}
	}
	while (m_files.size() && !m_files.back()) m_files.pop_back();
	return -1;
}

int ample_host_device::mli_close(unsigned dcb, file_entry &e) {
	LOGMASKED(LOG_MLI, "mli_close(%s)\n", e.path.c_str());

	e.close();
	if (&m_files.back() == &e) m_files.pop_back();
	return 0;
}


int ample_host_device::mli_flush(unsigned dcb) {
	LOGMASKED(LOG_MLI, "mli_flush()\n");

	unsigned level = m_space->read_byte(MLI_LEVEL);
	for (auto &e : m_files) {
		if (e && e.level < level && e.fd >= 0) {
			::fsync(e.fd);
		}
	}
	return -1;
}


int ample_host_device::mli_flush(unsigned dcb, file_entry &e) {
	LOGMASKED(LOG_MLI, "mli_flush(%s)\n", e.path.c_str());

	if (e.fd >= 0) {
		int ok = ::fsync(e);
		if (ok < 0) return map_errno(ok);
	}
	return 0;
}

int ample_host_device::mli_read(unsigned dcb, file_entry &e) {
	LOGMASKED(LOG_MLI, "mli_read(%s)\n", e.path.c_str());

	// todo -- does this work with aux memory swapping???
	unsigned data_buffer = m_space->read_word(dcb + 2);
	unsigned request_count = m_space->read_word(dcb + 4);
	unsigned transfer_count = 0;
	m_space->write_word(dcb + 6, 0); // pre-zero transfer count.
	if (request_count == 0) return 0;

	std::vector<uint8_t> buffer(request_count);
	if (e.type == file_directory) {
		if (e.offset > e.dir_file.size()) {
			// ???
			transfer_count = 0;
		} else {

			transfer_count = std::min(request_count, (unsigned)(e.dir_file.size() - e.offset));

			auto iter = e.dir_file.begin() + e.offset;
			auto end = iter + transfer_count;
			std::copy(iter, end, buffer.begin());
		}
	} else {
		int ok = ::pread(e.fd, buffer.data(), request_count, e.offset);
		if (ok < 0) return map_errno(errno);
		transfer_count = ok;
	}
	if (transfer_count == 0) return eofEncountered;

	translate_in(buffer, e.translate);

	if (e.newline_mask) {
		for (size_t i = 0; i <transfer_count; ++i) {
			auto c = buffer[i];
			if ((c & e.newline_mask) == e.newline_char) {
				transfer_count = i + 1;
				break;
			}
		}
	}

	e.offset += transfer_count;
	buffer.resize(transfer_count);
	m_space->write_word(dcb + 6, transfer_count);
	for (auto c : buffer)
		m_space->write_byte(data_buffer++, c);

	return 0;
}

int ample_host_device::mli_write(unsigned dcb, file_entry &e) {
	LOGMASKED(LOG_MLI, "mli_write(%s)\n", e.path.c_str());

	//if (BIT(m_sysconfig->read(), BIT_HOST_READ_ONLY)) return drvrWrtProt;

	unsigned data_buffer = m_space->read_word(dcb + 2);
	unsigned request_count = m_space->read_word(dcb + 4);
	m_space->write_word(dcb + 6, 0); // pre-zero transfer count.


	if (e.type == file_directory) return invalidAccess;

	std::vector<uint8_t> buffer;
	buffer.reserve(request_count);

	for(size_t i = 0; i < request_count; ++i)
		buffer.push_back(m_space->read_byte(data_buffer++));

	translate_out(buffer, e.translate);

	ssize_t ok = ::pwrite(e.fd, buffer.data(), request_count, e.offset);
	if (ok < 0) return map_errno(errno);

	e.offset += ok;
	m_space->write_word(dcb + 6, ok);
	return 0;
}

int ample_host_device::mli_get_eof(unsigned dcb, file_entry &e) {
	LOGMASKED(LOG_MLI, "mli_get_eof(%s)\n", e.path.c_str());

	ssize_t eof = 0;
	switch(e.type) {
	case file_directory:
		eof = e.dir_file.size();
		break;
	case file_regular:
	case file_resource:
		eof = ::lseek(e.fd, 0, SEEK_END);
		if (eof < 0) return map_errno(errno);
		break;
	}
	if (eof > 0x00ffffff) return outOfRange;

	// 24-bit write.
	m_space->write_word(dcb + 2, eof);
	m_space->write_byte(dcb + 4, eof >> 16);
	return 0;
}

int ample_host_device::mli_set_eof(unsigned dcb, file_entry &e) {
	LOGMASKED(LOG_MLI, "mli_set_eof(%s)\n", e.path.c_str());

	// if (BIT(m_sysconfig->read(), BIT_HOST_READ_ONLY)) return drvrWrtProt;

	unsigned eof = m_space->read_dword(dcb + 2) & 0x00ffffff;

	int ok;

	switch(e.type) {
	case file_directory:
		return invalidAccess;
		break;
	case file_regular:
	case file_resource:
		ok = ::ftruncate(e.fd, eof);
		if (ok < 0) return map_errno(errno);
		e.offset = std::min(e.offset, (off_t)eof);
		break;
	}

	return 0;
}


int ample_host_device::mli_get_mark(unsigned dcb, file_entry &e) {
	LOGMASKED(LOG_MLI, "mli_get_mark(%s)\n", e.path.c_str());

	// 24-bit write.
	m_space->write_word(dcb + 2, e.offset);
	m_space->write_byte(dcb + 4, e.offset >> 16);

	return 0;
}


int ample_host_device::mli_set_mark(unsigned dcb, file_entry &e) {
	LOGMASKED(LOG_MLI, "mli_set_mark(%s)\n", e.path.c_str());

	// TODO - positionError if offset > eof
	e.offset = m_space->read_dword(dcb + 2) & 0x00ffffff;
	return 0;
}


int ample_host_device::mli_get_buf(unsigned dcb, file_entry &e) {
	LOGMASKED(LOG_MLI, "mli_get_buf(%s)\n", e.path.c_str());

	m_space->write_word(dcb + 2, e.buffer);
	return 0;
}

int ample_host_device::mli_set_buf(unsigned dcb, file_entry &e) {
	LOGMASKED(LOG_MLI, "mli_set_buf(%s)\n", e.path.c_str());

	unsigned buffer = m_space->read_word(dcb + 2);
	if (buffer & 0xff) return badBufferAddress;
	e.buffer = buffer;
	return 0;
}



int ample_host_device::mli_online(unsigned dcb) {
	LOGMASKED(LOG_MLI, "mli_online()\n");

	/* if this is specific to our unit, handle it. if it is for all units, set up the tail patch */
	unsigned unit = m_space->read_byte(dcb + 1);
	unsigned buffer_address = m_space->read_word(dcb + 2);

	LOGMASKED(LOG_MLI, "  mli_online(%02x, %04x)\n", unit, buffer_address);

	if (unit == m_mli_unit) {

		if (!buffer_address) return badBufferAddress;
		/* slot 2, drive 1 */
		m_space->write_byte(buffer_address++, m_mli_unit | 0x04);
		m_space->write_byte(buffer_address++, 'H');
		m_space->write_byte(buffer_address++, 'O');
		m_space->write_byte(buffer_address++, 'S');
		m_space->write_byte(buffer_address++, 'T');
		return 0;
	}

	return unit == 0 ? -2 : -1;
}

int ample_host_device::mli_online_tail(unsigned dcb) {
	LOGMASKED(LOG_MLI, "mli_online_tail()\n");

	// unsigned unit = m_space->read_byte(dcb + 1);
	unsigned buffer_address = m_space->read_word(dcb + 2);


	/* at this point, ProDOS has filled out the buffer.  add ourself */
	for (unsigned i = 0; i < 16; ++i, buffer_address += 16) {

		unsigned x = m_space->read_byte(buffer_address);
		if (x == 0 || ((x & 0xf0) == m_mli_unit)) {

			m_space->write_byte(buffer_address+0, m_mli_unit | 0x04);
			m_space->write_byte(buffer_address+1, 'H');
			m_space->write_byte(buffer_address+2, 'O');
			m_space->write_byte(buffer_address+3, 'S');
			m_space->write_byte(buffer_address+4, 'T');

			if (x == 0 && i < 15) {
				// re-terminate
				m_space->write_byte(buffer_address+16, 0x00);
			}
			break;
		}

	}
	return 0;
}


int ample_host_device::mli_get_prefix(unsigned dcb) {
	LOGMASKED(LOG_MLI, "mli_get_prefix()\n");

	if (m_mli_prefix.empty()) return -1;
	unsigned pp = m_space->read_word(dcb + 1);

	write_string(pp, m_mli_prefix, 1);
	fprintf(stderr, " -> %s\n", m_mli_prefix.c_str());
	return 0;
}

int ample_host_device::mli_set_prefix(unsigned dcb) {

	std::string pfx = read_string(m_space->read_word(dcb + 1), 1, true);

	LOGMASKED(LOG_MLI, "mli_set_prefix(%s [%s])\n", pfx.c_str(), m_mli_prefix.c_str());


	int ok = mli_expand_path(pfx);
	fprintf(stderr, " -> %d, %s\n", ok, pfx.c_str());
	if (ok < 0) return m_mli_prefix.empty() ? -1 : -2;

	struct stat st;
	std::string path = m_host_directory + pfx;
	ok = ::stat(path.c_str(), &st);
	if (ok < 0) return map_errno(errno, path);
	if (!S_ISDIR(st.st_mode)) return badStoreType;

	if (!pfx.empty()) pfx.push_back('/');
	pfx = std::string("/HOST/") + pfx;
	if (pfx.length() > 63) return badPathSyntax;

	m_mli_prefix = std::move(pfx);
	m_space->write_byte(MLI_PFIXPTR, 1); // 1 indicates prefix is active.
	fprintf(stderr, " -> %s\n", m_mli_prefix.c_str());
	return 0;
}

int ample_host_device::mli_set_prefix_tail(unsigned dcb) {
	LOGMASKED(LOG_MLI, "mli_set_prefix_tail()\n");

	unsigned acc = m_maincpu->g65816_get_reg(g65816_device::G65816_A) & 0xff;
	if (!acc) m_mli_prefix.clear();
	return acc;
}


void ample_host_device::host_print()
{
	/* x:y is ptr to string to print, a is type of string */
	/* 0 = cstring, 1 = pstring, 2 = gsosstring, $8000 is add \n */

	const unsigned a = m_maincpu->g65816_get_reg(g65816_device::G65816_A);
	const unsigned x = m_maincpu->g65816_get_reg(g65816_device::G65816_X);
	const unsigned y = m_maincpu->g65816_get_reg(g65816_device::G65816_Y);

	uint32_t address = (y << 16) | x;
	unsigned type = a;

	std::string s = read_string(address, type);
	fputs(s.c_str(), stdout);
	if (type & 0x8000) fputc('\n', stdout);
	fflush(stdout);
}

void ample_host_device::host_hexdump()
{
	/* x:y is ptr to memory, a is length */

	const unsigned a = m_maincpu->g65816_get_reg(g65816_device::G65816_A);
	const unsigned x = m_maincpu->g65816_get_reg(g65816_device::G65816_X);
	const unsigned y = m_maincpu->g65816_get_reg(g65816_device::G65816_Y);

	uint32_t address = (y << 16) | x;
	unsigned count = a;

	if (address && count) {
		static char hex[] = "0123456789abcdef";
		char buffer1[16*3+1];
		char buffer2[16+1];
		uint8_t b;
		int i, j;
		while (count) {

			memset(buffer1, ' ', sizeof(buffer1)-1);
			memset(buffer2, ' ', sizeof(buffer2)-1);
			buffer1[48] = 0;
			buffer2[16] = 0;

			int xx = 16;
			if (count < 16) xx = count;
			for (i = 0, j = 0; i < xx; ++i) {
				b = m_space->read_byte(address + i);
				buffer1[j++] = hex[b >> 4];
				buffer1[j++] = hex[b & 0x0f];
				buffer1[j++] = ' ';
				b &= 0x7f; /* support high ascii */
				buffer2[i] = isprint(b) ? b : '.';

			}
			printf("%06x %s%s\n", address, buffer1, buffer2);
			count -= xx;
			address += xx;
		}
	}
	fflush(stdout);
}

DEFINE_DEVICE_TYPE(APPLE2_HOST, ample_host_device, "ample_host", "Ample Host")
