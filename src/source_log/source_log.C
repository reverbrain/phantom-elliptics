// This file is part of the phantom::io_benchmark module.
// Copyright (C) 2006-2012, Eugene Mamchits <mamchits@yandex-team.ru>.
// Copyright (C) 2013, Ruslan Nigmatullin <euroelessar@yandex.ru>.
// Copyright (C) 2006-2013, YANDEX LLC.
// This module may be distributed under the terms of the GNU LGPL 2.1.
// See the file ‘COPYING’ or ‘http://www.gnu.org/licenses/lgpl-2.1.html’.

#include "../source.H"

#include <phantom/module.H>

#include <pd/base/config.H>
#include <pd/base/exception.H>
#include <pd/base/in_fd.H>
#include <pd/base/thr.H>
#include <pd/base/size.H>
#include <pd/base/config.H>
#include <pd/base/cmp.H>

#include <pd/bq/bq_util.H>

#include <unistd.h>
#include <fcntl.h>

#include <iostream>

namespace phantom { namespace io_benchmark { namespace method_elliptics {

enum {
	LINE_LENGTH = 1024,
	TAG_LEN = 256
};

MODULE(io_benchmark_method_elliptics_source_log);

class log_file_t {
	in_fd_t in;
	in_t::ptr_t ptr;
	timeval_t timeval_start;
	interval_t delta, delta_max;
	bool work;

public:
	inline log_file_t(size_t ibuf_size, int fd) :
		in(ibuf_size, fd), ptr(in), timeval_start(timeval_current()),
		delta(interval_zero), delta_max(interval_zero), work(true) { }

	inline ~log_file_t() throw() { }

	bool get_request(request_t &request, interval_t &interval_sleep);

	interval_t stat(bool clear);
};

static void error_handler(in_t::ptr_t const &, char const *msg) {
	throw exception_log_t(log::error, "format error: %s", msg);
}

bool log_file_t::get_request(
	request_t &request, interval_t &interval_sleep
) {
	if (!work)
		return false;

	try {
		size_t data_length = 0;
		ptr.parse(data_length, &error_handler);

		if(!data_length) {
			work = false;
			return false;
		}

		if(*ptr == ' ') {
			++ptr;
			int64_t msec = 0;
			ptr.parse(msec, &error_handler);
			interval_t interval_request = msec * interval_millisecond;

			interval_sleep =
				interval_request - (timeval_current() - timeval_start);

			if(interval_sleep < interval_zero) {
				if (delta < -interval_sleep) {
					delta = -interval_sleep;

					if(delta_max < delta)
						delta_max = delta;
				}

				interval_sleep = interval_zero;
			}
		}

		if(*ptr == ' ') {
			in_t::ptr_t tagp = ++ptr;
			size_t limit = TAG_LEN;
			if(!ptr.scan("\n", 1, limit))
				throw exception_log_t(log::error, "format error #1");

			limit = ptr - tagp;
			if(tagp.scan("\t", 1, limit))
				throw exception_log_t(log::error, "format error #2");

			request.tag = in_segment_t(tagp, ptr - tagp);
		}
		else {
			request.tag = in_segment_t();
		}

		if(*ptr != '\n')
			throw exception_log_t(log::error, "format error #3");
		++ptr;

		in_t::ptr_t endp = ptr + data_length;

		request.request = in_segment_t(ptr, data_length);

		ptr.parse(request.cflags, &error_handler);
		if(*ptr != ' ')
			throw exception_log_t(log::error, "format error #4");
		++ptr;

		ptr.parse(request.ioflags, &error_handler);
		if(*ptr != ' ')
			throw exception_log_t(log::error, "format error #5");

		request.groups.resize(0);
		int group_id;
		do {
			++ptr;

			ptr.parse(group_id, error_handler);
			request.groups.push_back(group_id);
		} while (*ptr == ':');
		if(*ptr != ' ')
			throw exception_log_t(log::error, "format error #6");
		++ptr;

		in_t::ptr_t filenamep = ptr;
		size_t limit = LINE_LENGTH;
		if (!ptr.scan(" \n", 2, limit))
			throw exception_log_t(log::error, "format error #7");

		request.filename = in_segment_t(filenamep, ptr - filenamep);

		in_t::ptr_t idp = ptr;
		limit = LINE_LENGTH;
		if (!ptr.scan(" \n", 2, limit))
			throw exception_log_t(log::error, "format error #7-2");

		request.id = in_segment_t(idp, ptr - idp);

		if (*ptr != '\n')
			throw exception_log_t(log::error, "format error #8");
		++ptr;

		limit = LINE_LENGTH;
		in_t::ptr_t linep = ptr;
		ptr.scan(" \n", 2, limit);

		str_t write_command = CSTR("write");
		str_t read_command = CSTR("read");
		str_t remove_command = CSTR("remove");

		MKCSTR(cmd, in_segment_t(linep, 4));

		if (linep.match<ident_t>(write_command)) {
			linep += write_command.size();
			request.command = write_data;
		} else if (linep.match<ident_t>(read_command)) {
			linep += read_command.size();
			request.command = read_data;
		} else if (linep.match<ident_t>(remove_command)) {
			linep += remove_command.size();
			request.command = remove_data;
		} else {
			throw exception_log_t(log::error, "format error #9");
		}
		if (*ptr != ' ' && *ptr != '\n')
			throw exception_log_t(log::error, "format error #10");

		if (*ptr == ' ') {
			++ptr;
			ptr.parse(request.offset, error_handler);
		} else {
			request.offset = 0;
		}

		if (*ptr == ' ') {
			++ptr;
			ptr.parse(request.size, error_handler);
		} else {
			request.size = 0;
		}

		if (*ptr != '\n')
			throw exception_log_t(log::error, "format error #11");
		++ptr;

		if (request.command == write_data) {
			if (ptr == endp)
				throw exception_log_t(log::error, "format error #12");

			request.data = in_segment_t(ptr, endp - ptr - 1);
		} else if (ptr != endp) {
			throw exception_log_t(log::error, "format error #13");
		}

		ptr = endp;

		if (*ptr != '\n')
			throw exception_log_t(log::error, "format error #14");

		++ptr;
		if (*ptr == '\n')
			throw exception_log_t(log::error, "format error #15");

		in.truncate(ptr);
	}
	catch(const exception_t &exc) {
		work = false;
		throw;
	}

	return true;
}

interval_t log_file_t::stat(bool clear) {
	interval_t delta_print;

	if(clear) {
		delta_print = delta;
		delta = interval_zero;
	}
	else
		delta_print = delta_max;

	return delta_print;
}

class elliptics_source_log_t : public elliptics_source_t {
public:
	struct config_t {
		string_t filename;
		sizeval_t ibuf_size;

		inline config_t() throw() : filename(), ibuf_size(sizeval_mega) { }

		inline void check(in_t::ptr_t const &ptr) const {
			if(!filename)
				config::error(ptr, "filename is required");

			if(ibuf_size > sizeval_giga)
				config::error(ptr, "ibuf_size is too big");

			if(ibuf_size < sizeval_kilo)
				config::error(ptr, "ibuf_size is too small");
		}
	};

private:
	mutable thr::mutex_t mutex;
	int fd;
	size_t ibuf_size;
	string_t filename;
	log_file_t *log_file;

	virtual bool get_request(request_t &request) const;
	virtual void init();
	virtual void stat(out_t &out, bool clear, bool hrr_flag) const;
	virtual void fini();

public:
	inline elliptics_source_log_t(string_t const &, config_t const &config) :
		mutex(), fd(-1), ibuf_size(config.ibuf_size), filename(config.filename),
		log_file(NULL) { }

	inline ~elliptics_source_log_t() throw() { }
};

namespace elliptics_source_log {
config_binding_sname(elliptics_source_log_t);
config_binding_value(elliptics_source_log_t, filename);
config_binding_value(elliptics_source_log_t, ibuf_size);
config_binding_ctor(elliptics_source_t, elliptics_source_log_t);
}

void elliptics_source_log_t::init() {
	MKCSTR(_filename, filename);

	fd = open(_filename, O_RDONLY, 0);
	if(fd < 0)
		throw exception_sys_t(log::error, errno, "open (%s): %m", _filename);

	log_file = new log_file_t(ibuf_size, fd);
}

bool elliptics_source_log_t::get_request(request_t &request) const {
	interval_t interval_sleep = interval_zero;
	bool res = ({
		thr::mutex_guard_t guard(mutex);

		if(!log_file)
			return false;

		log_file->get_request(request, interval_sleep);
	});

	if(res && interval_sleep > interval_zero && bq_sleep(&interval_sleep) < 0)
		return false;

	return res;
}

void elliptics_source_log_t::stat(out_t &out, bool clear, bool hrr_flag) const {
	interval_t delta = ({
		thr::mutex_guard_t guard(mutex);
		log_file ? log_file->stat(clear) : interval_zero;
	});

	if(hrr_flag) {
		out.lf()(CSTR("== elliptics_source_log")).lf();

		out(CSTR("delta: ")).print(delta).lf();
	}
	else {
		out(CSTR("elliptics_source_log\t")).print(delta/interval_millisecond).lf();
	}
}

void elliptics_source_log_t::fini() {
	log_file_t *_log_file = NULL;
	{
		thr::mutex_guard_t guard(mutex);
		_log_file = log_file;
		log_file = NULL;
	}

	delete _log_file;
	close(fd);
	fd = -1;
}

}}} // namespace phantom::io_benchmark::method_elliptics

