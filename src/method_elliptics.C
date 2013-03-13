// This file is part of the phantom::io_benchmark module.
// Copyright (C) 2013, Ruslan Nigmatullin <euroelessar@yandex.ru>.
// Copyright (C) 2013, YANDEX LLC.
// This module may be distributed under the terms of the GNU LGPL 2.1.
// See the file ‘COPYING’ or ‘http://www.gnu.org/licenses/lgpl-2.1.html’.

#include "method_elliptics.H"
#include "source.H"

#include <phantom/module.H>
#include <phantom/io_benchmark/method_stream/logger.H>
#include <pd/bq/bq_util.H>
#include <pd/bq/bq_cond.H>
#include <pd/base/exception.H>

static int dnet_parse_numeric_id(char *value, unsigned char *id)
{
	unsigned char ch[5];
	unsigned int i, len = strlen(value);

	memset(id, 0, DNET_ID_SIZE);

	if (len/2 > DNET_ID_SIZE)
		len = DNET_ID_SIZE * 2;

	ch[0] = '0';
	ch[1] = 'x';
	ch[4] = '\0';
	for (i=0; i<len / 2; i++) {
		ch[2] = value[2*i + 0];
		ch[3] = value[2*i + 1];

		id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
	}

	if (len & 1) {
		ch[2] = value[2*i + 0];
		ch[3] = '0';

		id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
	}

	return 0;
}

namespace phantom {
namespace io_benchmark {

MODULE(io_benchmark_method_elliptics);

method_elliptics_t::config_t::config_t() throw() :
	port(0), family(0), logger_filename(STRING("/dev/null")), logger_level(0),
	timeout(5), nodes_count(1), check_timeout(20), flags(0), io_thread_num(1),
	net_thread_num(1) {
}

void method_elliptics_t::config_t::check(const in_t::ptr_t &ptr) const {
	if (!nodes_count)
		config::error(ptr, "nodes_count must be positive");

	if (!port)
		config::error(ptr, "port is required");

	if (!family)
		config::error(ptr, "family is required");

	if (!source)
		config::error(ptr, "source is required");
}

void method_elliptics_t::loggers_t::commit(
	in_segment_t const &request, in_segment_t const &tag, result_t const &res
) const {
	for(size_t i = 0; i < size; ++i) {
		logger_t *logger = items[i];
		if(res.log_level >= logger->level)
			logger->commit(request, tag, res);
	}
}

namespace method_elliptics {
config_binding_sname(method_elliptics_t);
config_binding_value(method_elliptics_t, port);
config_binding_value(method_elliptics_t, family);
config_binding_type(method_elliptics_t, elliptics_source_t);
config_binding_value(method_elliptics_t, source);
config_binding_value(method_elliptics_t, logger_filename);
config_binding_value(method_elliptics_t, logger_level);
config_binding_type(method_elliptics_t, logger_t);
config_binding_value(method_elliptics_t, loggers);
config_binding_value(method_elliptics_t, timeout);
config_binding_value(method_elliptics_t, nodes_count);
config_binding_value(method_elliptics_t, flags);
config_binding_value(method_elliptics_t, check_timeout);
config_binding_value(method_elliptics_t, io_thread_num);
config_binding_value(method_elliptics_t, net_thread_num);
//config_binding_ctor(method_t, method_elliptics_t);

namespace ipv4 {
config_binding_sname(method_elliptics_ipv4_t);
config_binding_value(method_elliptics_ipv4_t, address);
config_binding_parent(method_elliptics_ipv4_t, method_elliptics_t, 1);
config_binding_ctor(method_t, method_elliptics_ipv4_t);
}

namespace ipv6 {
config_binding_sname(method_elliptics_ipv6_t);
config_binding_value(method_elliptics_ipv6_t, address);
config_binding_parent(method_elliptics_ipv6_t, method_elliptics_t, 1);
config_binding_ctor(method_t, method_elliptics_ipv6_t);
}
}

static ioremap::elliptics::logger create_logger(const method_elliptics_t::config_t &config) {
	try {
		MKCSTR(logger_filename, config.logger_filename);
		if (strcmp(logger_filename, "/dev/null") == 0)
			return method_elliptics_t::elliptics_logger_t(0, config.logger_level);
		else
			return method_elliptics_t::elliptics_file_logger_t(logger_filename, config.logger_level);
	} catch (const ioremap::elliptics::error &e) {
		throw exception_sys_t(log::error, e.error_code(), "%s", e.what());
	} catch (const std::exception &e) {
		throw exception_sys_t(log::error, 0, "%s", e.what());
	}
}

static dnet_config create_config(const method_elliptics_t::config_t &config) {
	dnet_config cfg;
	memset(&cfg, 0, sizeof(cfg));
	cfg.wait_timeout = config.timeout;
	cfg.flags = config.flags;
	cfg.check_timeout = config.check_timeout;
	cfg.io_thread_num = config.io_thread_num;
	cfg.net_thread_num = config.net_thread_num;
	return cfg;
}

method_elliptics_t::method_elliptics_t(const string_t &, const config_t &config) :
	method_t(), logger(create_logger(config)), cfg(create_config(config)),
	source(*config.source) {

	for (uint i = 0; i < config.nodes_count; ++i)
		nodes.emplace_back(logger, cfg);

	for(typeof(config.loggers.ptr()) lptr = config.loggers; lptr; ++lptr)
		++loggers.size;

	loggers.items = new logger_t *[loggers.size];

	size_t i = 0;
	for(typeof(config.loggers.ptr()) lptr = config.loggers; lptr; ++lptr)
		loggers.items[i++] = lptr.val();
}

method_elliptics_t::~method_elliptics_t() throw() {
}

static inline std::string make_string(in_segment_t &in)
{
	std::string string;
	string.resize(in.size());
	out_t(&string[0], string.size())(in);
	return string;
}

struct method_elliptics_handler_t
{
	std::exception_ptr *exception;
	bq_cond_t *cond;
	timeval_t *time_recv;
	size_t *size_in;

	template <typename T>
	void operator() (const ioremap::elliptics::array_result_holder<T> &result)
	{
		if ((*exception = result.exception()) != std::exception_ptr()) {
			finish();
			return;
		}

		for (size_t i = 0; i < result.size(); ++i)
			*size_in += result[i].raw_data().size();

		finish();
	}

	template <typename T>
	void operator() (const ioremap::elliptics::result_holder<T> &result)
	{
		if ((*exception = result.exception()) != std::exception_ptr()) {
			finish();
			return;
		}

		*size_in += result->raw_data().size();

		finish();
	}

	void operator() (const std::exception_ptr &exc)
	{
		*exception = exc;
		finish();
	}

	void operator() (const ioremap::elliptics::exec_result &)
	{
	}

	void finish()
	{
		bq_cond_guard_t guard(*cond);
		*time_recv = timeval_current();
		cond->send();
	}
};

bool method_elliptics_t::test(stat_t &stat) const
{
	request_t request;
	if (!source.get_request(request))
		return false;

	stat_t::tcount_guard_t tcount_guard(stat);
	result_t result;

	elliptics_session_t session(nodes[rand() % nodes.size()]);

	session.set_cflags(request.cflags);
	session.set_ioflags(request.ioflags);
	session.set_groups(request.groups);
	result.size_out += request.groups.size() * sizeof(dnet_cmd);
	result.size_in += request.groups.size() * sizeof(dnet_cmd);

	ioremap::elliptics::key id;
	if (request.id) {
		MKCSTR(cid, request.id);
		dnet_id did;
		memset(&did, 0, sizeof(did));
		dnet_parse_numeric_id(cid, did.id);
		id = did;
	} else if (request.command != method_elliptics::exec_request) {
		id = make_string(request.filename);
	}

	try {
		std::exception_ptr exception;
		bq_cond_t cond;
		method_elliptics_handler_t handler = {
			&exception, &cond, &result.time_recv, &result.size_in
		};

		switch (request.command) {
		case method_elliptics::write_data:
			result.size_out += request.groups.size() * request.data.size();
			session.write_data(handler, id, make_string(request.data), request.offset);
			break;
		case method_elliptics::read_data:
			session.read_data(handler, id, request.offset, request.size);
			break;
		case method_elliptics::remove_data:
			session.remove(handler, id);
			break;
		case method_elliptics::exec_request: {
			result.size_out += request.data.size();
			const std::string tmp_data = make_string(request.data);
			const ioremap::elliptics::data_pointer data = tmp_data;
			dnet_id did;
			did.group_id = 0;
			did.type = 0;
			session.transform(data, did);
			session.exec(handler, handler, &did, make_string(request.filename), data);
			break;
			}
		}

		result.time_conn = timeval_current();
		result.time_send = result.time_conn;

		{
			bq_cond_guard_t guard(cond);
			if (!result.time_recv.is_real() && !bq_success(cond.wait(NULL)))
				throw exception_sys_t(log::error, errno, "cond.wait: %m");
		}

		result.time_recv = std::max(result.time_recv, result.time_send);
		result.time_end = timeval_current();

		if (exception != std::exception_ptr()) {
			result.log_level = logger_t::proto_warning;
			try {
				std::rethrow_exception(exception);
			} catch (const ioremap::elliptics::not_found_error &e) {
				result.err = -e.error_code();
				result.proto_code = 404;
			} catch (const ioremap::elliptics::error &e) {
				result.err = -e.error_code();
				result.proto_code = 500;
			} catch (const std::bad_alloc &e) {
				result.err = ENOMEM;
				result.proto_code = 500;
			}
		} else {
			result.proto_code = 200;
		}

		{
			thr::spinlock_guard_t guard(stat.spinlock);

			stat.update_time(result.time_end - result.time_start,
							 result.time_end - result.time_send);

			if (!result.err)
				stat.update_size(result.size_in, result.size_out);
		}

		loggers.commit(request.request, request.tag, result);
	} catch (const ioremap::elliptics::error &e) {
		throw exception_sys_t(log::error, e.error_code(), "%s", e.what());
	} catch (const std::exception &e) {
		throw exception_sys_t(log::error, 0, "%s", e.what());
	}

	return true;
}

void method_elliptics_t::init()
{
	source.init();
}

void method_elliptics_t::stat(out_t &out, bool clear, bool hrr_flag) const
{
	source.stat(out, clear, hrr_flag);
}

void method_elliptics_t::fini()
{
	source.fini();
}

size_t method_elliptics_t::maxi() const throw()
{
	return 0;
}

class network_descr_t : public descr_t {
	static size_t const max_errno = 140;

	virtual size_t value_max() const { return max_errno; }

	virtual void print_header(out_t &out) const {
		out(CSTR("elliptics"));
	}

	virtual void print_value(out_t &out, size_t value) const {
		if(value < max_errno) {
			char buf[128];
			char *res = strerror_r(value, buf, sizeof(buf));
			buf[sizeof(buf) - 1] = '\0';
			out(str_t(res, strlen(res)));
		}
		else
			out(CSTR("Unknown error"));
	}
public:
	inline network_descr_t() throw() : descr_t() { }
	inline ~network_descr_t() throw() { }
};

static network_descr_t const network_descr;

const descr_t *method_elliptics_t::descr(size_t) const throw()
{
	return &network_descr;
}

method_elliptics_ipv4_t::config_t::config_t() throw()
{
	family = AF_INET;
}

void method_elliptics_ipv4_t::config_t::check(const in_t::ptr_t &ptr) const
{
	if (!address)
		config::error(ptr, "address is required");

	method_elliptics_t::config_t::check(ptr);
}

method_elliptics_ipv4_t::method_elliptics_ipv4_t(const string_t &s, const config_t &c) :
	method_elliptics_t(s, c)
{
	try {
		string_t address_str(string_t::ctor_t((3 + 1) * 4 - 1).print(c.address));
		MKCSTR(address, address_str);
		for (uint i = 0; i < nodes.size(); ++i)
			nodes[i].add_remote(address, c.port, c.family);
	} catch (const ioremap::elliptics::error &e) {
		throw exception_sys_t(log::error, e.error_code(), "%s", e.what());
	} catch (const std::exception &e) {
		throw exception_sys_t(log::error, 0, "%s", e.what());
	}
}

method_elliptics_ipv4_t::~method_elliptics_ipv4_t() throw()
{
}

method_elliptics_ipv6_t::config_t::config_t() throw()
{
	family = AF_INET;
}

void method_elliptics_ipv6_t::config_t::check(const in_t::ptr_t &ptr) const
{
	if (!address)
		config::error(ptr, "address is required");

	method_elliptics_t::config_t::check(ptr);
}

method_elliptics_ipv6_t::method_elliptics_ipv6_t(const string_t &s, const config_t &c) :
	method_elliptics_t(s, c)
{
	try {
		string_t address_str(string_t::ctor_t((4 + 1) * 8 - 1).print(c.address));
		MKCSTR(address, address_str);
		for (uint i = 0; i < nodes.size(); ++i)
			nodes[i].add_remote(address, c.port, c.family);
	} catch (const ioremap::elliptics::error &e) {
		throw exception_sys_t(log::error, e.error_code(), "%s", e.what());
	} catch (const std::exception &e) {
		throw exception_sys_t(log::error, 0, "%s", e.what());
	}
}

method_elliptics_ipv6_t::~method_elliptics_ipv6_t() throw()
{
}

} // namespace io_benchmark
} // namespace phantom
