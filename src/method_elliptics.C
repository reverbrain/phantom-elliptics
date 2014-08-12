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
#include <pd/base/stat_items.H>
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
	port(0), family(0), logger_filename(STRING("/dev/null")), logger_level(STRING("error")),
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

void method_elliptics_t::loggers_t::commit(const in_segment_t &request, const in_segment_t &tag, const result_t &res) const
{
	for(size_t i = 0; i < size; ++i) {
		items[i]->commit(request, tag, res);
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
config_binding_parent(method_elliptics_ipv4_t, method_elliptics_t);
config_binding_ctor(method_t, method_elliptics_ipv4_t);
}

namespace ipv6 {
config_binding_sname(method_elliptics_ipv6_t);
config_binding_value(method_elliptics_ipv6_t, address);
config_binding_parent(method_elliptics_ipv6_t, method_elliptics_t);
config_binding_ctor(method_t, method_elliptics_ipv6_t);
}

typedef stat::count_t conns_t;
typedef stat::count_t icount_t;
typedef stat::count_t ocount_t;
typedef stat::mmcount_t mmtasks_t;

class load_t {
	spinlock_t spinlock;
	interval_t real, event;

public:
	inline load_t() throw() :
	spinlock(), real(interval::zero), event(interval::zero) { }

	inline ~load_t() throw() { }

	load_t(load_t const &) = delete;
	load_t &operator=(load_t const &) = delete;

	inline void put(interval_t _real, interval_t _event) {
		spinlock_guard_t guard(spinlock);
		real += _real;
		event += _event;
	}

	typedef load_t val_t;

	class res_t {
	public:
		interval_t real, event;

		inline res_t(load_t &load) throw() {
			spinlock_guard_t guard(load.spinlock);
			real = load.real; load.real = interval::zero;
			event = load.event; load.event = interval::zero;
		}

		inline res_t() throw() :
		real(interval::zero), event(interval::zero) { }

		inline ~res_t() throw() { }

		inline res_t(res_t const &) = default;
		inline res_t &operator=(res_t const &) = default;

		inline res_t &operator+=(res_t const &res) throw() {
			real += res.real;
			event += res.event;

			return *this;
		}
	};

	friend class res_t;
};


typedef stat::items_t<
	conns_t,
	icount_t,
	ocount_t,
	mmtasks_t,
	load_t
> stat_base_t;

struct stat_t : stat_base_t {
	inline stat_t() throw() : stat_base_t(
		STRING("conns"),
		STRING("in"),
		STRING("out"),
		STRING("mmtasks"),
		STRING("load")
	) {}

	inline ~stat_t() throw() {}

	inline conns_t &conns() throw() { return item<0>(); }
	inline icount_t &icount() throw() { return item<1>(); }
	inline ocount_t &ocount() throw() { return item<2>(); }
	inline mmtasks_t &mmtasks() throw() { return item<3>(); }
	inline load_t &load() throw() { return item<4>(); }
};

}

static ioremap::elliptics::logger_base create_logger(const method_elliptics_t::config_t &config) {
	try {
		using ioremap::elliptics::logger_base;
		using ioremap::elliptics::log_level;
		using ioremap::elliptics::file_logger;
		MKCSTR(logger_filename, config.logger_filename);
		MKCSTR(logger_level, config.logger_level);

		if (strcmp(logger_filename, "/dev/null") == 0) {
			static_assert(static_cast<int>(DNET_LOG_ERROR) > static_cast<int>(DNET_LOG_DEBUG), "Fix log_level");

			log_level level = static_cast<log_level>(static_cast<int>(DNET_LOG_ERROR) + 1);
			logger_base logger;
			logger.verbosity(level);
			return logger;
		} else {
			log_level level = file_logger::parse_level(logger_level);
			return file_logger(logger_filename, level);
		}
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
	method_t(STRING("elliptics")), logger(create_logger(config)), cfg(create_config(config)),
	source(*config.source), stat(*new stat_t), loggers(*new loggers_t(config.loggers))
{

	for (uint i = 0; i < config.nodes_count; ++i)
		nodes.emplace_back(ioremap::elliptics::logger(logger, blackhole::log::attributes_t()), cfg);
}

method_elliptics_t::~method_elliptics_t() throw() {
	delete &stat;
	delete &loggers;
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
	ioremap::elliptics::error_info *exception;
	bq_cond_t *cond;
	timeval_t *time_recv;
	size_t *size_in;

	void operator() (const ioremap::elliptics::callback_result_entry &result)
	{
		*size_in += result.raw_data().size();
	}

	void operator() (const ioremap::elliptics::error_info &error)
	{
		bq_cond_t::handler_t handler(*cond);
		*exception = error;
		*time_recv = timeval::current();
		handler.send();
	}
};

bool method_elliptics_t::test(times_t &times) const
{
	request_t request;
	if (!source.get_request(request))
		return false;

	result_t result;

	elliptics_session_t session(nodes[rand() % nodes.size()]);

	session.set_cflags(request.cflags);
	session.set_ioflags(request.ioflags);
	session.set_groups(request.groups);
	session.set_filter(ioremap::elliptics::filters::all_with_ack);
	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);

	result.size_in += request.groups.size() * sizeof(dnet_cmd);
	result.size_out += request.groups.size() * sizeof(dnet_cmd);

	ioremap::elliptics::key id;
	if (request.id) {
		MKCSTR(cid, request.id);
		dnet_id did;
		memset(&did, 0, sizeof(did));
		dnet_parse_numeric_id(cid, did.id);
		id = did;
	} else if (request.command == method_elliptics::exec_request) {
		id = make_string(request.data);
	} else {
		id = make_string(request.filename);
	}

	try {
		ioremap::elliptics::error_info exception;
		bq_cond_t cond;
		method_elliptics_handler_t handler = {
			&exception, &cond, &result.time_recv, &result.size_in
		};

		switch (request.command) {
		case method_elliptics::write_data:
			result.size_out += request.groups.size() * request.data.size();
			session.write_data(id, make_string(request.data), request.offset).connect(handler, handler);
			break;
		case method_elliptics::read_data:
			session.read_data(id, request.offset, request.size).connect(handler, handler);
			break;
		case method_elliptics::remove_data:
			session.remove(id).connect(handler, handler);
			break;
		case method_elliptics::exec_request: {
			result.size_out += request.data.size();
			const std::string data = make_string(request.data);
			id.transform(session);
			dnet_id did = id.id();
			session.exec(&did, make_string(request.filename), data).connect(handler, handler);
			break;
			}
		}

		result.time_conn = timeval::current();
		result.time_send = result.time_conn;

		{
			bq_cond_t::handler_t handler(cond);
			if (!result.time_recv.is_real() && !bq_success(handler.wait(NULL)))
				throw exception_sys_t(log::error, errno, "cond.wait: %m");
		}

		result.time_recv = std::max(result.time_recv, result.time_send);
		result.time_end = timeval::current();

		if (exception) {
			result.log_level = logger_t::proto_warning;
			result.err = exception.code();
			switch (exception.code()) {
			case -ENOENT:
				result.proto_code = 404;
				break;
			case -ENXIO:
				result.proto_code = 403;
				break;
			default:
				result.proto_code = 500;
				break;
			}
		} else {
			result.proto_code = 200;
		}

		auto interval_real = result.time_end - result.time_start;

		times.inc(interval_real);
		stat.load().put(interval_real, result.time_end - result.time_send);
		stat.icount() += result.size_in;
		stat.ocount() += result.size_out;

		loggers.commit(request.request, request.tag, result);
	} catch (const ioremap::elliptics::error &e) {
		throw exception_sys_t(log::error, e.error_code(), "%s", e.what());
	} catch (const std::exception &e) {
		throw exception_sys_t(log::error, 0, "%s", e.what());
	}

	return true;
}

void method_elliptics_t::do_init()
{
	source.init();
}

void method_elliptics_t::do_fini()
{
	source.fini();
}

void method_elliptics_t::do_run() const
{
	source.run();
}

void method_elliptics_t::do_stat_print() const
{
	stat.print();
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
			nodes[i].add_remote(ioremap::elliptics::address(address, c.port, c.family));
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
			nodes[i].add_remote(ioremap::elliptics::address(address, c.port, c.family));
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
