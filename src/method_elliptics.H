// This file is part of the phantom::io_benchmark module.
// Copyright (C) 2013, Ruslan Nigmatullin <euroelessar@yandex.ru>.
// Copyright (C) 2013, YANDEX LLC.
// This module may be distributed under the terms of the GNU LGPL 2.1.
// See the file ‘COPYING’ or ‘http://www.gnu.org/licenses/lgpl-2.1.html’.

#pragma once

#include <phantom/io_benchmark/method.H>

#include <pd/base/fd.H>
#include <pd/base/netaddr.H>
#include <pd/base/config.H>
#include <pd/base/config_list.H>
#include <pd/base/ipv4.H>
#include <pd/base/ipv6.H>

#include <elliptics/cppdef.h>

#pragma GCC visibility push(default)

namespace phantom { namespace io_benchmark {

namespace method_elliptics {
class elliptics_source_t;
class request_t;
class stat_t;
}
namespace method_stream {
class logger_t;
class result_t;
}

class method_elliptics_t : public method_t
{
public:
	typedef ioremap::elliptics::node elliptics_node_t;
	typedef ioremap::elliptics::session elliptics_session_t;
	typedef ioremap::elliptics::file_logger elliptics_file_logger_t;
	typedef ioremap::elliptics::logger_base elliptics_logger_base_t;
	typedef ioremap::elliptics::logger elliptics_logger_t;
	typedef method_elliptics::elliptics_source_t elliptics_source_t;
	typedef method_elliptics::request_t request_t;
	typedef method_elliptics::stat_t stat_t;
	typedef method_stream::logger_t logger_t;
	typedef method_stream::result_t result_t;

protected:
	struct loggers_t : sarray1_t<logger_t *>
	{
		inline loggers_t(const config::list_t<config::objptr_t<logger_t>> &list) throw() : sarray1_t<logger_t *>(list) {}
		inline ~loggers_t() throw() {}

		void commit(const in_segment_t &request, const in_segment_t &tag, const result_t &res) const;

	};

	elliptics_logger_base_t logger;
	dnet_config cfg;
	std::vector<elliptics_node_t> nodes;
	elliptics_source_t &source;
	stat_t &stat;
	loggers_t &loggers;

	bool test(times_t &stat) const;
	void do_init();
	void do_fini();
	void do_run() const;
	void do_stat_print() const;

public:
	struct config_t {
		config_binding_type_ref(elliptics_source_t);
		config_binding_type_ref(logger_t);

		u_int16_t port;
		int family;
		string_t logger_filename;
		string_t logger_level;
		config::objptr_t<elliptics_source_t> source;
		config::list_t<config::objptr_t<logger_t> > loggers;
		uint timeout;
		uint nodes_count;
		long check_timeout;
		int flags;
		int io_thread_num;
		int net_thread_num;

		config_t() throw();
		void check(in_t::ptr_t const &ptr) const;
		inline ~config_t() throw() { }
	};

	method_elliptics_t(string_t const &, config_t const &);
	~method_elliptics_t() throw();
};

class method_elliptics_ipv4_t : public method_elliptics_t
{
public:
	struct config_t : method_elliptics_t::config_t {
		address_ipv4_t address;

		config_t() throw();
		void check(in_t::ptr_t const &ptr) const;
	};

	method_elliptics_ipv4_t(string_t const &, config_t const &);
	~method_elliptics_ipv4_t() throw();
};

class method_elliptics_ipv6_t : public method_elliptics_t
{
public:
	struct config_t : method_elliptics_t::config_t {
		address_ipv6_t address;

		config_t() throw();
		void check(in_t::ptr_t const &ptr) const;
	};

	method_elliptics_ipv6_t(string_t const &, config_t const &);
	~method_elliptics_ipv6_t() throw();
};

}} // namespace phantom::io_benchmark

#pragma GCC visibility pop
