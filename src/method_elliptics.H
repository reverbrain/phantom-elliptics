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

#include <elliptics/cppdef.h>

#pragma GCC visibility push(default)

namespace phantom { namespace io_benchmark {

namespace method_elliptics {
class source_t;
class request_t;
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
	typedef ioremap::elliptics::logger elliptics_logger_t;
	typedef method_elliptics::source_t source_t;
	typedef method_elliptics::request_t request_t;
	typedef method_stream::logger_t logger_t;
	typedef method_stream::result_t result_t;

private:
	elliptics_logger_t logger;
	dnet_config cfg;
	elliptics_node_t node;
	source_t &source;

	struct loggers_t {
		size_t size;
		logger_t **items;
		inline loggers_t() throw() : size(0), items(NULL) { }
		inline ~loggers_t() throw() { if(items) delete [] items; }

		void commit(
			in_segment_t const &request, in_segment_t const &tag, result_t const &res
		) const;

	} loggers;

	virtual bool test(stat_t &stat) const;
	virtual void init();
	virtual void stat(out_t &out, bool clear, bool hrr_flag) const;
	virtual void fini();
	virtual size_t maxi() const throw();
	virtual descr_t const *descr(size_t ind) const throw();

public:
	struct config_t {
		config_binding_type_ref(source_t);
		config_binding_type_ref(logger_t);

		config::list_t<string_t> remotes;
		string_t logger_filename;
		config::objptr_t<source_t> source;
		config::list_t<config::objptr_t<logger_t> > loggers;
		unsigned int wait_timeout;
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

}} // namespace phantom::io_benchmark

#pragma GCC visibility pop
