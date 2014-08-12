// This file is part of the phantom::io_benchmark module.
// Copyright (C) 2013, Ruslan Nigmatullin <euroelessar@yandex.ru>.
// Copyright (C) 2013, YANDEX LLC.
// This module may be distributed under the terms of the GNU LGPL 2.1.
// See the file ‘COPYING’ or ‘http://www.gnu.org/licenses/lgpl-2.1.html’.

#pragma once

#include <phantom/pd.H>

#include <pd/base/out.H>
#include <pd/base/time.H>

#include <vector>

#pragma GCC visibility push(default)

namespace phantom { namespace io_benchmark { namespace method_elliptics {

enum command_t {
	write_data,
	read_data,
	remove_data,
	exec_request
};

struct request_t {
	command_t command;

	uint64_t cflags;
	uint32_t ioflags;
	std::vector<int> groups;

	in_segment_t filename;
	in_segment_t id;

	in_segment_t request;
	in_segment_t tag;

	uint64_t offset;
	uint64_t size;
	in_segment_t data;
};

class elliptics_source_t {
public:
	virtual bool get_request(request_t &request) const = 0;
	virtual void init() = 0;
	virtual void run() = 0;
	virtual void stat_print() const = 0;
	virtual void fini() = 0;

protected:
	inline elliptics_source_t() throw() { }
	inline ~elliptics_source_t() throw() { }

private: // don't use
	void *operator new(size_t);
	void operator delete(void *);
};

}}} // namespace phantom::io_benchmark::method_elliptics

#pragma GCC visibility pop
