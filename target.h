#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "store.h"
#include "index.h"

struct target {
	struct store s;

	struct index idx;
	int fd;
	bool queryable;

	off_t offset;
	bool seekable;
};

struct target *target_new(const char *path);

int target_write(struct target *t, const uint8_t *data, size_t len, off_t offset, const uint8_t *id);

static inline struct store *target_as_store(struct target *t)
{
	if (!t->seekable) {
		u_log(WARN, "cannot use non-seekable target as store");
		return NULL;
	}

	t->queryable = true;

	return &t->s;
}
