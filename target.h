#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "store.h"
#include "index.h"

struct target {
	struct store s;

	struct index idx;
	int fd;
};

struct target *target_new(const char *path);

ssize_t target_write(struct target *t, const uint8_t *data, size_t len, off_t offset, const uint8_t *id, bool read_before_write);

int target_calc_chunk_id(struct target *t, off_t offset, size_t len, uint8_t *data_out, uint8_t *id_out);

static inline struct store *target_as_store(struct target *t)
{
	return &t->s;
}
