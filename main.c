#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <time.h>
#include <getopt.h>

#include "utils.h"
#include "caibx.h"
#include "chunker.h"
#include "store-local.h"
#include "store-http.h"
#include "target.h"
#include "ui.h"

static struct store *store_local, *store_remote;
static struct target *target;
static struct chunker_params chunker_params;
static size_t n_entries;
static int index_fd;

static bool interactive = false;

struct {
	size_t total_chunks;
	size_t repeated_chunks;

	size_t local_hits;
	size_t remote_hits;

	size_t inplace_hashes, inplace_hits;

	off_t total_bytes, total_bytes_written;
} sync_stats;

static int sync_chunk(uint64_t offset, uint32_t len, uint8_t *id, void *arg)
{
	static bool have_buf_id = false;
	static uint8_t buf_id[CHUNK_ID_LEN];
	static uint8_t buf[256*1024];
	bool read_before_write = true;

	(void) arg;

	if ((size_t)len > sizeof(buf)) {
		u_log(ERR, "chunk is too large for buffer (%zu > %zu)", (size_t)len, sizeof(buf));
		return -1;
	}

	sync_stats.total_chunks++;
	sync_stats.total_bytes += len;

	// if we are writing the same entry multiple times, we can reuse the
	// data
	if (have_buf_id && memcmp(buf_id, id, CHUNK_ID_LEN) == 0) {
		sync_stats.repeated_chunks++;

		goto write_chunk;
	}

	// otherwise, try local stores first
	ssize_t ret_len;
	ret_len = store_get_chunk(store_local, id, buf, sizeof(buf));
	if (ret_len >= 0 && (size_t)ret_len == len) {
		memcpy(buf_id, id, CHUNK_ID_LEN);
		have_buf_id = true;

		sync_stats.local_hits++;

		goto write_chunk;
	}

	// try hashing the target area to see if it already contains the data
	// we want without downloading it first
	if (target_calc_chunk_id(target, offset, len, buf, buf_id) == 0) {
		sync_stats.inplace_hashes++;

		if (memcmp(buf_id, id, CHUNK_ID_LEN) == 0) {
			// chunk matches already, nothing to be done
			sync_stats.inplace_hits++;
			goto progress;
		}
	} else {
		u_log(WARN, "calculating in-place chunk id failed");
		have_buf_id = false;

		// fall through
	}

	// last resort: download the chunk
	ret_len = store_get_chunk(store_remote, id, buf, sizeof(buf));
	if (ret_len >= 0 && (size_t)ret_len == len) {
		memcpy(buf_id, id, CHUNK_ID_LEN);
		have_buf_id = true;

		// because of the above checks, we know that the target has to
		// differ from what we want it to be, so don't check it again
		read_before_write = false;

		sync_stats.remote_hits++;

		goto write_chunk;
	}

	char chunk_id_str[CHUNK_ID_STRLEN];
	chunk_format_id(chunk_id_str, id);

	u_log(ERR, "chunk %s not found in any store", chunk_id_str);

	return -1;

	ssize_t written;
write_chunk:
	written = target_write(target, buf, len, offset, id, read_before_write);
	if (written < 0) {
		u_log(ERR, "failed to store chunk to target");
		return -1;
	}

	sync_stats.total_bytes_written += written;

progress:
	// only show progress bar when running interactively and not spamming
	// debug information anyway
	if (interactive && !check_loglevel(U_LOG_DEBUG)) {
		static progess_status_t progress_status = PROGRESS_STATUS_INIT;

		show_progress(100 * sync_stats.total_chunks / n_entries, &progress_status);
	}

	return 0;
}

static int append_store_from_arg(char *arg)
{
	struct store *s;
	struct store_chain *sc;

	if (startswith(arg, "http")) {
		s = store_http_new(arg);
		if (!s) {
			u_log(ERR, "creating HTTP store from '%s' failed", arg);
			return -1;
		}

		sc = (struct store_chain*)store_remote;
	} else {
		char *p = strchr(arg, ':');
		if (p) {
			*p = 0;
			p++;
		}

		s = store_local_new(arg, p, &chunker_params);
		if (!s) {
			u_log(ERR, "creating local store from '%s' failed", arg);
			return -1;
		}

		sc = (struct store_chain*)store_local;
	}

	if (store_chain_append(sc, s) < 0) {
		u_log(ERR, "appending store '%s' to store chain failed", arg);
		return -1;
	}

	return 0;
}

static int csn(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "usage: %s input.caibx target [store ...]\n", argv[0]);
		return -1;
	}

	index_fd = open(argv[1], O_RDONLY);
	if (index_fd < 0) {
		u_log_errno("opening index '%s' failed", argv[1]);
		return -1;
	}

	if (caibx_load_header(index_fd, &chunker_params, &n_entries) < 0) {
		u_log(ERR, "loading caibx header failed");
		return -1;
	}

	target = target_new(argv[2]);
	if (!target) {
		u_log(ERR, "creating target failed");
		return -1;
	}

	if (store_chain_append((struct store_chain*)store_local, target_as_store(target)) < 0) {
		u_log(ERR, "appending target to store chain failed");
		return -1;
	}

	for (int i = 3; i < argc; i++) {
		if (append_store_from_arg(argv[i]) < 0)
			return -1;
	}

	return 0;
}

static void casync_help(void)
{
	fprintf(stderr,
	        "casync [OPTIONS...] extract BLOB_INDEX PATH\n"
	        "\n"
	        "note: This is casync-nano, which only supports extracting blob indices\n"
	        "      and just implements enough command line parsing to work with RAUC.\n"
	        "\n"
	        "supported options:\n"
	        "  --store      add a chunk store (HTTP(S) only)\n"
	        "  --seed       add seed (block device or file)\n");
}

static int casync(int argc, char **argv)
{
	enum {
		ARG_STORE = 0x100,
		ARG_SEED,
		ARG_SEED_OUTPUT
	};

	static const struct option options[] = {
		{ "help",              no_argument,       NULL, 'h'                   },
		{ "store",             required_argument, NULL, ARG_STORE             },
		{ "seed",              required_argument, NULL, ARG_SEED              },
		{ "seed-output",       required_argument, NULL, ARG_SEED_OUTPUT       },
		{}
	};

	if (argc < 3) {
		casync_help();
		exit(EXIT_FAILURE);
	}

	index_fd = open(argv[argc-2], O_RDONLY);
	if (index_fd < 0) {
		u_log_errno("opening index '%s' failed", argv[argc-2]);
		return -1;
	}

	if (caibx_load_header(index_fd, &chunker_params, &n_entries) < 0) {
		u_log(ERR, "loading caibx header failed");
		return -1;
	}

	target = target_new(argv[argc-1]);
	if (!target) {
		u_log(ERR, "creating target failed");
		return -1;
	}

	if (store_chain_append((struct store_chain*)store_local, target_as_store(target)) < 0) {
		u_log(ERR, "appending target to store chain failed");
		return -1;
	}

	int c;
	while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {
		switch (c) {
			case 'h':
				casync_help();
				return 0;
			case ARG_STORE:
			case ARG_SEED:
				if (append_store_from_arg(optarg) < 0)
					return -1;

				break;
			case ARG_SEED_OUTPUT:
				// ignored to silence unknown option warning
				// with rauc
				break;
			default:
				casync_help();
				exit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 3 || !streq(argv[0], "extract")) {
		casync_help();
		exit(EXIT_FAILURE);
	}

	return 0;
}

int main(int argc, char **argv)
{
	u_log_init();

	int exit_code = EXIT_FAILURE;

	if (isatty(STDOUT_FILENO))
		interactive = true;

	time_t now;

	now = time_monotonic();
	time_t start = now;

	int (*app)(int argc, char **argv);
	const char *appname = basename(argv[0]);
	if (streq(appname, "csn")) {
		app = csn;
	} else if (streq(appname, "casync")) {
		app = casync;
	} else {
		u_log(ERR, "unimplemented app variant '%s'", appname);
		goto out;
	}

	store_local = store_chain_to_store(store_chain_new(2));
	if (!store_local) {
		u_log(ERR, "allocating local store chain failed");
		goto out;
	}

	store_remote = store_chain_to_store(store_chain_new(1));
	if (!store_remote) {
		u_log(ERR, "allocating remote store chain failed");
		goto out_sc_local;
	}

	if (app(argc, argv)) {
		u_log(ERR, "initializing synchronization process failed");
		goto out_sc_remote;
	}

	now = time_monotonic();
	u_log(INFO, "init finished after %u seconds", (unsigned int)(now - start));
	start = now;

	u_log(INFO, "starting synchronization");

	if (caibx_iterate_entries(index_fd, &chunker_params, n_entries, sync_chunk, NULL) < 0) {
		u_log(ERR, "iterating entries failed");
		goto out_index;
	}

	exit_code = EXIT_SUCCESS;

	now = time_monotonic();
	u_log(INFO, "synchronization finished after %u seconds", (unsigned int)(now - start));

	u_log(INFO, " total chunks: %zu", sync_stats.total_chunks);
	u_log(INFO, " total bytes: %zu", sync_stats.total_bytes);
	u_log(INFO, "  total bytes written: %zu (%.2f%%)", sync_stats.total_bytes_written,
	      100.0 * sync_stats.total_bytes_written / sync_stats.total_bytes);
	u_log(INFO, " local/remote hits: %zu/%zu", sync_stats.local_hits, sync_stats.remote_hits);
	u_log(INFO, " inplace hashes/hits: %zu/%zu", sync_stats.inplace_hashes, sync_stats.inplace_hits);

out_index:
	close(index_fd);
out_sc_remote:
	store_free(store_remote);
out_sc_local:
	store_free(store_local);
out:
	return exit_code;
}
