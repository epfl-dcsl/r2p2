#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include <r2p2/raft-stats.h>

#define RAFT_STATS_LOG_SIZE (1<<22)

static int rs_fd;
static void *rs_addr;
static struct raft_stats *current;
static long *count;

int raft_stats_init(void)
{
	int ret;

	printf("Initialise raft stats\n");

	rs_fd = shm_open("/raft-stats", O_RDWR | O_CREAT | O_TRUNC, 0660);
	if (rs_fd == -1)
		return -1;

	ret = ftruncate(rs_fd, RAFT_STATS_LOG_SIZE * sizeof(struct raft_stats));
	if (ret)
		return ret;

	rs_addr = mmap(NULL, RAFT_STATS_LOG_SIZE * sizeof(struct raft_stats),
			PROT_READ | PROT_WRITE, MAP_SHARED, rs_fd, 0);

	if (rs_addr == MAP_FAILED)
		return -1;

	current = (struct raft_stats *) rs_addr;
	count = &current->type;
	current++;

	return 0;
}

int raft_stats_log(struct raft_stats *rs)
{
	assert(*count < RAFT_STATS_LOG_SIZE);
	memcpy(current++, rs, sizeof(struct raft_stats));
	*count += 1;

	return 0;
}
