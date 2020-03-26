#pragma once

struct __attribute__((__packed__)) raft_stats {
	long type;
	long duration;
};

int raft_stats_init(void);
int raft_stats_log(struct raft_stats *rs);
