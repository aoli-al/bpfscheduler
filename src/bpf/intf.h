#ifndef __CCT_INTF_H
#define __CCT_INTF_H

#ifndef __KERNEL__
typedef unsigned long long u64;
#endif

enum cct_consts {
	CCT_NUM_PPIDS_CHECK	= 1 << 20,
};

enum cct_match {
	CCT_MATCH_UNKNOWN			= 0,
	CCT_MATCH_COMPLETE			= 1 << 0,
	CCT_MATCH_NOT_CONTROLLED	= 1 << 1,
	CCT_MATCH_HAS_PARENT		= 1 << 2,

	CCT_MATCH_MAX				= 1 << 3,
};

struct cct_task_ctx {
	enum cct_match	match;
	u64			priority;
};


#endif /* __CCT_INTF_H */