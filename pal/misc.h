#ifndef __MISC_H__
#define __MISC_H__

//max table length is one 4k page for the moment. to be revised
#define MAX_TABLE_LENGTH (PAGE_SIZE/sizeof(cap_t))

#define DO_OR_BAIL(e, failop, op, args...)  \
do {                                \
	int rv = op(args);              \
	if(rv != ESUCCESS) {            \
		failop;                     \
		return e == 0 ? rv : -e;    \
	}                               \
} while (0)


#define ANNIHILATE(x, sz) memset(x, 0, sz)

#define NOTHING (void)0

#ifdef NDEBUG
#define DPRINTF(fmt, args...)
#else //NDEBUG
#define DPRINTF(fmt, args...) printf("%s: " fmt, __FUNCTION__, ##args)
#endif //NDEBUG

#endif /* __MISC_H__ */

