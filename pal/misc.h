#ifndef __MISC_H__
#define __MISC_H__

//max table length is one 4k page for the moment. to be revised
#define MAX_TABLE_LENGTH (PAGE_SIZE/sizeof(cap_t))

#define DO_OR_BAIL(e, op, args...)  \
do {                                \
	int rv = op(args);              \
	if(rv != ESUCCESS) {            \
		return e == 0 ? rv : -e;    \
	}                               \
} while (0)


#endif /* __MISC_H__ */

