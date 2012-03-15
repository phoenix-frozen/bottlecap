#ifndef __MISC_H__
#define __MISC_H__

#define DO_OR_BAIL(e, op, args...)  \
do {                                \
	int rv = op(args);              \
	if(rv != ESUCCESS) {            \
		return e == 0 ? rv : -e;    \
	}                               \
} while (0)


#endif /* __MISC_H__ */

