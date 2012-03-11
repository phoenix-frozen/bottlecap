#ifndef __ERRORS_H__
#define __ERRORS_H__

#define ESUCCESS   0 //yup, the error code that says 'it worked!'
#define ENOMEM     1 //ran out of memory or insufficient memory provided
#define EINVAL     2 //invalid argument
#define ENOTSUP    3 //invalid operation with current arguments
#define ENOSYS     4 //function not implemented
#define ESIGFAIL   5 //bottle signature verification failed
#define ECRYPTFAIL 6 //failure in cryptographic subsystem
#define ECORRUPT   7 //corruption detected in captable

#endif /* __ERRORS_H__ */

