
/* Define if kernel is 64 bit and userland is 32 bit */
#undef KERNEL64_USER32

@BOTTOM@

#include <sys/types.h>

#ifdef KERNEL64_USER32
typedef u_int64_t kptr_t;
#else
typedef void *kptr_t;
#endif
