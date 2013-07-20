#ifndef ADIOS_H
#define ADIOS_H

/* Include files */
#include <sys/types.h>

/* Standard definitions */
#if !defined(HAVE_CONFIG_H) && !defined(HAVE_SYSDEPS_H) && !defined(__GNUC__)
# define const			/* */
# define inline			/* */
# define __attribute__(args)	/* */
#endif

/* Exit codes */
#define EXIT_HAPPILY		0
#define EXIT_ERR_USER		1
#define EXIT_ERR_OTHER		2
#define EXIT_ERR_INSIDE		3
#define EXIT_ERR_INTR		4
#define EXIT_ERR_INPUT		5
#define EXIT_ERR_FALSE		6

#ifndef CHAR_BIT
# define CHAR_BIT		8
#endif
#define NOT_NULL		((void *)!0)

/* Macros */
/* Stringify */
#define Q(str)			QQ(str)
#define QQ(str)			#str

/* Typecast */
#define C(buf)			((char const *)(buf))
#define VPP(ptr)		((void **)(ptr))

/* Compile-time assertion */
#define STATIC_ASSERT0(id, ex)	typedef int static_assert_##id[-(!(ex))]
#define STATIC_ASSERT1(id, ex)	STATIC_ASSERT0(id, ex)
#define STATIC_ASSERT(expr)	STATIC_ASSERT1(__LINE__, expr)

/* gcc version check */
#ifdef __GNUC__
# define GCC_AT_LEAST(major, minor)	(__GNUC__ > (major) \
	|| (__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)))
#else
# define GCC_AT_LEAST(major, minor)	0
#endif

#define XCHG_ANY(ptype, p1, p2)	\
do				\
{				\
	ptype tmp;		\
				\
	(tmp) = (p1);		\
	(p1) = (p2);		\
	(p2) = (tmp);		\
} while (0)

#define BITS_OF(obj)		(CHAR_BIT * sizeof(obj))
#define DISTANCE_OF(far, near)	((char const *)(far) - (char const *)(near))
#define FIELD_OF(st, field)	((st *)0)->field
#define MEMBS_OF(array)		(sizeof(array) / sizeof(*(array)))
#define LAST_OF(array)		(array)[MEMBS_OF(array) - 1]
#define END_OF(array)		&LAST_OF(array)
#define AFTER_OF(array)		&(array)[MEMBS_OF(array)]

#define STRSIZE(str)		sizeof(str)
#define STRLEN(str)		(sizeof(str) - 1)
#define STR_SIZE(str)		(str), STRSIZE(str)
#define STR_LEN(str)		(str), STRLEN(str)

#ifndef MIN
# define MIN(a, b)		((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
# define MAX(a, b)		((a) > (b) ? (a) : (b))
#endif
#define INRANGE(n, lo, hi)	((lo) <= (n) && (n) <= (hi))

#define MK_PATH(dir, fname)	dir "/" fname
#define MK_INADDR(a, b, c, d)	\
	(((a) << 24) | ((b) << 16) | ((c) << 8) | (d))
#define DE_INADDR(addr)		\
	((addr) >> 24) & 0xFF, ((addr) >> 16) & 0xFF, \
		((addr) >> 8) & 0xFF, (addr) & 0xFF

#define VARST_SIZE(var, last, nmem) \
	((sizeof(*(var)) - sizeof((var)->last)) \
		+ (nmem) * sizeof((var)->last))
#define DEF_VARSTRUCT(ast, var, last, lastmem) \
union \
{ \
	ast st; \
	char pad[sizeof(ast) - sizeof(FIELD_OF(ast, last)) \
		+ (lastmem) * sizeof(*FIELD_OF(ast, last))]; \
} var

#endif /* ! ADIOS_H */
