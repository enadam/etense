/*
 * etense.c -- enhanced Electric Fence
 *
 * XXX This whole mess is undocumented, sorry.
 *
 * Configuration:
 *    Environment variable	C variable		default value
 * -- $ETENSE_BANNER		--			0
 * -- $ETENSE_ALIGNMENT		@ETense_Alignment	sizeof(int)
 * -- $ETENSE_PROTECT_UNDER	@ETense_Protect_Under	1
 * -- $ETENSE_PROTECT_OVER	@ETense_Protect_Over	1
 * -- $ETENSE_TEND_LEFTWARD	@ETense_Tend_Leftward	Protect_Under
 *							&& !Protect_Over
 * -- $ETENSE_PROTECT_FREE	@ETense_Protect_Free	0
 * -- $ETENSE_ZONE_CHECK	@ETense_Zone_Check	ETENSE_CHECK_ON_EXIT/
 *				other possible values:	ETENSE_CHECK_ON_FREE
 *				ETENSE_NO_CHECK		(depending on
 *				ETENSE_CHECK_ALWAYS	 CONFIG_MULTITHREAD)
 *
 * Statistics:
 * -- @ETense_AS_Now
 * -- @ETense_AS_Max
 * Other interfaces:
 * -- void ETense_Check(void)
 *
 * TODO
 * -- new_entry() is
 *    -- thread and signal safe if HAVE_CMPXCHG
 *    -- otherwise thread safe if CONFIG_MULTITHREAD, but not signal safe
 *    -- otherwise more-or-less signal safe
 * -- neither ETense_Zone_Check > ETENSE_CHECK_ON_EXIT nor ETense_Check()
 *    are thread safe (->owner is missing) or signal safe (they mustn't be
 *    interrupted by free()).
 * -- Neither is ETense_AS_Max.
 *
 * Otherwise we're supposed to be OK.
 *
 * TODO ETENSE_CHECK_ON_FREE seems to be unimplemented
 * TODO Use the system's malloc() as backend for memory allocation,
 *      because it's probably way faster than our dummy linked list.
 */

/* Configuration {{{ */
/* For MREMAP_MAYMOVE */
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYSDEPS_H
# include "sysdeps.h"
#endif

/* Set up the defaults. */
#ifndef CONFIG_MULTITHREAD
# define CONFIG_MULTITHREAD	0
#endif

#ifndef CONFIG_ETENSE_GLOBALS
# define CONFIG_ETENSE_GLOBALS	1
#endif

#ifndef HAVE_SYS_USER_H
# define HAVE_SYS_USER_H	0
#endif

/* HAVE_CMPXCHG (__sync_bool_compare_and_swap) if gcc >= 4.1 */
#ifndef HAVE_CMPXCHG
# define HAVE_CMPXCHG		GCC_AT_LEAST(4, 1)
#endif

#ifndef HAVE_PTHREAD_SPINLOCK
# define HAVE_PTHREAD_SPINLOCK	(!HAVE_CMPXCHG)
#endif

#if CONFIG_MULTITHREAD && !HAVE_CMPXCHG && !HAVE_PTHREAD_SPINLOCK
# error "CONFIG_MULTITHREAD needs either cmpxchg or pthread_spinlock."
#endif
/* }}} */

/* Include files {{{ */
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#if CONFIG_MULTITHREAD && !HAVE_CMPXCHG
# include <pthread.h>
#endif

#include <string.h>
#include <signal.h>

#include <sys/mman.h>

/* For PAGE_SIZE */
#if HAVE_SYS_USER_H
# include <sys/user.h>
#endif

#include "etense.h"
#include "adios.h"
/* }}} */

/* Macros {{{ */
#define TE_TAKEN		(1 << 0)
#define TE_COMPLETE		(1 << 1)
#define TE_LEFTWARD		(1 << 2)
#define TE_UNDER		(1 << 3)
#define TE_OVER			(1 << 4)
#define TE_ZONED		(1 << 5)

#define ZONE_SEED		257
#define ZONE_OF(te, i) \
	(((ptr_t)(te)->paddr % (i)) & 0xFF)

#if CONFIG_ETENSE_GLOBALS
# define ETENSE_GLOBAL		/* */
#else
# define ETENSE_GLOBAL		static
#endif
/* }}} */

/* Type definitions {{{ */
/* An integer that can store an address (a pointer).
 * XXX It is certainly not certain that unsigned long is wide enough.
 *     I've heard stories about 128-bit wide pointers. */
typedef unsigned long ptr_t;
STATIC_ASSERT(sizeof(ptr_t) >= sizeof(void *));

struct regentry_st
{
	volatile sig_atomic_t lock;
	volatile sig_atomic_t flags;

	unsigned char *paddr, *uaddr;
	size_t psize, usize;
	unsigned alignment;
};

struct registry_st
{
#if CONFIG_MULTITHREAD && !HAVE_CMPXCHG
	pthread_spinlock_t lock;
#endif

	struct registry_st *volatile next;
	volatile sig_atomic_t free_entries;
	struct regentry_st entries[1];
};

enum caller_t
{
	M_MALLOC,
	M_CALLOC,
	M_REALLOC,
};
/* }}} */

/* Function prototypes {{{ */
/* Birth and death */
static void __attribute__((noreturn))
	panic(char const *msg);
static void printopt(int fd, char const *str, int val);
static void __attribute__((constructor))
	init(void);
static void __attribute__((destructor))
	done(void);

/* Page allocation */
static size_t round_to_pagesize(size_t size);
static void *get_pages(size_t size, unsigned prot)
	__attribute__((malloc));
static void free_pages(void *paddr, size_t psize);
static int protect(struct regentry_st const *te, int isall);
static int unprotect(struct regentry_st const *te);
static void *realloc_pages(struct regentry_st *te, size_t size);

/* Registration */
static struct registry_st *new_alist(void);
static void free_alist(struct registry_st *tl)
	__attribute__((unused));
static int new_entry(struct registry_st **tlp,
	struct regentry_st **tep);
static void get_entry(struct registry_st **tlp,
	struct regentry_st **tep, void const *ptr);

/* Red zone */
static void mkzone(struct regentry_st *te);
static void chkzone(struct regentry_st const *te);

/* Memory allocation -- dispatchers */
static unsigned get_flags(struct regentry_st const *te);
static void *do_malloc(enum caller_t caller, size_t alignment, size_t size);
static void *do_realloc(struct regentry_st *te, size_t size);

/* Memory allocation -- hard workers */
static void *align(ptr_t what, unsigned alignment,
	int can_left, int can_right);
static void *do_malloc_null(struct registry_st *tl, struct regentry_st *te,
	unsigned alignment);
static void *do_malloc_real(struct registry_st *tl, struct regentry_st *te,
	enum caller_t caller, unsigned flags, unsigned alignment,
	size_t usize);
static void do_free(struct registry_st *tl, struct regentry_st *te);
/* }}} */

/* Variable definitions {{{ */
/* Private variables */
static size_t Pagesize;
static unsigned Entries_per_page;
static struct registry_st *Tense_alist;

/* Global variables */
/* Be conservative with the default alignment. */
ETENSE_GLOBAL unsigned ETense_Alignment = sizeof(int);
ETENSE_GLOBAL int ETense_Tend_Leftward	= -1;
ETENSE_GLOBAL int ETense_Protect_Under	= -1;
ETENSE_GLOBAL int ETense_Protect_Over	= -1;
ETENSE_GLOBAL int ETense_Protect_Free	=  0;
#if !CONFIG_MULTITHREAD
ETENSE_GLOBAL unsigned ETense_Zone_Check = ETENSE_CHECK_ON_EXIT;
#else
ETENSE_GLOBAL unsigned ETense_Zone_Check = ETENSE_CHECK_ON_FREE;
#endif

size_t ETense_AS_Now, ETense_AS_Max;
/* }}} */

/* Program code */
/* Interface functions */
/* Overridden functions {{{ */
void *malloc(size_t size)
{
	return do_malloc(M_MALLOC, ETense_Alignment, size);
} /* malloc */

void *memalign(size_t alignment, size_t size)
{
	return do_malloc(M_MALLOC, alignment, size);
} /* memalign */

void *valloc(size_t size)
{
	return do_malloc(M_MALLOC, Pagesize, size);
} /* valloc */

void *pvalloc(size_t size)
{
	return do_malloc(M_MALLOC, Pagesize, round_to_pagesize(size));
} /* pvalloc */

void *calloc(size_t n, size_t msize)
{
	/* TODO What about integer overflows? */
	return do_malloc(M_CALLOC, ETense_Alignment, msize * n);
} /* calloc */

void *realloc(void *ptr, size_t size)
{
	struct registry_st *tl;
	struct regentry_st *te;

	/*
	 * malloc(3) says:
	 * -- realloc(NULL,  0) == malloc( 0)
	 * -- realloc(NULL, !0) == malloc(!0)
	 * -- realloc(not-NULL, 0) == free(not-NULL)
	 * -- realloc()ing anything to the same size is nop
	 * -- malloc(0) returns not-NULL
	 */
	if (!ptr)
		return do_malloc(M_MALLOC, ETense_Alignment, size);

	get_entry(&tl, &te, ptr);
	if (size == 0)
	{
		do_free(tl, te);
		return NULL;
	} else if (size == te->usize)
		return te->uaddr;
	else
		return do_realloc(te, size);
} /* realloc */

void free(void *ptr)
{
	struct registry_st *tl;
	struct regentry_st *te;

	if (!ptr)
		return;
	get_entry(&tl, &te, ptr);
	do_free(tl, te);
} /* free */
/* }}} */

/* Extended debugging support {{{ */
void ETense_Check(void)
{
	unsigned i;
	struct registry_st *tl;

	for (tl = Tense_alist; tl; tl = tl->next)
		for (i = 0; i < Entries_per_page; i++)
			if (tl->entries[i].flags & TE_COMPLETE)
				chkzone(&tl->entries[i]);
} /* ETense_Check */
/* }}} */

/* Private functions */
/* Birth and death {{{ */
void panic(char const *msg)
{
	/* Be very minimalistic wrt libc-usage. */
	write(STDERR_FILENO, STR_LEN("etense: "));
	write(STDERR_FILENO, msg, strlen(msg));
	write(STDERR_FILENO, STR_LEN("\n"));

	/* Block until the signal arrives. */
	raise(SIGABRT);
	for (;;)
		pause();
} /* panic */

void printopt(int fd, char const *str, int val)
{
	write(fd, str, strlen(str));
	if (val)
		write(fd, STR_LEN("on"));
	else
		write(fd, STR_LEN("off"));
} /* printopt */

void init(void)
{
	static int inited;
	int n;
	char const *s;

	if (!inited)
		inited = -1;
	else if (inited > 0)
		return;
	else
	{	/* Don't call init() again. */
		inited = 1;
		panic("init() interrupted");
	}

	/* Get Pagesize. */
#if defined(PAGE_SIZE)
	Pagesize = PAGE_SIZE;
#elif HAVE_GETPAGESIZE
	Pagesize = getpagesize();
#elif defined(_SC_PAGE_SIZE)
	Pagesize = sysconf(_SC_PAGE_SIZE);
#elif defined(_SC_PAGESIZE)
	Pagesize = sysconf(_SC_PAGESIZE);
#else
	Pagesize = 4096;
#endif

	/* Allocate Tense_alist. */
	Entries_per_page = (Pagesize-VARST_SIZE(Tense_alist, entries, 0))
		/ sizeof(Tense_alist->entries);
	if (!(Tense_alist = new_alist()))
		panic("init: can't allocate memory for the register");

	/* Import configuration from the environment variables. */
	if ((s = getenv("ETENSE_ALIGNMENT")) != NULL)
		if ((n = atoi(s)) >= 0)
			ETense_Alignment = n;
	if ((s = getenv("ETENSE_TEND_LEFTWARD")) != NULL)
		if ((n = atoi(s)) >= 0)
			ETense_Tend_Leftward = n;
	if ((s = getenv("ETENSE_PROTECT_UNDER")) != NULL)
		if ((n = atoi(s)) >= 0)
			ETense_Protect_Under = n;
	if ((s = getenv("ETENSE_PROTECT_OVER")) != NULL)
		if ((n = atoi(s)) >= 0)
			ETense_Protect_Over = n;
	if ((s = getenv("ETENSE_PROTECT_FREE")) != NULL)
		if ((n = atoi(s)) >= 0)
			ETense_Protect_Free = n;
	if ((s = getenv("ETENSE_ZONE_CHECK")) != NULL)
		if ((n = atoi(s)) >= 0)
			ETense_Zone_Check = n;

	/* Set unspecified variables. */
	if (ETense_Protect_Under < 0)
		ETense_Protect_Under = 1;
	if (ETense_Protect_Over  < 0)
		ETense_Protect_Over  = 1;
	if (ETense_Tend_Leftward < 0)
		ETense_Tend_Leftward = ETense_Protect_Under
			&& !ETense_Protect_Over;

	if ((s = getenv("ETENSE_BANNER")) != NULL && (n = atoi(s)) > 0)
	{	/* Print banner on $n:th file descriptor. */
		write(n, STR_LEN("Electric Tense is active\n"
			"------------------------\n"
			"\n"));
		printopt(n, "protect over: ", ETense_Protect_Over);
		printopt(n, ", protect under: ", ETense_Protect_Under);
		printopt(n, ", tend leftward: ", ETense_Tend_Leftward);
		write(n, STR_LEN("\n"));
		printopt(n, "protect free: ", ETense_Protect_Free);
		write(n, STR_LEN(", zone check: "));
		if (ETense_Zone_Check == ETENSE_NO_CHECK)
			write(n, STR_LEN("none\n\n"));
		else if (ETense_Zone_Check == ETENSE_CHECK_ON_FREE)
			write(n, STR_LEN("on free\n\n"));
		else if (ETense_Zone_Check == ETENSE_CHECK_ON_EXIT)
			write(n, STR_LEN("on exit\n\n"));
		else
			write(n, STR_LEN("always\n\n"));
	}

	inited = 1;
} /* init */

void done(void)
{
	if (ETense_Zone_Check >= ETENSE_CHECK_ON_EXIT)
		ETense_Check();
} /* done */
/* }}} */

/* Page allocation {{{ */
size_t round_to_pagesize(size_t size)
{
	if (size & (Pagesize-1))
	{
		size &= ~(Pagesize - 1);
		size += Pagesize;
	}
	return size;
} /* round_to_pagesize */

void *get_pages(size_t psize, unsigned prot)
{
	void *paddr;

#ifdef MAP_ANONYMOUS
	paddr = mmap(NULL, psize, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#else
	static int hdevzero = -1;

	if (hdevzero < 0 && (hdevnull = open("/dev/zero", O_RDONLY)) < 0)
		panic("get_pages: can't open /dev/zero");
	paddr = mmap(NULL, psize, prot, MAP_PRITVATE, hdevzero, 0);
#endif

	if (paddr == (void *)-1)
		return NULL;

	ETense_AS_Now += psize;
	if (ETense_AS_Max < ETense_AS_Now)
		ETense_AS_Max = ETense_AS_Now;
	return paddr;
} /* get_pages */

void free_pages(void *paddr, size_t psize)
{
	if (munmap(paddr, psize) < 0)
		panic("free_pages: munmap() failed (double free() ?)");
	ETense_AS_Now -= psize;
} /* free_pages */

int protect(struct regentry_st const *te, int isall)
{
	int ok;

	if (isall)
		return mprotect(te->paddr, te->psize, PROT_NONE) == 0;

	ok = 1;
	if (te->flags & TE_UNDER)
		ok  = mprotect(te->paddr, Pagesize, PROT_NONE) == 0;
	if (te->flags & TE_OVER)
		ok &= mprotect(te->paddr+te->psize - Pagesize,
			Pagesize, PROT_NONE) == 0;
	return ok;
} /* protect */

int unprotect(struct regentry_st const *te)
{
	return mprotect(te->paddr, te->psize, PROT_READ | PROT_WRITE) == 0;
} /* unprotect */

void *realloc_pages(struct regentry_st *te, size_t psize)
{
#ifdef MREMAP_MAYMOVE
	void *paddr;

	/* This is supposed to work even if `te' was allocated
	 * by do_malloc_null(). */

	/* It isn't documented what happens to protection during mpremap()
	 * but it may be safe to remove all, then reinstall them. */
	if (!unprotect(te))
		return NULL;

	/* Make sure the contents of the user area remain accessible
	 * after mremap(). */
	memmove(te->paddr, te->uaddr, te->usize);

	/* After that we must not fail. */
	paddr = mremap(te->paddr, te->psize, psize, MREMAP_MAYMOVE);
	if (paddr == (void *)-1)
	{
		/* Oops.  Rollback. */
		memmove(te->uaddr, te->paddr, te->usize);
		protect(te, te->usize == 0);
		mkzone(te);
		return NULL;
	}

	return paddr;
#else /* ! MREMAP_MAYMOVE */
	return NULL;
#endif
} /* realloc_pages */
/* }}} */

/* Registration {{{ */
struct registry_st *new_alist(void)
{
	struct registry_st *tl;

	if (!(tl = get_pages(Pagesize, PROT_READ | PROT_WRITE)))
		return NULL;

	memset(tl, 0, Pagesize);
#if CONFIG_MULTITHREAD && !HAVE_CMPXCHG
	pthread_spin_init(&tl->lock, 0);
#endif
	tl->free_entries = Entries_per_page;

	return tl;
} /* new_alist */

void free_alist(struct registry_st *tl)
{
#if CONFIG_MULTITHREAD && !HAVE_CMPXCHG
	pthread_spin_destroy(&tl->lock, 0);
#endif
	free_pages(tl, Pagesize);
} /* free_alist */

/* This is our only concurrency/reentrancy-sensitive routine. */
int new_entry(struct registry_st **tlp, struct regentry_st **tep)
{
	unsigned i;
	struct registry_st *tl;
	struct regentry_st *te;

	if (ETense_Zone_Check >= ETENSE_CHECK_ALWAYS)
		ETense_Check();

	// Is somebody trying to allocate memory before our init() has run? */
	if (!Tense_alist)
		init();

	for (tl = Tense_alist; ; tl = tl->next)
	{
		struct registry_st *nl __attribute((unused));

		/* Scan `tl' for a free `te'. */
		for (i = Entries_per_page, te = tl->entries; i > 0; i--, te++)
		{
			/* Seen every entries? */
			if (!tl->free_entries)
				break;

			/* Take it unless it's already owned. */
			/* We need locks even if singlethreaded
			 * to improve our signal safety somewhat. */
			te->lock++;
			if (te->lock != 1 || te->flags)
			{
				te->lock--;
				continue;
			}
			te->flags |= TE_TAKEN;
			te->lock--;
			tl->free_entries--;

			*tlp = tl;
			*tep = te;
			return 1;
		} /* for */

		/* Goto the next `tl'. */
#if HAVE_CMPXCHG
		/* Thread safe and reentrant. */
		if (tl->next)
			continue;
		if (!(nl = new_alist()))
			return 0;
		/* tl->next <- nl if !tl->next; otherwise free(nl). */
		if (!__sync_bool_compare_and_swap(&tl->next, NULL, nl))
			free_alist(nl);
#elif CONFIG_MULTITHREAD /* && !HAVE_CMPXCHG && HAVE_PTHREAD_SPINLOCK */
		/* XXX I don't think pthread_spin_lock() is reentrant. */
		if (tl->next)
			continue;
		pthread_spin_lock(&tl->lock);
		if (!tl->next)
			tl->next = new_alist();
		pthread_spin_unlock(&tl->lock);
		if (!tl->next)
			return 0;
#else /* !CONFIG_MULTITHREAD && !HAVE_CMPXCHG */
		/* XXX Not reentrant. */
		if (!tl->next && !(tl->next = new_alist()))
			return 0;
#endif
	} /* for */
} /* new_entry */

void get_entry(struct registry_st **tlp, struct regentry_st **tep,
	void const *ptr)
{
	unsigned i;
	struct registry_st *tl;
	struct regentry_st *te;

	if (ETense_Zone_Check >= ETENSE_CHECK_ALWAYS)
		ETense_Check();

	if (ptr == NULL)
		panic("get_entry: searching for zero address "
			"(attempt to free(NULL)?)");

	for (tl = Tense_alist; tl; tl = tl->next)
	{
		for (i = Entries_per_page, te = tl->entries; i > 0;
			i--, te++)
		{
			if (!(te->flags & TE_COMPLETE) || te->uaddr != ptr)
				continue;

			if (ETense_Zone_Check)
				chkzone(te);

			*tep = te;
			*tlp = tl;
			return;
		} /* for */
	} /* for */

	panic("get_entry: address not found "
		"(attempt to free(<invalid-address>) ?)");
} /* get_entry */
/* }}} */

/* Red zone {{{ */
void mkzone(struct regentry_st *te)
{
	unsigned i;
	unsigned char *ptr, *end;

	if (!(te->flags & TE_ZONED))
		return;

	/* Before user area */
	ptr = te->paddr;
	if (te->flags & TE_UNDER)
		ptr += Pagesize;
	for (i = ZONE_SEED; ptr < (unsigned char *)te->uaddr; ptr++, i++)
		*ptr = ZONE_OF(te, i);

	/* Past user ares */
	end = te->paddr + te->psize;
	if (te->flags & TE_OVER)
		end -= Pagesize;
	for (ptr = te->uaddr + te->usize; ptr < end; ptr++, i++)
		*ptr = ZONE_OF(te, i);

	te->flags |= TE_ZONED;
} /* mkzone */

void chkzone(struct regentry_st const *te)
{
	unsigned i;
	unsigned char const *ptr, *end;

	if (!(te->flags & TE_ZONED))
		return;

	/* In front of user area */
	ptr = te->paddr;
	if (te->flags & TE_UNDER)
		ptr += Pagesize;
	for (i = ZONE_SEED; ptr < (unsigned char *)te->uaddr; ptr++, i++)
		if (*ptr != ZONE_OF(te, i))
			panic("chkzone: red zone integrity violated "
				"(buffer underrun?)");

	/* Past user area */
	end = te->paddr + te->psize;
	if (te->flags & TE_OVER)
		end -= Pagesize;
	for (ptr = te->uaddr + te->usize; ptr < end; ptr++, i++)
		if (*ptr != ZONE_OF(te, i))
			panic("chkzone: red zone integrity violated "
				"(buffer overrun?)");
} /* chkzone */
/* }}} */

/* Memory allocation -- dispatchers {{{ */
unsigned get_flags(struct regentry_st const *te)
{
	if (!te || te->usize == 0)
	{
		unsigned flags;

		flags = 0;
		if (ETense_Tend_Leftward)
			flags |= TE_LEFTWARD;
		if (ETense_Protect_Under)
			flags |= TE_UNDER;
		if (ETense_Protect_Over)
			flags |= TE_OVER;
		if (ETense_Zone_Check)
			flags |= TE_ZONED;
		return flags;
	} else
		return te->flags & (TE_LEFTWARD|TE_UNDER|TE_OVER|TE_ZONED);
} /* get_flags */

void *do_malloc(enum caller_t caller, size_t alignment, size_t size)
{
	struct registry_st *tl;
	struct regentry_st *te;

	if (!new_entry(&tl, &te))
		return NULL;
	else if (size > 0)
		return do_malloc_real(tl, te, caller,
			get_flags(NULL), alignment, size);
	else
		return do_malloc_null(tl, te, alignment);
} /* do_malloc */

void *do_realloc(struct regentry_st *te, size_t size)
{
	struct regentry_st nt;

#ifdef MREMAP_MAYMOVE
	void *ptr;

	/* Use mremap(). */
	if ((ptr = do_malloc_real(NULL, te, M_REALLOC,
			get_flags(te), te->alignment, size)) != NULL)
		return ptr;
#endif /* MREMAP_MAYMOVE */

	/* mmap() another region and copy over te->uaddr.  For some
	 * reason this may work even if mremap() fails. */
	nt.flags = get_flags(te);
	if (!do_malloc_real(NULL, &nt, M_MALLOC,
			nt.flags, te->alignment, size))
		return NULL;

	te->flags &= ~TE_COMPLETE;
	memcpy(nt.uaddr, te->uaddr, MIN(nt.usize, te->usize));
	free_pages(te->paddr, te->psize);

	te->paddr = nt.paddr;
	te->psize = nt.psize;
	te->uaddr = nt.uaddr;
	te->usize = nt.usize;
	te->flags |= nt.flags;

	return te->uaddr;
} /* do_realloc */
/* }}} */

/* Memory alllocation -- hard workers {{{ */
void *align(ptr_t what, unsigned alignment, int can_left, int can_right)
{
	unsigned reml, remr;

	if (alignment == 0)
		return (void *)what;

	reml = what % alignment;
	if (reml == 0)
		return (void *)what;
	remr = alignment - reml;
		
	if (can_left && (!can_right || reml < remr))
	{
		what -= reml;
	} else
	{
		what += remr;
	}

	return (void *)what;
} /* align */

void *do_malloc_null(struct registry_st *tl, struct regentry_st *te,
	unsigned alignment)
{
	/* Allocate exactly one page to minimize waste. */
	if (!(te->paddr = get_pages(Pagesize, PROT_NONE)))
	{
		te->flags = 0;
		tl->free_entries++;
		return NULL;
	}
	te->psize = Pagesize;

	/* TODO We don't support alignment > Pagesize. */
	te->alignment = alignment;
	te->uaddr = align((ptr_t)(te->paddr + Pagesize/2), alignment, 1, 1);
	te->usize = 0;

	/* TODO ETense_* flags are ignored. */
	te->flags |= TE_COMPLETE;
	return te->uaddr;
} /* do_malloc_null */

void *do_malloc_real(struct registry_st *tl, struct regentry_st *te,
	enum caller_t caller, unsigned flags, unsigned alignment,
	size_t usize)
{
	int dont_reprotect;
	size_t psize, old_usize;
	unsigned pzleft, pzright, more;
	unsigned char *paddr, *old_uaddr;

	old_usize = 0;
	old_uaddr = NULL;
	dont_reprotect = 0;

	/* Where are the protected zones? */
	pzleft  = (flags & TE_UNDER) ? Pagesize : 0;
	pzright = (flags & TE_OVER)  ? Pagesize : 0;

	/* Calculate psize. (We expect usize > 0.) */
	more = alignment > 1 && Pagesize % alignment
		? alignment - 1 : 0;
	psize = pzleft + round_to_pagesize(usize + more) + pzright;

	/* Page allocation */
	if (caller == M_REALLOC)
	{
		/* Don't let other functions consider `te'
		 * while we're working on it. */
		te->flags &= ~TE_COMPLETE;
		old_usize = te->usize;

		if (psize != te->psize)
		{
			if (!(paddr = realloc_pages(te, psize)))
				goto out_realloc;

			/* realloc_pages() moved it there. */
			old_uaddr = paddr;
		} else
		{
			/* No need change the size of the mmap()ed region.
			 * OTOH we need to unprotect() if we're reallocing
			 * a zero-size block because the the entire mmap
			 * is protected this case. */
			if (old_usize == 0 && !unprotect(te))
				goto out_realloc;

			/* We won't need to protect in any case, either
			 * because the appropriate protection is already
			 * established, or we're resizing a zero size block
			 * (psize == Pagesize protected --> psize == Pagesize
			 * unprotected). */
			dont_reprotect = 1;
			paddr = te->paddr;
			old_uaddr = te->uaddr;
		} /* if */
	} else
	{
		if (!(paddr = get_pages(psize, PROT_READ | PROT_WRITE)))
			goto out_alloc;
	}

	/* Calculate the start of the user area. */
	te->alignment = alignment;
	te->uaddr = (flags & TE_LEFTWARD)
		? align((ptr_t)(paddr       + pzleft),
			alignment, 0, 1)
		: align((ptr_t)(paddr+psize - pzright - usize),
			alignment, 1, 0);
	te->usize = usize;

	/* Preserve content if realloc()ing.  Do it before we release
	 * pages in the next step as old_uaddr might be there. */
	if (caller == M_REALLOC)
		memmove(te->uaddr, old_uaddr, MIN(usize, old_usize));

	/* Release excessive pages. */
	if (more > 0)
	{
		unsigned lpad, rpad, excess;

		/* On the left */
		lpad = te->uaddr - (paddr + pzleft);
		if (lpad > Pagesize)
		{
			excess = (lpad/Pagesize) * Pagesize;

			free_pages(paddr, excess);
			paddr += excess;
			psize -= excess;
			lpad  -= excess;

			dont_reprotect = 0;
		}

		/* On the right */
		rpad = (psize - pzleft - pzright) - (lpad + usize);
		if (rpad > Pagesize)
		{
			excess = (rpad/Pagesize) * Pagesize;

			free_pages(paddr+psize - excess, excess);
			psize -= excess;

			dont_reprotect = 0;
		}
	} /* if */

	/* te->paddr is finalized. */
	te->flags |= flags;
	te->paddr  = paddr;
	te->psize  = psize;

	/* Activate the fence. */
	/* In case of realloc, the memory is already realloced,
	 * so we must not fail because we cannot roll back. */
	if (!dont_reprotect && !protect(te, 0) && caller != M_REALLOC)
		goto out_free;
	mkzone(te);

	/* Prepare thr user area. */
	if (caller == M_CALLOC)
		/* Clear */
		memset(te->uaddr, 0, te->usize);
	else if (usize > old_usize)
	{ /* realloc(enlarge) or plain malloc() */
		unsigned i, o;

		/* Fill with junk.  ZONE_OF() depends on te->paddr. */
		for (i = old_usize, o = ZONE_SEED; i < usize; i++, o++)
			te->uaddr[i] = ZONE_OF(te, o);
	}

	/* Done */
	te->flags |= TE_COMPLETE;
	return te->uaddr;

out_free:
	free_pages(paddr, psize);
out_alloc:
	te->flags = 0;
	if (tl != NULL)
		tl->free_entries++;
	return NULL;

out_realloc:
	/* Pretend nothing has happened. */
	te->flags |= TE_COMPLETE;
	return NULL;
} /* do_malloc_real */

void do_free(struct registry_st *tl, struct regentry_st *te)
{
	/*
	 * Clear TE_COMPLETE so get_entry() won't return it again.
	 * Leave TE_TAKEN so new_entry() won't take it until we're done.
	 */
	te->flags &= ~TE_COMPLETE;

	/* Release the pages.  ElectricFence fills the user area
	 * with junk before release but I don't see the win.
	 * (We do it in malloc() time.) */
	if (!ETense_Protect_Free || !protect(te, 1))
		free_pages(te->paddr, te->psize);

	if (tl != NULL)
		tl->free_entries++;
	te->flags = 0;
} /* do_free */
/* }}} */

/* vim: set foldmethod=marker: */
/* End of etense.c */
