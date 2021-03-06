/*
 * test.c -- fuzzy test for libetense
 *
 * Synopsis:
 *   test [-1] [-S <seed>] [-n <nrounds>] [-m [<nmems>] [-s <???>]
 *
 * Options:
 *   -1			Just allocate a single memory region, and then
 *			reallocate it many times subsequently.  Otherwise
 *			allocate up to <nmems> memory regions and do the
 *			same to them.
 *   -S <seed>		Specify the seed of the PRNG used for fuzzying.
 *			If left unspecified, it will be initialized from
 *			the current time.  The seed is printed at every
 *			invocation of the program, thus you can use this
 *			option to reproduce an earlier test sequence.
 *   -n <nrounds>	If not -1, specifies the number of times each
 *			memory region is tested.
 *   -m <nmems>		Tells the maximum number of memory allocations
 *			to test in ! -1 mode.
 *   -s <???>		XXX No idea.
 *
 * The tests performed on a memory region are:
 * -- allocating it with varying alignments
 * -- reallocating it randomly
 * -- trying to (re)allocate insanely large amounts of memory
 * -- testing whether the fences work by over/underflowing the memory region
 * -- freeing it
 *
 * TODO What is @isfake used for?
 * TODO Multithreading is completely untested.
 * TODO documentation
 */

/* Include files */
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <limits.h>
#include <alloca.h>
#include <assert.h>
#include <stdarg.h>

#include <malloc.h>
#include <string.h>
#include <math.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <dlfcn.h>

#include <sys/wait.h>
#if HAVE_SYS_USER_H
# include <sys/user.h>		/* for PAGE_SIZE */
#endif

#include "adios.h"
#include "etense.h"

/* Standard definitions */
/* Of course! */
#define CONFIG_ETENSE		1

/* Integraral [-T99; +T99] gauss(x)dx = 0.99.  Used by grand(). */
#define T99			2.58

/* Allocate MEAN +/- RANGE bytes of memory. */
#define	MEAN			10000
#define RANGE			MEAN

/* The amount of memory you shouldn't be able to malloc. */
#ifdef __LP64__
# define TOOMUCH		(1L * 1024*1024*1024 * 64)
#else
# define TOOMUCH		(1L * 1024*1024*1024 *  2)
#endif

#ifndef PAGE_SIZE
# define PAGE_SIZE		4096 /* Just a wild guess. */
#endif

/* Type definitions */
struct memory_st
{
	u_int8_t *addr;
	size_t size;
	unsigned align;
	int left, right;
	unsigned key, mod;
};

/* Private variables */
static unsigned Pagesize, Round, Slot;

#ifdef CONFIG_ETENSE_PRELOAD
static int *My_ETense_Tend_Leftward;
static int *My_ETense_Protect_Under;
static int *My_ETense_Protect_Over;
static unsigned *My_ETense_Zone_Check;
static void (*My_ETense_Check)(void);

# define ETense_Tend_Leftward	(*My_ETense_Tend_Leftward)
# define ETense_Protect_Under	(*My_ETense_Protect_Under)
# define ETense_Protect_Over	(*My_ETense_Protect_Over)
# define ETense_Zone_Check	(*My_ETense_Zone_Check)
# define ETense_Check		My_ETense_Check
#endif /* CONFIG_ETENSE_PRELOAD */

/* Program code */
/* Return a random float from a Gaussian distribution
 * from the range [-l, m, +l] where m is the peak.
 * (Stolen from Adios::Random.pm) */
static double grand(double m, double l)
{
	double r, x1, x2;

	/* Get a standard Gaussian PRN. */
	do
	{
		x1 = 2*drand48() - 1;
		x2 = 2*drand48() - 1;
		r = x1*x1 + x2*x2;
	} while (r >= 1);
	r = x1 * sqrt(-2*log(r) / r);

	/* Scale it. */
	if (l == 0)
		l = abs(m);
	if (r <= -T99)
		return m-l;
	else if (r >= T99)
		return m+l;
	else
		return m + r*l/T99;
} /* grand */

static int is_aligned(void const *addr, unsigned alignment)
{
	return alignment <= 1 || (unsigned long)addr % alignment == 0;
}

/* Is all the user content intact? */
static void test_user(struct memory_st *mem, size_t setfrom)
{
	unsigned i;

	for (i = 0; i < mem->size && i < setfrom; i++)
		assert(mem->addr[i] == (mem->key % (mem->mod + i)) % 256);
	for (; i < mem->size; i++)
		mem->addr[i] = (mem->key % (mem->mod + i)) % 256;
} /* test_user */

static void logit(int isfake, char const *op, char const *fmt, ...)
{
	char str[96];
	va_list printf_args;

	if (isfake)
		return;

	snprintf(str, sizeof(str), "%u %u %s", Round, Slot, op);
	write(STDOUT_FILENO, str, strlen(str));
	if (fmt)
	{
		write(STDOUT_FILENO, "\t", 1);
		va_start(printf_args, fmt);
		vsnprintf(str, sizeof(str), fmt, printf_args);
		write(STDOUT_FILENO, str, strlen(str));
		va_end(printf_args);
	}
	write(STDOUT_FILENO, STR_LEN("\n"));
} /* logit */

/* Does the fence work? */
static void negtest_user(struct memory_st *mem, int isfake)
{
#if CONFIG_ETENSE
	pid_t pid;
	int can_under, can_over;

	if (isfake)
		return;

	/* Don't expect an under/overwlow detected
	 * if `mem' is not protected against it. */
	can_under = mem->left  || !is_aligned(mem->addr, PAGE_SIZE);
	can_over  = mem->right || !is_aligned(mem->addr + mem->size,
					PAGE_SIZE);
	if (!can_under && !can_over)
	{
		logit(0, "NEGTEST", NULL);
		return;
	}

	if (!(pid = fork()))
	{
		int i;

		/* Simulate a buffer overrun or underrun. */
		if (can_over && (!can_under || rand() % 2))
		{
			logit(0, "NEGTEST OVER", NULL);
			mem->addr[mem->size]++;
			for (i = 0; i < 2000; i++)
				mem->addr[mem->size + i]++;
		} else
		{
			logit(0, "NEGTEST UNDER", NULL);
			for (i = -1; i > -2000; i--)
				mem->addr[i]++;
		}

		/* Even if the MM was unable to catch us the damage
		 * made to the red zone ought to not remain unnoticed. */
		ETense_Check();

		/* By now we should be dead. */
		logit(0, "FUCKUP", NULL);
		abort();
	} else
	{
		int status;

		if (waitpid(pid, &status, 0) != pid)
		{
			logit(0, "NOWAIT", NULL);
			abort();
		} else if (!WIFSIGNALED(status))
		{
			logit(0, "NOSIGNAL", NULL);
			abort();
		} else if (WTERMSIG(status) == SIGSEGV)
		{
			logit(0, "SIGSEGV", NULL);
		} else if (WTERMSIG(status) != SIGABRT)
		{
			logit(0, "BADSIGNAL", NULL);
			abort();
		}
	}
#endif /* CONFIG_ETENSE */
} /* negtest_user */

/* Probe with random and very strange alignments. */
static void test_alloc(struct memory_st *mem, size_t size, int isfake)
{
	mem->size = size;
#if CONFIG_ETENSE
	mem->align = rand() % 10
		? grand(MEAN / 2, 0)
		: 1 << (rand() % 17);
	if (size > 0)
	{
		mem->left  = ETense_Protect_Under = rand() % 2;
		mem->right = ETense_Protect_Over  = rand() % 2;
		ETense_Tend_Leftward = rand() % 2;
	} else
	{
		/* malloc(0) doesn't support alignment > PAGE_SIZE
		 * and ignores ETense_Protect altogether. */
		mem->align %= PAGE_SIZE;
		mem->left = mem->right = 0;
	}
#else
	mem->align = 1 << (rand() % 13);
	mem->left = mem->right = 0;
#endif

	logit(isfake, "ALLOC", "s:%u a:%u l:%d r:%d t:%d",
		mem->size, mem->align,
		mem->left, mem->right,
		ETense_Tend_Leftward);

	if (!isfake)
	{
		mem->addr = memalign(mem->align, mem->size);
		assert(mem->addr != NULL);
		assert(is_aligned(mem->addr, mem->align));
	} else
		mem->addr = (void *)~0;

	/* Set up the red zone inside. */
	mem->key = rand();
	mem->mod = 1+rand();
	if (!isfake)
		test_user(mem, 0);

	negtest_user(mem, isfake);
} /* test_alloc */

/* Can etense free()? */
static void test_free(struct memory_st *mem, int isfake)
{
	logit(isfake, "FREE", NULL);
	if (!isfake)
		free(mem->addr);
	mem->addr = NULL;
} /* test_free */

/* Does realloc() work? */
static void test_realloc(struct memory_st *mem, size_t newsize, int isfake)
{
	size_t oldsize;

	oldsize = mem->size;
	mem->size = newsize;

	if (isfake)
	{
		if (!newsize)
			/* Would free(). */
			mem->addr = NULL;
		return;
	}

	logit(isfake, "REALLOC", "%p: %u -> %u",
		mem->addr, oldsize, newsize);
	mem->addr = realloc(mem->addr, newsize);
	if (newsize)
	{
		if (mem->addr == NULL)
			abort();
		assert(mem->addr != NULL);
		assert(is_aligned(mem->addr, mem->align));

		test_user(mem, oldsize);
		if (oldsize == 0)
		{
			mem->left  = ETense_Protect_Under;
			mem->right = ETense_Protect_Over;
		}
		negtest_user(mem, isfake);
	} else /* Managed to free(). */
		assert(mem->addr == NULL);
} /* test_realloc */

/* What happens to `mem' if realloc() fails? */
static void negtest_realloc(struct memory_st *mem, int isfake)
{
	logit(isfake, "RIDICULOUS REALLOC", NULL);
	if (isfake)
		return;

	assert(realloc(mem->addr, TOOMUCH) == NULL);
	test_user(mem, mem->size);
	negtest_user(mem, isfake);
} /* negtest_realloc */

static void test_many(unsigned nrounds, unsigned nmems, int skipbut)
{
	struct memory_st *memory;

	/* Avoid malloc(), our subject of tests. */
	memory = alloca(sizeof(*memory) * nmems);
	memset(memory, 0, sizeof(*memory) * nmems);

	for (Round = 0; Round < nrounds; Round++)
	{
		logit(0, "ROUND", NULL);
		for (Slot = 0; Slot < nmems; Slot++)
		{
			int isfake;
			struct memory_st *mem;

			isfake = skipbut >= 0 ? Slot != skipbut : 0;
			mem = &memory[Slot];

			/* The only thing we can do about an unallocated
			 * piece is allocating it. */
			if (!mem->addr)
			{
				test_alloc(mem, grand(MEAN, RANGE), isfake);
				continue;
			}

			/* `mem' is already allocated. */
			if (!isfake)
				test_user(mem, mem->size);

			switch (rand() % 4)
			{
			case 0:
				test_free(mem, isfake);
				break;
			case 1:
				test_realloc(mem, grand(MEAN, RANGE), isfake);
				break;
			case 2:
				// negtest_realloc(mem, isfake);
				break;
			case 3:
				negtest_user(mem, isfake);
			} /* switch */
		} /* for */
	} /* for */
	logit(0, "DONE!", NULL);
} /* test_many */

static void test_one(unsigned nrounds)
{
	struct memory_st mem;

	memset(&mem, 0, sizeof(mem));
	for (;;)
	{
		if (!mem.addr)
		{
			if (Round >= nrounds)
				break;
			Round++;
			Slot = 0;
			test_alloc(&mem, grand(MEAN, RANGE), 0);
		} else
		{
			Slot++;
			negtest_realloc(&mem, 0);
		}
		test_realloc(&mem, grand(mem.size, 0), 0);
	} /* for */
	logit(0, "DONE!", NULL);
}

#ifdef CONFIG_ETENSE_PRELOAD
static void *resolve(char const *name)
{
	void *sym;
	char const *error;

	dlerror();
	sym = dlsym(RTLD_DEFAULT, name);
	if ((error = dlerror()))
	{
		fprintf(stderr, "%s: %s\n", name, error);
		exit(1);
	}

	return sym;
} /* resolve */
#endif /* CONFIG_ETENSE_PRELOAD */

/* The main function */
int main(int argc, char *argv[])
{
	long opt_seed;
	unsigned opt_nrounds, opt_nmems;
	int optchar, opt_skipbut, opt_one;

	opt_seed	= time(NULL);
	opt_nrounds	= 10;
	opt_nmems	= 100;
	opt_skipbut	= -1;
	opt_one		= 0;
	while ((optchar = getopt(argc, argv, "S:n:m:s:1")) != EOF)
	{
		switch (optchar)
		{
		case 'S':
			opt_seed = atoi(optarg);
			break;
		case 'n':
			opt_nrounds = atoi(optarg);
			break;
		case 'm':
			opt_nmems = atoi(optarg);
			break;
		case 's':
			opt_skipbut = atoi(optarg);
			break;
		case '1':
			opt_one = 1;
			break;
		default:
			exit(1);
		}
	} /* while */

	printf("seed: %ld\n", opt_seed);
	srand(opt_seed);
	srand48(opt_seed);

#ifdef CONFIG_ETENSE_PRELOAD
	My_ETense_Tend_Leftward	= resolve("ETense_Tend_Leftward");
	My_ETense_Protect_Under	= resolve("ETense_Protect_Under");
	My_ETense_Protect_Over	= resolve("ETense_Protect_Over");
	My_ETense_Zone_Check	= resolve("ETense_Zone_Check");
	My_ETense_Check		= resolve("ETense_Check");
#endif /* CONFIG_ETENSE_PRELOAD */

#if CONFIG_ETENSE
	ETense_Zone_Check = ETENSE_CHECK_ALWAYS;
#endif

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

	/* Run */
	if (opt_one)
		test_one(opt_nrounds);
	else
		test_many(opt_nrounds, opt_nmems, opt_skipbut);

	/* Done */
	return 0;
} /* main */

/* test.c */
