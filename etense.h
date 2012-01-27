#ifndef ETENSE_H
#define ETENSE_H

/* Include files */
#include <stddef.h>

/* Standard definitions */
#define ETENSE_NO_CHECK			0
#define ETENSE_CHECK_ON_FREE		1
#define ETENSE_CHECK_ON_EXIT		2
#define ETENSE_CHECK_ALWAYS		3

/* Global variables */
/* These variables are unreachable if the library was compiled
 * with -DCONFIG_ETENSE_GLOBALS=0. */
extern unsigned ETense_Alignment;
extern int ETense_Tend_Leftward;
extern int ETense_Protect_Under;
extern int ETense_Protect_Over;
extern int ETense_Protect_Free;
extern unsigned ETense_Zone_Check;

/* Statistics */
extern size_t ETense_AS_Now;
extern size_t ETense_AS_Max;

/* Function prototypes */
extern void ETense_Check(void);

#endif /* ! ETENSE_H */
