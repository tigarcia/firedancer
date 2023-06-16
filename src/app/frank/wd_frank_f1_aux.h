#ifndef HEADER_fd_src_wiredancer_wd_f1_aux_h
#define HEADER_fd_src_wiredancer_wd_f1_aux_h

#include "../../util/fd_util_base.h"
#include <stdint.h>
#include <time.h>

/* TSC simple "calibration" method */

static inline double get_tsc_ticks_ns()
{
  struct timespec ts_start, ts_end;
  volatile long rdtsc_start = 0LL;
  volatile long rdtsc_end   = 0LL;
  volatile long i = 0;

  clock_gettime(CLOCK_MONOTONIC, &ts_start);
  rdtsc_start = fd_tickcount();
  /* Compute intensive - arbitrary count */
  for (i = 0; i < 100000000LL; i++);
  rdtsc_end = fd_tickcount();
  clock_gettime(CLOCK_MONOTONIC, &ts_end);

  static struct timespec ts_diff;
  do { /* compute the differences */
    ts_diff.tv_sec  = ts_end.tv_sec  - ts_start.tv_sec ;
    ts_diff.tv_nsec = ts_end.tv_nsec - ts_start.tv_nsec;
    if (ts_diff.tv_nsec < 0) { ts_diff.tv_sec--; ts_diff.tv_nsec += 1000000000LL; /* ns per second */}
  } while(0);
  uint64_t ns = (uint64_t)(ts_diff.tv_sec * 1000000000LL + ts_diff.tv_nsec);
  return (double)(rdtsc_end - rdtsc_start)/(double)ns;
}

#endif
