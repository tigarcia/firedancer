#include "tiles.h"

#include "generated/cswitch_seccomp.h"

#include <fcntl.h>

typedef struct {
  long next_report_nanos;

  ulong   tile_cnt;
  int     status_fds[ 128 ];
  ulong * metrics[ 128 ];
} fd_cswitch_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_cswitch_ctx_t ), sizeof( fd_cswitch_ctx_t ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_cswitch_ctx_t ) );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  (void)topo;
  (void)tile;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_cswitch_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_cswitch_ctx_t ), sizeof( fd_cswitch_ctx_t ) );

  ctx->tile_cnt = topo->tile_cnt;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    for(;;) {
      ulong pid = fd_metrics_tile( topo->tiles[ i ].metrics )[ FD_METRICS_GAUGE_TILE_PID_OFF ];
      ulong tid = fd_metrics_tile( topo->tiles[ i ].metrics )[ FD_METRICS_GAUGE_TILE_TID_OFF ];
      if( FD_UNLIKELY( !pid || !tid ) ) {
        FD_SPIN_PAUSE();
        continue;
      }

      char path[ 64 ];
      FD_TEST( fd_cstr_printf_check( path, sizeof( path ), NULL, "/proc/%lu/task/%lu/status", pid, tid ) );
      ctx->status_fds[ i ] = open( path, O_RDONLY );
      ctx->metrics[ i ] = fd_metrics_tile( topo->tiles[ i ].metrics );
      if( FD_UNLIKELY( -1==ctx->status_fds[ i ] ) ) FD_LOG_ERR(( "open failed (%i-%s)", errno, strerror( errno ) ));
      break;
    }
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  (void)topo;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_cswitch_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_cswitch_ctx_t ), sizeof( fd_cswitch_ctx_t ) );

  ctx->next_report_nanos = 0L;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static void
during_housekeeping( void * _ctx ) {
  fd_cswitch_ctx_t * ctx = (fd_cswitch_ctx_t *)_ctx;

  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now>ctx->next_report_nanos ) ) {
    ctx->next_report_nanos = now + 1000L * 1000L * 1000L;
    for( ulong i=0UL; i<ctx->tile_cnt; i++ ) {
      if( FD_UNLIKELY( -1==lseek( ctx->status_fds[ i ], 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));

      char contents[ 4096 ];
      ulong contents_len = 0UL;

      while( 1 ) {
        if( FD_UNLIKELY( contents_len>=sizeof( contents ) ) ) FD_LOG_ERR(( "contents overflow" ));
        long n = read( ctx->status_fds[ i ], contents + contents_len, sizeof( contents ) - contents_len );
        if( FD_UNLIKELY( -1==n ) ) FD_LOG_ERR(( "read failed (%i-%s)", errno, strerror( errno ) ));
        if( FD_UNLIKELY( 0==n ) ) break;
        contents_len += (ulong)n;
      }

      char * line = contents;
      while( 1 ) {
        char * next_line = strchr( line, '\n' );
        if( FD_UNLIKELY( NULL==next_line ) ) break;
        *next_line = '\0';

        char * colon = strchr( line, ':' );
        if( FD_UNLIKELY( NULL==colon ) ) FD_LOG_ERR(( "no colon in line '%s'", line ));

        *colon = '\0';
        char * key = line;
        char * value = colon + 1;

        while( ' '==*value || '\t'==*value ) value++;

        if( FD_LIKELY( !strcmp( key, "voluntary_ctxt_switches" ) ) ) {
          char * endptr;
          ulong voluntary_ctxt_switches = strtoul( value, &endptr, 10 );
          if( FD_UNLIKELY( *endptr!='\0' || voluntary_ctxt_switches==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul failed" ));
          fd_metrics_tile( ctx->metrics[ i ] )[ FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_VOLUNTARY_COUNT_OFF ] = voluntary_ctxt_switches;
        } else if( FD_LIKELY( !strcmp( key, "nonvoluntary_ctxt_switches" ) ) ) {
          char * endptr;
          ulong involuntary_ctxt_switches = strtoul( value, &endptr, 10 );
          if( FD_UNLIKELY( *endptr!='\0' || involuntary_ctxt_switches==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul failed" ));
          fd_metrics_tile( ctx->metrics[ i ] )[ FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_INVOLUNTARY_COUNT_OFF ] = involuntary_ctxt_switches;
        }

        line = next_line + 1;
      }
    }
  }
}

static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  (void)scratch;

  populate_sock_filter_policy_cswitch( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_cswitch_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_cswitch_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_cswitch_ctx_t ), sizeof( fd_cswitch_ctx_t ) );

  if( FD_UNLIKELY( out_fds_cnt<2UL+ctx->tile_cnt ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  for( ulong i=0; i<ctx->tile_cnt; i++ )
    out_fds[ out_cnt++ ] = ctx->status_fds[ i ]; /* /proc/<pid>/task/<tid>/status descriptor */
  return out_cnt;
}

fd_topo_run_tile_t fd_tile_cswitch = {
  .name                     = "cswitch",
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .mux_ctx                  = mux_ctx,
  .mux_during_housekeeping  = during_housekeeping,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};
