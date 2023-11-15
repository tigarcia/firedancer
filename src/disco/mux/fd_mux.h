#ifndef HEADER_fd_src_disco_mux_fd_mux_h
#define HEADER_fd_src_disco_mux_fd_mux_h

/* fd_mux provides services to multiplex multiple streams of input
   fragments and present them to a mix of reliable and unreliable
   consumers as though they were generated by a single multi-stream
   producer.  The entire process is zero copy for the actual fragment
   payloads and thus has extremely high throughput and extremely high
   scalability. */

#include "../fd_disco_base.h"

/* Beyond the standard FD_CNC_SIGNAL_HALT, FD_MUX_CNC_SIGNAL_ACK can be
   raised by a cnc thread with an open command session while the mux is
   in the RUN state.  The mux will transition from ACK->RUN the next
   time it processes cnc signals to indicate it is running normally.  If
   a signal other than ACK, HALT, or RUN is raised, it will be logged as
   unexpected and transitioned by back to RUN. */

#define FD_MUX_CNC_SIGNAL_ACK (4UL)

/* FD_MUX_TILE_IN_MAX and FD_MUX_TILE_OUT_MAX are the maximum number of
   inputs and outputs respectively that a mux tile can have.  These
   limits are more or less arbitrary from a functional correctness POV.
   They mostly exist to set some practical upper bounds for things like
   scratch footprint.  The current value for IN_MAX is large enough to
   have every possible frag meta origin be handled by a single thread.
   (And out_max is set arbitrarily to match.) */

#define FD_MUX_TILE_IN_MAX  FD_FRAG_META_ORIG_MAX
#define FD_MUX_TILE_OUT_MAX FD_FRAG_META_ORIG_MAX

/* FD_MUX_FLAG_* are user provided flags specifying how to run the mux
   tile.

   FD_MUX_FLAG_DEFAULT
      Default mux operating mode.
`
   FD_MUX_FLAG_MANUAL_PUBLISH
      By default, the mux will automatically publish received frags that
      are not filtered to the output mcache.  If this flag is set, the
      mux does not publish frags, and publishing must be done by the
      user provided callbacks.

      Note that it is not safe for a user to publish frags directly to
      the mcache which is managed by the mux, as the mux would not know
      about them for flow control purposes.  Instead, you should publish
      by calling fd_mux_publish.  If the mux is created with
      MANUAL_PUBLISH the mux will still do flow control on reliable
      consumers to ensure they are not overrun, other mux properties may
      no longer hold, particularly about the interleaving and ordering
      of the frags.

   FD_MUX_FLAG_COPY
      The mux tile is not zero copy, meaning it copies frag payloads and
      does not simply republishes a pointer to the incoming frag payload
      on to downstream consumers.  Because of this, flow control is less
      complicated since we no longer need to track the number of
      filtered frags in addition to published ones.  If this flag is
      set, it means the user promises that all published frags have been
      copied and the mux does not need to track filtered ones.

      Practically, to implement frag copying, the caller would need to
      either
       (a) Pass FD_MUX_FLAG_MANUAL_PUBLISH and call publish manually
           on fragments they manage.
       (b) Set the opt_chunk in the fd_mux_after_frag_fn callback to
           point to a copy of the frag payload. */
#define FD_MUX_FLAG_DEFAULT        0
#define FD_MUX_FLAG_MANUAL_PUBLISH 1
#define FD_MUX_FLAG_COPY           2

/* FD_MUX_TILE_SCRATCH_{ALIGN,FOOTPRINT} specify the alignment and
   footprint needed for a mux tile scratch region that can support
   in_cnt inputs and out_cnt outputs.  ALIGN is an integer power of 2 of
   at least be at least double cache line to mitigate various kinds of
   false sharing.  FOOTPRINT will be an integer multiple of ALIGN.
   {in,out}_cnt are assumed to be valid (i.e. at most
   FD_MUX_TILE_{IN,OUT}_MAX).  in_cnt and out_cnt are assumed to be
   valid and safe against multiple evaluation.  These are provided to
   facilitate compile time declarations. */

#define FD_MUX_TILE_SCRATCH_ALIGN (128UL)
#define FD_MUX_TILE_SCRATCH_FOOTPRINT( in_cnt, out_cnt )                \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( \
  FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,                   \
    64UL,             (in_cnt)*64UL                           ),        \
    alignof(ulong *), (out_cnt)*sizeof(ulong *)               ),        \
    alignof(ulong *), (out_cnt)*sizeof(ulong *)               ),        \
    alignof(ulong),   (out_cnt)*sizeof(ulong)                 ),        \
    alignof(ushort),  ((in_cnt)+(out_cnt)+1UL)*sizeof(ushort) ),        \
    FD_MUX_TILE_SCRATCH_ALIGN )

/* fd_mux_context_t is an opaque type that is passed to the user
   provided callbacks.  The user can use this mux object to publish
   messages to the downstream consumers by calling fd_mux_publish( mux )
   , where mux is the fd_mux_context_t object passed to the callbacks.

   This is the only supported way of publishing, as the mux needs to
   keep housekeeping information related to flow control.

   The user callback should not modify any fields of the mux context. */

typedef struct {
   fd_frag_meta_t * mcache;
   ulong depth;
   ulong * cr_avail;
   ulong * seq;
   ulong   cr_decrement_amount;
} fd_mux_context_t;

/* fd_mux_during_housekeeping_fn is called during the housekeeping routine,
   which happens infrequently on a schedule determined by the mux (based on
   the lazy parameter, see fd_tempo.h for more information).

   It is appropriate to do slightly expensive things here that wouldn't be
   OK to do in the main loop, like updating sequence numbers that are shared
   with other tiles (e.g. synchronization information), or sending batched
   information somewhere.

   The ctx is a user-provided context object from when the mux tile was
   initialized. */
typedef void (fd_mux_during_housekeeping_fn)( void * ctx );

/* fd_mux_before_credit_fn is called every iteration of the mux run loop,
   whether there is a new frag ready to receive or not.  This callback
   is also still invoked even if the mux is backpressured and cannot
   read any new fragments while waiting for downstream consumers to
   catch up.

   This callback is useful for things that need to occur even if no new
   frags are being handled.  For example, servicing network connections
   could happen here.

   The ctx is a user-provided context object from when the mux tile was
   initialized.  The mux is the mux which is invoking this callback.
   The mux should only be used for calling fd_mux_publish to publish
   a fragment to downstream consumers. */
typedef void (fd_mux_before_credit_fn)( void *             ctx,
                                        fd_mux_context_t * mux);

/* fd_mux_after_credit_fn is called every iteration of the mux run loop,
   whether there is a new frag ready to receive or not, except in cases
   where the mux is backpressured by a downstream consumer and would not
   be able to publish.

   The callback might be used for publishing new fragments to downstream
   consumers in the main loop which are not in response to an incoming
   fragment.  For example, code that collects incoming fragments over
   a period of 1 second and joins them together before publishing a
   large block fragment downstream, would publish the block here.

   The ctx is a user-provided context object from when the mux tile was
   initialized.  The mux is the mux which is invoking this callback.
   The mux should only be used for calling fd_mux_publish to publish
   a fragment to downstream consumers. */
typedef void (fd_mux_after_credit_fn)( void *             ctx,
                                       fd_mux_context_t * mux );

/* fd_mux_before_frag_fn is called immediately whenever a new fragment
   has been detected that was published by an upstream producer.  The
   signature and sequence number (sig and seq) provided as arguments
   are read atomically from shared memory, so must both match each other
   from the published fragment (aka. they will not be torn or partially
   overwritten).  in_idx is an index in [0, num_ins) indicating which
   producer published the fragment.

   No fragment data has been read yet here, nor has other metadata, for
   example the size or timestamps of the fragment.  Mainly this callback
   is useful for deciding whether to filter the fragment based on its
   signature.  If opt_filter is set to non-zero, the frag will be
   skipped completely, no fragment data will be read, and the in will
   be advanced so that we now wait for the next fragment.

   The ctx is a user-provided context object from when the mux tile was
   initialized. */
typedef void (fd_mux_before_frag_fn)( void * ctx,
                                      ulong  in_idx,
                                      ulong  seq,
                                      ulong  sig,
                                      int *  opt_filter );

/* fd_mux_during_frag_fn is called after the mux has received a new frag
   from an in, but before the mux has checked that it was overrun.  This
   callback is not invoked if the mux is backpressured, as it would not
   try and read a frag from an in in the first place (instead, leaving
   it on the in mcache to backpressure the upstream producer).  in_idx
   will be the index of the in that the frag was received from.

   If the producer of the frags is respecting flow control, it is safe
   to read frag data in any of the callbacks, but it is suggested to
   copy or read frag data within this callback, as if the producer does
   not respect flow control, the frag may be torn or corrupt due to an
   overrun by the reader.  If the frag being read from has been
   overwritten while this callback is running, the frag will be ignored
   and the mux will not call the process function.  Instead it will
   recover from the overrun and continue with new frags.

   This function cannot fail.  If opt_filter is set to non-zero, it
   means the frag should be filtered and not passed on to downstream
   consumers of the mux.

   The ctx is a user-provided context object from when the mux tile was
   initialized.

   sig, chunk, and sz are the respective fields from the mcache fragment
   that was received.  If the producer is not respecting flow control,
   these may be corrupt or torn and should not be trusted. */

typedef void (fd_mux_during_frag_fn)( void * ctx,
                                      ulong  in_idx,
                                      ulong  sig,
                                      ulong  chunk,
                                      ulong  sz,
                                      int *  opt_filter );

/* fd_mux_after_frag_fn is called immediately after the
   fd_mux_during_frag_fn, along with an additional check that the reader
   was not overrun while handling the frag.  If the reader was overrun,
   the frag is abandoned and this function is not called.  This callback
   is not invoked if the mux is backpressured, as it would not read a
   frag in the first place.  It is also not invoked if
   fd_mux_during_frag sets opt_filter to non-zero, indicating to filter
   the frag. in_idx will be the index of the in that the frag was
   received from.

   You should not read the frag data directly here, as it might still
   get overrun, instead it should be copied out of the frag during the
   read callback if needed later.

   This function cannot fail.  If opt_filter is set to non-zero, it
   means the frag should be filtered and not passed on to downstream
   consumers of the mux.

   The ctx is a user-provided context object from when the mux tile was
   initialized.  mux should only be used for calling fd_mux_publish to
   publish a fragment to downstream consumers.

   opt_sig, opt_chunk, and opt_sz are the respective fields from the
   mcache fragment that was received.  The callback can modify these
   values to change the sig, chunk, and sz of the outgoing frag that is
   being copied to downstream consumers.  If the producer is not
   respecting flow control, these may be corrupt or torn and should not
   be trusted. */

typedef void (fd_mux_after_frag_fn)( void *             ctx,
                                     ulong              in_idx,
                                     ulong *            opt_sig,
                                     ulong *            opt_chunk,
                                     ulong *            opt_sz,
                                     int *              opt_filter,
                                     fd_mux_context_t * mux );

/* By convention, the mux tile (and other tiles) use the app data region
   of the joined cnc to store overall tile diagnostics like whether they
   are backpressured.  fd_mux_cnc_diag_write is called back to let the
   user add additional diagnostics.  This should not touch cnc_app[0] or
   cnc_app[1] which are reserved for the mux tile (FD_CNC_DIAG_IN_BACKP
   and FD_CNC_DIAG_BACKP_CNT).  The user can use cnc_app[2] and beyond,
   if such additional space was reserved when the cnc was created.

   fd_mux_cnc_diag_write and fd_mux_cnc_diag_clear are a pair of
   functions to support accumulating counters.  fd_mux_cnc_diag_write is
   called inside a compiler fence to ensure the writes do not get
   reordered, which may be important for observers or monitoring tools,
   but such a guarantee is not needed when clearing local values in the
   ctx.  A typical usage for a counter is then to increment from a local
   context counter in write(), and then reset the local context counter
   to 0 in clear().

   The ctx is a user-provided context object from when the mux tile was
   initialized. */

typedef void (fd_mux_cnc_diag_write_fn)( void *  ctx,
                                         ulong * cnc_app );

typedef void (fd_mux_cnc_diag_clear_fn)( void * ctx );

/* fd_mux_callbacks_t will be invoked during mux tile execution, and can
   be used to alter behavior of the mux tile from the default of copying
   frags from the inputs directly to the outputs.  Each of the callbacks
   can be NULL, in which case it will not be executed. */

typedef struct {
  fd_mux_during_housekeeping_fn * during_housekeeping;

  fd_mux_before_credit_fn * before_credit;
  fd_mux_after_credit_fn *  after_credit;

  fd_mux_before_frag_fn * before_frag;
  fd_mux_during_frag_fn * during_frag;
  fd_mux_after_frag_fn  * after_frag;

  fd_mux_cnc_diag_write_fn * cnc_diag_write;
  fd_mux_cnc_diag_clear_fn * cnc_diag_clear;
} fd_mux_callbacks_t;

FD_PROTOTYPES_BEGIN

/* fd_mux_tile multiplex fragment streams provided through in_cnt
   in_mcache's that has to out_cnt reliable consumers and an arbitrary
   number of unreliable consumers.  (While reliable consumers are simple
   to reason about, they have especially high demands on their
   implementation as a single slow reliable consumer can backpressure
   _all_ producers and _all_ other consumers using the mux.)

   The order of frags among a group of streams covered by a single
   in_mcache will be preserved.  Frags from different groups of streams
   can be arbitrarily interleaved (but this makes an extreme best effort
   to avoid starvation and minimize slip between different groups of
   streams).

   The signature, chunk, sz, ctl and tsorig input fragment metadata will
   be unchanged by this tile, unless they are modified by the user in a
   callback.

   For seq, the mux tile will resequence the frags from all the mcache's
   into a new total order consistent with the above.

   For ctl, it is up to the application to specify ctl.orig for all
   streams covered by the in_mcache's in a non-conflicting way.
   Specifically, at any given time, ctl.orig field should unique
   identify an active logical publisher such that a consumer can
   correctly reassemble multiple fragment messages from that ctl.orig.
   (As such, ctl.orig could be used more flexible if an application
   never does multiple fragment messages.)

   For chunk, a consumer needs to be able to map a (ctl.orig,chunk) pair
   to an address in that consumer's local address space.  The simplest
   and most performant way to do this (especially in simple NUMA
   topologies) is to have all dcache's use the same workspace and have
   each producer reference chunks relative to the containing workspace.

   For tsorig and tspub, the mux tile will recompute tspub for
   multiplexed fragments.  Assuming the original publisher of the frag
   set tsorig of the the fragment to when it started producing the
   message to which the frag belongs and set tspub to the timestamp to
   when it first published the frag, and that the producer, mux and
   consumer all have access to the same clock, a downstream consumer can
   tell when a message started arriving, when it was first available to
   for consumption and (by locally reading the clock) the time when it
   actually started consuming.  And the logic for doing so on the
   consumer will be the same on the consumer regardless it is consuming
   directly or through one or more rounds of multiplexing.

   When this is called, the cnc should be in the BOOT state.  Returns 0
   on a successful run of the mux tile.  That is, the tile booted
   successfully (transitioning the cnc from BOOT->RUN), ran (handling
   any application specific cnc signals while running), and (after
   receiving a HALT signal) halted successfully (transitioning the cnc
   from HALT->BOOT before return).  Returns a non-zero error code if the
   tile fails to boot up (logs details ... the cnc will not be
   transitioned from its original state and thus is likely bootable
   again if its original state was BOOT).  For maximally robust
   operation in the current implementation, all reliable consumers
   should be halted and/or caught up before this tile is halted.

   There are no theoretical restrictions on the fragment stream mcache
   depths.  Practically, it is recommend these be as large as possible,
   especially for bursty streams and/or a large number of reliable
   consumers.  Likewise, there is no benefit from the mux's POV to using
   a mcache depth different from the smallest input mcache depth
   (smaller can underutilize the input mcaches and larger cannot be
   fully utilized by the downstream outs due to the worst case scenarios
   with the smallest in mcache).  Similarly, there is no advantage from
   the mux's POV to using variable in_mcache depths.  But there can be
   unrelated reasons for variable mcache depths (e.g. hardware
   requirements for a frag stream produced by custom hardware, needs for
   non-mux consumers of individual frag streams, etc).

   Note that a number of tricks can be done to facilitate making this
   work with completely unreliable / non-backpressuring communications
   from producer to mux and mux to consumer.  The most efficient trick
   being that producers tag their payloads uniquely and include that tag
   in metadata (e.g.  use the signature).  When an unreliable consumer
   reads the metadata from the mcache, it learns the tag and then can
   read the payload from direct from the in dcache (no communication
   links need to be reliable in this regime and no verification read of
   the metadata is required either ... does require a tagging method,
   payload formatting requirements and using up some metadata signature
   bits).  This is currently not done in the interest of generality
   (more pedantically, this more about how applications handle fragment
   streams and less about how the mux tile functions).

   cr_max is the maximum number of flow control credits the mux tile is
   allowed for publishing frags to outs.  It represents the maximum
   number of frags a reliable out can lag behind the multiplexed stream
   and the maximum number of frags from any in mcache that might be
   exposed to the outs.  In the general case, the optimal value is
   usually min(in[*].cr_max,out[*].lag_max).  Noting that in[*].cr_max
   is in [1,in_mcache[*].depth] and out[*].lag_max is in
   [1,mcache.depth], cr_max must be in, at a minimum,
   [1,min(in_mcache[*].depth,mcache.depth)].  If cr_max is zero, this
   use a default cr_max of min(in_mcache[*].depth,mcache.depth).  This
   is equivalent to assuming, as is typically the case, outs are allowed
   to lag the mux by up to mcache.depth frags and in[*].cr_max is the
   same as in_mcache[*].depth.

   lazy is the ballpark interval in ns for how often to receive credits
   from an out (and, equivalently, how often to return credits to an
   in).  Too small a lazy will drown the system in cache coherence
   traffic.  Too large a lazy will kill system throughput because of
   producers stalled waiting for credits.  lazy should be roughly
   proportional to cr_max and the constant of proportionality should be
   less than the smaller of how fast a producer can generate frags / how
   fast a consumer can process frags typically.  <=0 indicates to pick a
   conservative default.

   scratch points to tile scratch memory.  fd_mux_tile_scratch_align and
   fd_mux_tile_scratch_footprint return the required alignment and
   footprint needed for this region.  This memory region is exclusively
   owned by the mux tile while the tile is running and is ideally near
   the core running the mux tile.  fd_mux_tile_scratch_align will return
   the same value as FD_MUX_TILE_SCRATCH_ALIGN.  If (in_cnt,out_cnt) is
   not valid, fd_mux_tile_scratch_footprint silently returns 0 so
   callers can diagnose configuration issues.  Otherwise,
   fd_mux_tile_scratch_footprint will return the same value as
   FD_MUX_TILE_SCRATCH_FOOTPRINT.

   A fd_mux_tile will use the application regions of the fseqs and cncs
   for accumulating standard diagnostics in the standard ways.  Except
   for FD_CNC_DIAG_IN_BACKP, none of the diagnostics are cleared at (as
   such that they can be accumulated over multiple runs).  Clearing is
   up to monitoring scripts.  It is recommend that inputs and outputs
   also use their cnc and fseq application regions similarly for
   monitoring simplicity / consistency.

   The lifetime of the cnc, mcaches, fseqs, rng and scratch used by this
   tile should be a superset of this tile's lifetime.  While this tile
   is running, no other tile should use cnc for its command and control,
   publish into mcache, use the rng for anything (and the rng should be
   be seeded distinctly from all other rngs in the system), or use
   scratch for anything.  This tile will act as a reliable consumer of
   in_mcache metadata.  This tile uses the in_fseqs passed to it in the
   usual consumer ways (e.g. publishing recent locations in the
   producers sequence space and updating consumer oriented diagnostics)
   and the out_fseqs passed to it in the usual producer ways (i.e.
   discovering the location of reliable consumers in sequence space and
   updating producer oriented diagnostics).  The in_mcache, in_fseq and
   out_fseq arrays will not be used the after the tile has successfully
   booted (transitioned the cnc from BOOT to RUN) or returned (e.g.
   failed to boot), whichever comes first. */

FD_FN_CONST ulong
fd_mux_tile_scratch_align( void );

FD_FN_CONST ulong
fd_mux_tile_scratch_footprint( ulong in_cnt,
                               ulong out_cnt );

int
fd_mux_tile( fd_cnc_t *              cnc,         /* Local join to the mux's command-and-control */
             ulong                   flags,       /* Any of FD_MUX_FLAG_* specifying how to run the mux */
             ulong                   in_cnt,      /* Number of input mcaches to multiplex, inputs are indexed [0,in_cnt) */
             fd_frag_meta_t const ** in_mcache,   /* in_mcache[in_idx] is the local join to input in_idx's mcache */
             ulong **                in_fseq,     /* in_fseq  [in_idx] is the local join to input in_idx's fseq */
             fd_frag_meta_t *        mcache,      /* Local join to the mux's frag stream output mcache */
             ulong                   out_cnt,     /* Number of reliable consumers, reliable consumers are indexed [0,out_cnt) */
             ulong **                out_fseq,    /* out_fseq[out_idx] is the local join to reliable consumer out_idx's fseq */
             ulong                   burst,       /* The maximum number of frags this tile publishes per input frag */
             ulong                   cr_max,      /* Maximum number of flow control credits, 0 means use a reasonable default */
             long                    lazy,        /* Lazyiness, <=0 means use a reasonable default */
             fd_rng_t *              rng,         /* Local join to the rng this mux should use */
             void *                  scratch,     /* Tile scratch memory */
             void *                  ctx,         /* User supplied context to be passed to the read and process functions */
             fd_mux_callbacks_t *    callbacks ); /* User supplied callbacks to be invoked during mux tile execution */

static inline ulong
fd_mux_advance( fd_mux_context_t * ctx ) {
  ulong * seqp = ctx->seq;
  ulong   seq  = *seqp;
  *ctx->cr_avail -= ctx->cr_decrement_amount;
  *seqp = fd_seq_inc( seq, 1UL );
  return seq;
}

/* If the mux is operating with FD_MUX_FLAG_NO_PUBLISH, the caller can optionally
   publish fragments to the consumers themself.  To do this, they should call
   fd_mux_publish with the mux context provided in the  */
static inline void
fd_mux_publish( fd_mux_context_t * ctx,
                ulong              sig,
                ulong              chunk,
                ulong              sz,
                ulong              ctl,
                ulong              tsorig,
                ulong              tspub ) {
  ulong * seqp = ctx->seq;
  ulong   seq  = *seqp;
  fd_mcache_publish( ctx->mcache, ctx->depth, seq, sig, chunk, sz, ctl, tsorig, tspub );
  *ctx->cr_avail -= ctx->cr_decrement_amount;
  *seqp = fd_seq_inc( seq, 1UL );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_mux_fd_mux_h */

