#ifndef HEADER_fd_src_ballet_pack_fd_pack_chkdup_h
#define HEADER_fd_src_ballet_pack_fd_pack_chkdup_h
#include "../fd_ballet_base.h"
#include "../txn/fd_txn.h"

/* fd_pack_chkdup declares a set of functions for ultra-HPC
   checking if a list of account addresses contains any duplicates.
   It's important that this be fast, because a transaction containing
   duplicate account addresses fails to sanitize and is not charged a
   fee.  Although this check can (and really ought) to be done in
   parallel, perhaps in the verify tiles, right now, it's done in pack,
   which means it's serial and on the critical path.

   On platforms with AVX, the current implementation uses a fast initial
   check which may have false positives (thinking there are duplicates
   when there aren't).  Any transaction that fails the initial check is
   then subjected to the full, precise check.  Without AVX, all
   transactions use the slow path. */

/* The functions are defined in the header to facilitate inlining since
   they take 10s of cycles in the good case, but should probably be
   treated as if they were defined in a .c file. */

#ifndef FD_PACK_CHKDUP_IMPL
# if FD_HAS_AVX512
#   define FD_PACK_CHKDUP_IMPL 2
# elif FD_HAS_AVX
#   define FD_PACK_CHKDUP_IMPL 1
# else
#   define FD_PACK_CHKDUP_IMPL 0
# endif
#endif


#if FD_PACK_CHKDUP_IMPL==2
# define FD_PACK_CHKDUP_ALIGN ( 64UL)
# define FD_PACK_CHKDUP_K     (256UL)
#elif FD_PACK_CHKDUP_IMPL==1
# define FD_PACK_CHKDUP_ALIGN ( 32UL)
# define FD_PACK_CHKDUP_K     (160UL)
#elif FD_PACK_CHKDUP_IMPL==0
# define FD_PACK_CHKDUP_ALIGN ( 32UL)
# define FD_PACK_CHKDUP_K     (  0UL)
#else
# error "Unrecognized value of FD_PACK_CHKDUP_IMPL"
#endif


# define FD_PACK_CHKDUP_FOOTPRINT  FD_LAYOUT_FINI( FD_LAYOUT_APPEND(                                   \
                                                             FD_LAYOUT_APPEND( FD_LAYOUT_INIT,         \
                                                             FD_PACK_CHKDUP_ALIGN, FD_PACK_CHKDUP_K ), \
                                                             32UL,                 (1UL<<8)*32UL    ), \
                                                   FD_PACK_CHKDUP_ALIGN )

FD_STATIC_ASSERT( (1UL<<8)==2*FD_TXN_ACCT_ADDR_MAX, "hash table size" );

/* Fixed size (just over 8kB) and safe for declaration on the stack or
   inclusion in a struct. */
struct fd_pack_chkdup_private;
typedef struct fd_pack_chkdup_private fd_pack_chkdup_t;

FD_PROTOTYPES_BEGIN
/* fd_pack_chkdup_{footprint, align} return the footprint and
   alignment of the scratch memory that duplicate detection requires. */
static inline ulong fd_pack_chkdup_footprint( void ) { return FD_PACK_CHKDUP_FOOTPRINT; }
static inline ulong fd_pack_chkdup_align    ( void ) { return FD_PACK_CHKDUP_ALIGN;     }

/* fd_pack_chkdup_new formats an appropriately sized region of memory
   for use in duplicate address detection.  shmem must point to the
   first byte of a region of memory with the appropriate alignment and
   footprint.  rng must be a pointer to a local join of an RNG.  Some
   slots of the RNG will be consumed, but no interest in the RNG will be
   retained after the function returns.  Returns shmem on success and
   NULL on failure (logs details).  The only failure cases are if shmem
   is NULL or not aligned.

   fd_pack_chkdup_join joins the caller to the formatted region of
   memory.  Returns shmem.

   fd_pack_chkdup_leave unjoins the caller to chkdup.  Returns chkdup.
   fd_pack_chkdup_delte unformats the region of memory.  Returns a
   pointer to the unformatted memory region. */
static inline void *             fd_pack_chkdup_new   ( void * shmem, fd_rng_t * rng );
static inline fd_pack_chkdup_t * fd_pack_chkdup_join  ( void * shmem                 );
static inline void *             fd_pack_chkdup_leave ( fd_pack_chkdup_t * chkdup    );
static inline void *             fd_pack_chkdup_delete( void * shmem                 );


/* fd_pack_chkdup_check_duplicate{,_slow,_fast} check a list of account
   addresses for any duplicate addresses, i.e. an account address that
   appears twice in the list.  The list does not need to be sorted or
   have any particular order.  The list may be decomposed into two
   sublists (list0 and list1) to facilitate 0-copy usage with address
   lookup tables, but list0 and list1 are logically concatenated prior
   to checking for duplicates.

   chkdup is a pointer to a valid local join of a chkdup object.

   list0 and list1 point to the first account address of the respective
   sublists.  The memory they point to need not have any particular
   alignment.  list0==NULL is okay only if list0_cnt==0, and similarly
   for list1.  list0 is accessed with indices [0, list0_cnt) and list1
   is accessed with indices [0, list1_cnt).  list0 and list1 must not
   overlap.  Requires list0_cnt+list1_cnt<=128, and the function is
   somewhat tuned for smaller values.

   fd_pack_chkdup_check_duplicates and the _slow version return 1 if the
   list of transactions contains at least one duplicated account address
   and 0 otherwise (implying each account address in the provided list
   is unique).

   fd_pack_chkdup_check_duplicates_fast returns 1 if the list of
   transactions contains at least one duplicated account address and
   typically returns 0 if each account address in the provided list is
   unique, but may sometimes spuriiously return 1 even without
   duplicates.

   WARNING: the _fast version MAY HAVE FALSE POSITIVES.  You probably
   want the un-suffixed version, which is precise.  It uses the fast
   version as a fast-path and then does a slower full check if the
   fast-path suggests there may be a duplicate.

   However, it's also worth calling out again that the _fast version
   only makes errors in one direction.  If the list contains duplicates,
   it will definitely return 1.  If it returns 0, the list definitely
   does not contain duplicates. (Those two statements are equivalent).
   */
static inline int
fd_pack_chkdup_check_duplicate     ( fd_pack_chkdup_t     * chkdup,
                                     fd_acct_addr_t const * list0,     ulong list0_cnt,
                                     fd_acct_addr_t const * list1,     ulong list1_cnt );
static inline int
fd_pack_chkdup_check_duplicate_slow( fd_pack_chkdup_t     * chkdup,
                                     fd_acct_addr_t const * list0,     ulong list0_cnt,
                                     fd_acct_addr_t const * list1,     ulong list1_cnt );
static inline int
fd_pack_chkdup_check_duplicate_fast( fd_pack_chkdup_t     * chkdup,
                                     fd_acct_addr_t const * list0,     ulong list0_cnt,
                                     fd_acct_addr_t const * list1,     ulong list1_cnt );


/*   -----  Implementation details and discussion follow------

   The fast path implementation is somewhat interesting.  Basically, for
   each account address, we compute lots of projections using a fixed
   set of random functions.  Along with each projection function, we
   keep track of the lowest value we've seen among all the account
   addresses in a transaction.  If an account address results in a newer
   minimum for even a single projection, that means that we cannot have
   seen that account address before.  If none of the minimums are
   updated, the account address may be a duplicate.

   In order to reduce the false positive occurrence rate, we need lots
   of projections, which means they need to be fast.  To that end,
   we use projection p_k( a ) = a[k%32] ^ c_k, where c_k is a constant
   known at compile time.  This means we can use the vpminub and
   vpcmpeqb instructions as part of computing 32 projections.  All in
   all, we can process 32 projections in a little more than 1 cycle
   (throughput).

   The slow-path implementation uses a hash table to check for
   duplicates.  This is slower than sorting for transactions with only a
   few account addresses, but substantially faster than sorting for
   transactions with large numbers of account addresses, which is when
   the slow-path matters more anyway.


   Now, some math on how to tune this:

   We assume account addresses are effectively random, and a transaction
   has N account addresses.  Then the value of each projection of each
   account address is also a random uniformly distributed integer in
   [0, 255].

   To do the analysis, we need to know something about the distribution
   M(j) of the minimum of j iid random integers P_1, P_2, ... P_j
   distributed uniformly on [0, 255].  If X ~ M(j), then the CDF for X
   is
             P(X <= x) = 1 - P(x < X)
                       = 1 - P(x < P_1 and x < P_2 ... and x < P_j)
                       = 1 - P(x < P_1)^j
                       = 1 - ((255-x)/256)^j

  Now then, the next single account address projection gives a false
  positive if the projected value is at least as large as X, the
  minimum.  Let the projected value, A, be a random variable distributed
  uniformly randomly on [0, 255].
             P(X <= A) = P(X<=0)/256 + P(X<=1)/256 + ... P(X<=255)/256
                       = sum_{a=0}^255 P(X <= a)/256
                       = sum_{a=0}^255 (1 - ((255-a)/256)^j)/256
                       = 1 - (256)^(-j-1) * sum_{a=0}^255 (255-a)^j
                       = 1 - (256)^(-j-1) * sum_{a=0}^255 a^j

  This last term is known as the generalized harmonic number
  H_{255, -j}.  Asymptotically, this is something like
  1-1/j * (255/256)^j, which isn't so great, which is why we need a lot
  of projections.  One important insight is that making the projections
  wider (e.g. increasing 256 to 64k by switching from bytes to shorts)
  has a pretty minimal effect.

  When we have multiple projections, we only have a real false positive
  if all the projections are false positives simultaneously.
  Specifically, if we have K projections, then the actual probability of
  a false positive is
                   (1 - H_{255, -j}/256^(j+1))^K.

  However, we want the probability of the whole transaction having a
  false positive, not just the jth account.  A transaction doesn't have
  a false positive if none of the accounts have false positives, so the
  actual probability we want for a transaction with J account addresses
  is:
                       J-1
                      -----
     FP_{J,K} = 1  -  |   | 1 - ( 1 - H_{255,-j}/256^(j+1) )^K
                      |   |
                       j=1

  Now, with all this behind us, our goal is to pick the optimal value of
  K given a supposed distribution of transactions, and a performance
  model.  Based on some back of the envelope calculations based on
  instruction throughput and latency measurements and confirmed by some
  experiments, the fast path code takes about J*(2+4/3*ceil(K/32))
  cycles on a modern Intel chip using AVX2 and J*(4+2*ceil(K/64)) if
  using AVX512.  The slow path takes about 133*J cycles.  Then the
  expected value of the number of cycles it takes to process a
  transaction with J accounts is
              J*(2+4/3*ceil(K/32)) + FP_{J,K}*133*J
  Based on a sample of 100,000 slots containing about 100M transactions,
  the CDF looks like

    Fraction of transactions containing <=  3 account addresses     71%
                                        <= 13 account addresses     80%
                                        <= 24 account addresses     91%
                                        <= 31 account addresses     95%
                                        <= 44 account addresses     98%
                                        <= 50 account addresses     99%

  Basically, there's a peak at 3 (votes), and then a very long, very fat
  tail.  The value of K that minimizes the expected value is 256, but
  any value between about 160 and 400 gives about the same expected
  computation time.  The performance model above assumed we had enough
  AVX registers available (about 3K/32+1), so for AVX2 we'll pick K=5*32
  and for AVX512, we'll pick K=4*64. */

struct fd_pack_chkdup_waddr {
  fd_acct_addr_t key; /* account address */
};
typedef struct fd_pack_chkdup_waddr fd_pack_chkdup_waddr_t;
static const fd_acct_addr_t null_addr = {{ 0 }};

#define MAP_NAME              fd_pack_chkdup_pmap
#define MAP_T                 fd_pack_chkdup_waddr_t
#define MAP_KEY_T             fd_acct_addr_t
#define MAP_KEY_NULL          null_addr
#define MAP_KEY_INVAL(k)      MAP_KEY_EQUAL(k, null_addr)
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp((k0).b,(k1).b, FD_TXN_ACCT_ADDR_SZ))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_MEMOIZE           0
#define MAP_KEY_HASH(key)     ((uint)fd_ulong_hash( fd_ulong_load_8( (key).b ) ))
#define MAP_LG_SLOT_CNT 8
#include "../../util/tmpl/fd_map.c"


struct __attribute__((aligned(FD_PACK_CHKDUP_ALIGN))) fd_pack_chkdup_private {
#if FD_PACK_CHKDUP_IMPL >= 1
  uchar  entropy[ FD_PACK_CHKDUP_K ];
#endif

  fd_pack_chkdup_waddr_t hashmap[ 1UL<<8 ];
};

static inline void *
fd_pack_chkdup_new( void    * shmem,
                   fd_rng_t * rng   ) {
  fd_pack_chkdup_t * chkdup = (fd_pack_chkdup_t *)shmem;
#if FD_PACK_CHKDUP_IMPL >= 1
  for( ulong i=0UL; i<FD_PACK_CHKDUP_K; i++ ) chkdup->entropy[ i ] = fd_rng_uchar( rng );
#endif
  FD_TEST( fd_pack_chkdup_pmap_footprint()==sizeof(chkdup->hashmap) ); /* Known at compile time */

  fd_pack_chkdup_pmap_new( chkdup->hashmap );
  return chkdup;
}

static inline fd_pack_chkdup_t * fd_pack_chkdup_join  ( void * shmem ) { return (fd_pack_chkdup_t *)shmem; }

static inline void * fd_pack_chkdup_leave ( fd_pack_chkdup_t * chkdup ) { return (void *)chkdup; }
static inline void * fd_pack_chkdup_delete( void             * shmem  ) { return         shmem;  }


static inline int
fd_pack_chkdup_check_duplicate     ( fd_pack_chkdup_t     * chkdup,
                                     fd_acct_addr_t const * list0,     ulong list0_cnt,
                                     fd_acct_addr_t const * list1,     ulong list1_cnt ) {
  if( FD_LIKELY( 0==fd_pack_chkdup_check_duplicate_fast( chkdup, list0, list0_cnt, list1, list1_cnt ) ) ) return 0;
  return fd_pack_chkdup_check_duplicate_slow( chkdup, list0, list0_cnt, list1, list1_cnt );
}

static inline int
fd_pack_chkdup_check_duplicate_slow( fd_pack_chkdup_t     * chkdup,
                                     fd_acct_addr_t const * list0,     ulong list0_cnt,
                                     fd_acct_addr_t const * list1,     ulong list1_cnt ) {
  fd_pack_chkdup_waddr_t * map = fd_pack_chkdup_pmap_join( chkdup->hashmap );
  fd_pack_chkdup_waddr_t * inserted[ FD_TXN_ACCT_ADDR_MAX ];
  ulong inserted_cnt = 0UL;

  int any_duplicates = 0;
  int skipped_inval = 0;
  for( ulong i0=0UL; (i0<list0_cnt) & any_duplicates; i0++ ) {
    if( FD_UNLIKELY( fd_pack_chkdup_pmap_key_inval( list0[ i0 ] ) ) ) {
      /* Okay if this is the 1st, but not if the 2nd */
      any_duplicates |= skipped_inval;
      skipped_inval   = 1;
      continue;
    }
    fd_pack_chkdup_waddr_t * ins = fd_pack_chkdup_pmap_insert( map, list0[ i0 ] );
    inserted[ inserted_cnt++ ] = ins;
    any_duplicates |=        (NULL==ins);
    inserted_cnt   -= (ulong)(NULL==ins); /* Correct inserted_cnt if we just stored a NULL */
  }
  for( ulong i1=0UL; (i1<list1_cnt) & any_duplicates; i1++ ) {
    if( FD_UNLIKELY( fd_pack_chkdup_pmap_key_inval( list1[ i1 ] ) ) ) {
      any_duplicates |= skipped_inval;
      skipped_inval   = 1;
      continue;
    }
    fd_pack_chkdup_waddr_t * ins = fd_pack_chkdup_pmap_insert( map, list1[ i1 ] );
    inserted[ inserted_cnt++ ] = ins;
    any_duplicates |=        (NULL==ins);
    inserted_cnt   -= (ulong)(NULL==ins);
  }

  /* FIXME: This depends on undocumented map behavior for correctness.
     Deleting in the opposite order of insertion preserves previously
     inserted pointers. That behavior should be documented. */
  for( ulong i=0UL; i<inserted_cnt; i++ ) fd_pack_chkdup_pmap_remove( map, inserted[ inserted_cnt-1UL-i ] );

  fd_pack_chkdup_pmap_leave( map );

  return any_duplicates;
}


#if FD_PACK_CHKDUP_IMPL==1

/* AVX2 implementation */
#include "../../util/simd/fd_avx.h"
static inline int
fd_pack_chkdup_check_duplicate_fast( fd_pack_chkdup_t     * chkdup,
                                     fd_acct_addr_t const * list0,     ulong list0_cnt,
                                     fd_acct_addr_t const * list1,     ulong list1_cnt ) {
  FD_STATIC_ASSERT( FD_PACK_CHKDUP_K==5*32, hand_unroll );
  if( FD_UNLIKELY( list0_cnt+list1_cnt<=1UL ) ) return 0UL;

  int any_duplicates = 0;

  const wb_t c0 = wb_ld( chkdup->entropy         );
  const wb_t c1 = wb_ld( chkdup->entropy +  32UL );
  const wb_t c2 = wb_ld( chkdup->entropy +  64UL );
  const wb_t c3 = wb_ld( chkdup->entropy +  96UL );
  const wb_t c4 = wb_ld( chkdup->entropy + 128UL );

  wb_t addr = wb_ldu( list0_cnt ? list0 : list1 );

  wb_t x0 = wb_xor( addr, c0 );
  wb_t x1 = wb_xor( addr, c1 );
  wb_t x2 = wb_xor( addr, c2 );
  wb_t x3 = wb_xor( addr, c3 );
  wb_t x4 = wb_xor( addr, c4 );

  for( ulong i0=1UL; i0<list0_cnt; i0++ ) {
    addr = wb_ldu( list0+i0 );

    /* Compute projections and the minimum */
    wb_t y0 = wb_min( x0, wb_xor( addr, c0 ) );
    wb_t y1 = wb_min( x1, wb_xor( addr, c1 ) );
    wb_t y2 = wb_min( x2, wb_xor( addr, c2 ) );
    wb_t y3 = wb_min( x3, wb_xor( addr, c3 ) );
    wb_t y4 = wb_min( x4, wb_xor( addr, c4 ) );

    wb_t e0 = wb_eq( y0, x0 );
    wb_t e1 = wb_eq( y1, x1 );
    wb_t e2 = wb_eq( y2, x2 );
    wb_t e3 = wb_eq( y3, x3 );
    wb_t e4 = wb_eq( y4, x4 );

    wb_t all = wb_and( e4, wb_and( e3, wb_and( e2, wb_and( e1, e0 ) ) ) );

    x0 = y0;
    x1 = y1;
    x2 = y2;
    x3 = y3;
    x4 = y4;

    /* If all the projections were equal, it might be a duplicate */
    any_duplicates |= wb_all_fast( all );

    /* The compiler correcly identifies that if any_duplicates ever
       becomes 1, the function will unconditionally return 1, and
       subsequent iterations don't matter.  However, that is unlikely,
       and we don't want a branch dependent on the value of the
       computation here. */
    FD_COMPILER_FORGET( any_duplicates );
  }
  /* If list0_cnt==0, then the initial address is list1[0] */
  for( ulong i1=(ulong)(!list0_cnt); i1<list1_cnt; i1++ ) {
    addr = wb_ldu( list1+i1 );

    wb_t y0 = wb_min( x0, wb_xor( addr, c0 ) );     wb_t y1 = wb_min( x1, wb_xor( addr, c1 ) );
    wb_t y2 = wb_min( x2, wb_xor( addr, c2 ) );     wb_t y3 = wb_min( x3, wb_xor( addr, c3 ) );
    wb_t y4 = wb_min( x4, wb_xor( addr, c4 ) );

    wb_t e0 = wb_eq( y0, x0 );                      wb_t e1 = wb_eq( y1, x1 );
    wb_t e2 = wb_eq( y2, x2 );                      wb_t e3 = wb_eq( y3, x3 );
    wb_t e4 = wb_eq( y4, x4 );

    wb_t all = wb_and( e4, wb_and( e3, wb_and( e2, wb_and( e1, e0 ) ) ) );

    x0 = y0;    x1 = y1;   x2 = y2;    x3 = y3;    x4 = y4;

    any_duplicates |= wb_all_fast( all );
    FD_COMPILER_FORGET( any_duplicates );
  }
  return any_duplicates;
}

#elif FD_PACK_CHKDUP_IMPL==2

/* AVX512 implementation */
#include "../../util/simd/fd_avx512.h"
static inline int
fd_pack_chkdup_check_duplicate_fast( fd_pack_chkdup_t     * chkdup,
                                     fd_acct_addr_t const * list0,     ulong list0_cnt,
                                     fd_acct_addr_t const * list1,     ulong list1_cnt ) {
  FD_STATIC_ASSERT( FD_PACK_CHKDUP_K==4*64, hand_unroll );

  if( FD_UNLIKELY( list0_cnt+list1_cnt<=1UL ) ) return 0UL;

  int any_duplicates = 0;

  /* There's no wwb_t, so we'll use wwu_t and intrinsics where it
     matters.  These are still bytes, not uints. */
  const wwu_t c0 = wwu_ld( chkdup->entropy         );
  const wwu_t c1 = wwu_ld( chkdup->entropy +  64UL );
  const wwu_t c2 = wwu_ld( chkdup->entropy + 128UL );
  const wwu_t c3 = wwu_ld( chkdup->entropy + 192UL );

  wwu_t addr = _mm512_broadcast_i64x4( wb_ldu( list0_cnt ? list0 : list1 ) );

  wwu_t x0 = wwu_xor( addr, c0 );                            wwu_t x1 = wwu_xor( addr, c1 );
  wwu_t x2 = wwu_xor( addr, c2 );                            wwu_t x3 = wwu_xor( addr, c3 );

  for( ulong i0=1UL; i0<list0_cnt; i0++ ) {
    addr = _mm512_broadcast_i64x4( wb_ldu( list0+i0 ) );

    wwu_t y0 = _mm512_min_epu8( x0, wwu_xor( addr, c0 ) );   wwu_t y1 = _mm512_min_epu8( x1, wwu_xor( addr, c1 ) );
    wwu_t y2 = _mm512_min_epu8( x2, wwu_xor( addr, c2 ) );   wwu_t y3 = _mm512_min_epu8( x3, wwu_xor( addr, c3 ) );

    __mmask64 m0 = _mm512_cmpeq_epu8_mask( y0, x0 );         __mmask64 m1 = _mm512_cmpeq_epu8_mask( y1, x1 );
    __mmask64 m2 = _mm512_cmpeq_epu8_mask( y2, x2 );         __mmask64 m3 = _mm512_cmpeq_epu8_mask( y3, x3 );

    __mmask64 all = _kand_mask64( m3, _kand_mask64( m2, _kand_mask64( m1, m0 ) ) );

    any_duplicates |= _kortestc_mask64_u8( all, all );
    FD_COMPILER_FORGET( any_duplicates );
  }

  for( ulong i1=(ulong)(!list0_cnt); i1<list1_cnt; i1++ ) {
    addr = _mm512_broadcast_i64x4( wb_ldu( list1+i1 ) );

    wwu_t y0 = _mm512_min_epu8( x0, wwu_xor( addr, c0 ) );   wwu_t y1 = _mm512_min_epu8( x1, wwu_xor( addr, c1 ) );
    wwu_t y2 = _mm512_min_epu8( x2, wwu_xor( addr, c2 ) );   wwu_t y3 = _mm512_min_epu8( x3, wwu_xor( addr, c3 ) );

    __mmask64 m0 = _mm512_cmpeq_epu8_mask( y0, x0 );         __mmask64 m1 = _mm512_cmpeq_epu8_mask( y1, x1 );
    __mmask64 m2 = _mm512_cmpeq_epu8_mask( y2, x2 );         __mmask64 m3 = _mm512_cmpeq_epu8_mask( y3, x3 );

    __mmask64 all = _kand_mask64( m3, _kand_mask64( m2, _kand_mask64( m1, m0 ) ) );

    any_duplicates |= _kortestc_mask64_u8( all, all );
    FD_COMPILER_FORGET( any_duplicates );
  }
  return any_duplicates;
}

#else

static inline int
fd_pack_chkdup_check_duplicate_fast( fd_pack_chkdup_t     * chkdup,
                                     fd_acct_addr_t const * list0,     ulong list0_cnt,
                                     fd_acct_addr_t const * list1,     ulong list1_cnt ) {
  return 1;
}

#endif


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_pack_fd_pack_chkdup_h */
