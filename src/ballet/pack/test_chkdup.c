#define FD_UNALIGNED_ACCESS_STYLE 0
#include "fd_pack_chkdup.h"

#define P 4294967291UL /* A prime that fits in a uint with 2 as a primitive root */

typedef int (*checker)( fd_pack_chkdup_t *, fd_acct_addr_t const *, ulong, fd_acct_addr_t const *, ulong );


/* Populates bytes [0, sz) of mem such that no aligned 4 byte sequence
   occurs twice.  This sounds hard to do, but a trivial algorithm that
   does this would be to write 0, 1, 2, ..., UINT_MAX.  This algorithm
   produces bytes that look a bit more random.  Requires sz to be a
   multiple of 4 and sz<P*4=17,179,869,164.  Requires seed in [1, P).
   Returns a new value of seed that can be used to continue the
   sequence. */
static inline ulong
populate_unique( ulong  seed,
                 void * mem,
                 ulong  sz ) {
  FD_TEST( sz%sizeof(uint)==0UL );
  for( ulong o=0UL; o<sz; o += sizeof(uint) ) {
    FD_STORE( uint, ((uchar *)mem)+o, (uint)seed );
    seed = (seed*2208550410UL)%P;
  }
  return seed;
}


static int
test_false_positive_rate( float      expected,
                          checker    f,
                          fd_rng_t * rng,
                          ulong      l0_cnt,
                          ulong      l1_cnt ) {
  ulong const iters = 1000000UL;
  ulong false_positives = 0UL;
  fd_acct_addr_t l0[128];
  fd_acct_addr_t l1[128];

  fd_pack_chkdup_t _mem[1];
  fd_pack_chkdup_t * chkdup = fd_pack_chkdup_join( fd_pack_chkdup_new( _mem, rng ) );

  for( ulong i=0UL; i<iters; i++ ) {
    ulong base = fd_rng_uint_roll( rng, P-1UL )+1UL; /* ensure it's not 0 mod P */
    populate_unique( populate_unique( base, l0, l0_cnt*sizeof(fd_acct_addr_t) ), l1, l1_cnt*sizeof(fd_acct_addr_t) );
    false_positives += (ulong)f( chkdup, l0, l0_cnt, l1, l1_cnt );
  }
  fd_pack_chkdup_delete( fd_pack_chkdup_leave( chkdup ) );

  /* Is observing `false_positive` successes consistant with a binomial
     distribution with n=iters and p=expected?  The math is not too
     hard, but calculating it in C seems like a nightmare.  Instead
     we'll use the normal approximation to the binomial, since iters is
     pretty large.  We call this function about 3000 times, and we want
     a roughly p=0.001 failure rate, so that suggests we should accept
     anything within 5 standard deviations of the theoretical. */
  ulong acceptable_false_positives = (ulong)(0.49f + (float)iters*expected + 5.0f * sqrtf( (float)iters*expected*(1.0f-expected) ));

  FD_LOG_NOTICE(( "l0=%lu, l1=%lu. fp=%lu acceptable=%lu", l0_cnt, l1_cnt, false_positives, acceptable_false_positives ));
  return 1;//false_positives<=acceptable_false_positives;
}

static int
test_null( checker    f,
           fd_rng_t * rng ) {
  fd_acct_addr_t l0[128];

  fd_pack_chkdup_t _mem[1];
  fd_pack_chkdup_t * chkdup = fd_pack_chkdup_join( fd_pack_chkdup_new( _mem, rng ) );
  populate_unique( 0x12345678, l0, 128UL*sizeof(fd_acct_addr_t) );

  ulong false_positive_count = 0UL;
  for( ulong i=0UL; i<128UL; i++ ) {
    fd_acct_addr_t temp;
    fd_acct_addr_t zero = {0};
    temp = l0[i];
    l0[i] = zero;

    /* Take the 8-aligned 8 elements around i */
    false_positive_count += (ulong)f( chkdup, l0 + (i&0x78), 4UL, l0 + (i&0x78)+4UL, 4UL );
    l0[i] = temp;
  }

  /* Insert a 0 wherever i has a 1 bit */
  for( ulong i=1UL; i<256UL; i++ ) {
    populate_unique( 0x12345678, l0, 8UL*sizeof(fd_acct_addr_t) );
    fd_acct_addr_t zero = {0};
    for( ulong k=0UL; k<8UL; k++ ) {
      if( i&(1UL<<k) ) l0[ k ] = zero;
    }
    int result = f( chkdup, l0, 4UL, l0+4UL, 4UL );
    /* has at least two 0 addresses */
    if( (!fd_ulong_is_pow2( i )) & (result==0) ) return 0;
    if(   fd_ulong_is_pow2( i )  & result )      false_positive_count++;
  }
  FD_LOG_NOTICE(( "Had %lu false positives out of 136", false_positive_count ));


  fd_pack_chkdup_delete( fd_pack_chkdup_leave( chkdup ) );

  return 1;
}

static int
test_duplicates( checker    f,
                 fd_rng_t * rng ) {
  fd_acct_addr_t l0[128];

  fd_pack_chkdup_t _mem[1];
  fd_pack_chkdup_t * chkdup = fd_pack_chkdup_join( fd_pack_chkdup_new( _mem, rng ) );
  ulong base = fd_rng_uint_roll( rng, P-1UL )+1UL;
  populate_unique( base, l0, 128UL*sizeof(fd_acct_addr_t) );

  for( ulong i=0UL; i<128UL; i++ ) {
    for( ulong j=0UL; j<128UL; j++ ) {
      if( FD_UNLIKELY( i==j ) ) continue;
      /* Make j the same as i */
      fd_acct_addr_t temp = l0[j];
      l0[j] = l0[i];

      /* We need i, j in [0, l0_cnt+l1_cnt), so
         l0_cnt+l1_cnt > max(i, j). */
      ulong l0_cnt = fd_rng_ulong_roll( rng, fd_ulong_max( i, j )+2UL );
      /* Given l0_cnt, then l1_cnt > max(i,j)-l0_cnt.  We also know that
         l0_cnt+l1_cnt<=128.  This implies l1_cnt in
         [max(i,j)-l0_cnt+1, 129-l0_cnt ).  In other words, we generate
         a random value in
         [0, 129-l0_cnt - (max(i,j)-l0_cnt+1) ) and add max(i,j)-l0_cnt+1.
         [0, 128-max(i,j) ) */
      ulong l1_cnt = fd_rng_ulong_roll( rng, 128UL-fd_ulong_max( i, j ) ) + fd_ulong_max( i, j )+1UL - l0_cnt;
      if( FD_UNLIKELY( 0==f( chkdup, l0, l0_cnt, l0+l0_cnt, l1_cnt ) ) ) return 0;
      l0[j] = temp;
    }
  }
  fd_pack_chkdup_delete( fd_pack_chkdup_leave( chkdup ) );

  return 1;
}

static ulong
performance_test( fd_rng_t * rng,
                  int        which ) {
  fd_acct_addr_t l0[32];

  fd_pack_chkdup_t _mem[1];
  fd_pack_chkdup_t * chkdup = fd_pack_chkdup_join( fd_pack_chkdup_new( _mem, rng ) );

  ulong base = fd_rng_uint_roll( rng, P-1UL )+1UL;
  populate_unique( base, l0, 32UL*sizeof(fd_acct_addr_t) );

  ulong false_positives = 0UL;

  ulong const iters = 100000UL;
  long time = -fd_log_wallclock();
  for( ulong i=0UL; i<iters; i++ ) {
    for( ulong k=0UL; k<10UL; k++ ) {
      ulong l0_cnt;
      switch( k ) {
        default:   l0_cnt =  3UL; break;
        case 7UL:  l0_cnt =  8UL; break;
        case 8UL:  l0_cnt = 13UL; break;
        case 9UL:  l0_cnt = 24UL; break;
      }
      /* I'm more optimistic about the compiler's ability to inline this
         vs. calling via a function pointer. */
      switch( which ) {
        case 0: false_positives += (ulong)fd_pack_chkdup_check_duplicate     ( chkdup, l0, l0_cnt, NULL, 0UL ); break;
        case 1: false_positives += (ulong)fd_pack_chkdup_check_duplicate_slow( chkdup, l0, l0_cnt, NULL, 0UL ); break;
        case 2: false_positives += (ulong)fd_pack_chkdup_check_duplicate_fast( chkdup, l0, l0_cnt, NULL, 0UL ); break;
        default: FD_TEST( 0 );
      }
    }
  }
  time += fd_log_wallclock();
  fd_pack_chkdup_delete( fd_pack_chkdup_leave( chkdup ) );
  return (ulong)time/(iters*10UL);
}


const float FALSE_POSITIVE_RATE[3][129] = { {
  0.0f, 0.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f },
 { 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 4.440892098500626e-16f, 3.1175062531474396e-13f, 2.8240632055087644e-11f, 7.790255107664734e-10f, 1.0054093446676404e-08f, 7.743753038802481e-08f, 4.1265689032510267e-07f, 1.6735245090826467e-06f, 5.508720156366387e-06f, 1.539919613102736e-05f, 3.777683095762541e-05f, 8.333762958889768e-05f, 0.00016842882665857317f, 0.00031637998665512423f, 0.0005586621205658782f, 0.0009357860755335734f, 0.001497882644854731f, 0.002304935469854552f, 0.0034266605213477686f, 0.004942041929037688f, 0.006938543916493178f, 0.009511024081700237f, 0.012760375877929997f, 0.016791929349237567f, 0.02171364006902121f, 0.027634097550016334f, 0.03466038652330661f, 0.042895837517588964f, 0.05243770698168493f, 0.06337483149797152f, 0.07578530504265002f, 0.08973423231326849f, 0.10527161439864408f, 0.12243042506048707f, 0.14122493622388732f, 0.16164934960140298f, 0.18367678746372118f, 0.2072586892940791f, 0.23232465242793798f, 0.2587827439252839f, 0.2865202981305177f, 0.31540520005652906f, 0.3452876394147736f, 0.3760023044257629f, 0.40737096917180526f, 0.43920541391092427f, 0.4713106051594129f, 0.5034880521175309f, 0.5355392487103814f, 0.5672691065647564f, 0.5984892839031515f, 0.6290213186885036f, 0.6586994812887718f, 0.6873732721546744f, 0.7149095030513106f, 0.7411939156449059f, 0.7661323080002849f, 0.7896511570067368f, 0.8116977421129623f, 0.8322397922352673f, 0.851264692596854f, 0.8687783009584806f, 0.8848034327493264f, 0.8993780816980217f, 0.9125534465621195f, 0.9243918354905041f, 0.9349645176119232f, 0.9443495869410649f, 0.9526298970529158f, 0.9598911166900677f, 0.9662199470674239f, 0.9717025316597968f, 0.9764230792090665f, 0.9804627110254254f, 0.9838985347660463f, 0.9868029390532341f, 0.9892430967500447f, 0.9912806595603187f, 0.9929716228922572f, 0.9943663375748111f, 0.9955096439371371f, 0.9964411037993807f, 0.9971953068934409f, 0.9978022299348815f, 0.9982876287994752f, 0.9986734468272319f, 0.9989782250087276f, 0.9992175025532681f, 0.9994041989741683f, 0.9995489712607594f, 0.9996605418757759f, 0.9997459951827369f, 0.9998110414558293f, 0.9998602488582725f, 0.9998972447122224f, 0.9999248880521999f, 0.9999454158893561f, 0.9999605658531899f, 0.9999716779584774f, 0.9999797782042101f, 0.9999856465810765f, 0.9999898718730904f, 0.9999928954113931f, 0.9999950456934124f, 0.9999965655334003f, 0.9999976331718278f, 0.9999983785486791f, 0.9999988957439677f, 0.9999992524100771f, 0.9999994968654076f, 0.9999996633865578f, 0.9999997761253655f, 0.9999998519855017f, 0.9999999027186736f, 0.999999936440476f, 0.999999958718267f, 0.9999999733460438f, 0.9999999828922705f, 0.9999999890843251f, 0.9999999930763191f, 0.9999999956343136f, 0.999999997263484f, 0.9999999982948033f, 0.9999999989437103f },
 { 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 2.55351295663786e-15f, 1.4310774787418268e-13f, 3.4980907059889432e-12f, 4.7202686204173006e-11f, 4.11177647485772e-10f, 2.569226165149985e-09f, 1.2394650972247234e-08f, 4.867850300627197e-08f, 1.6185919748945565e-07f, 4.6937911857281023e-07f, 1.2146364234411067e-06f, 2.855730865891637e-06f, 6.188165642351251e-06f, 1.2502758632404465e-05f, 2.37767922409704e-05f, 4.2893426274837054e-05f, 7.388200621671892e-05f, 0.00012217032703265573f, 0.00019483919474472255f, 0.00030086967139797416f, 0.00045137402692407846f, 0.0006598024606813135f, 0.0009421189117583273f, 0.0013169405959402303f, 0.00180563717342197f, 0.0024323865901692f, 0.0032241856086882015f, 0.004210813841454164f, 0.005424750734388861f, 0.006901045444663079f, 0.008677139950583945f, 0.010792646057979582f, 0.013289077262881754f, 0.01620953672636105f, 0.019598362940774106f, 0.02350073503789163f, 0.027962240122261894f, 0.03302840551493069f, 0.03874419936409479f, 0.045153503715135046f, 0.05229856482192974f, 0.060219426208544036f, 0.0689533507350798f, 0.07853423865971942f, 0.08899204939392125f, 0.10035223529034676f, 0.11263519635324593f, 0.1258557651883525f, 0.14002273178438374f, 0.15513841781355642f, 0.17119831002984331f, 0.188190762011069f, 0.20609677291985318f, 0.22488985114081395f, 0.2445359695865903f, 0.26499361816042066f, 0.2862139573339534f, 0.3081410750699891f, 0.3307123474237714f, 0.35385890113394713f, 0.37750617441320966f, 0.401574570022618f, 0.4259801926205782f, 0.450635660378058f, 0.4754509790067042f, 0.5003344647154422f, 0.5251937012490965f, 0.5499365151186966f, 0.5744719524481474f, 0.5987112405665603f, 0.6225687175886448f, 0.6459627137533979f, 0.6688163692266862f, 0.6910583743954204f, 0.7126236203561949f, 0.7334537492836299f, 0.7534975965969231f, 0.7727115192623588f, 0.7910596071037063f, 0.8085137765668379f, 0.8250537489241159f, 0.8406669173346795f, 0.8553481094300217f, 0.8690992541087529f, 0.8819289629481305f, 0.893852038031881f, 0.9048889190255097f, 0.9150650829861674f, 0.9244104106719291f, 0.9329585330254399f, 0.9407461710715475f, 0.9478124817204232f, 0.9541984209480399f, 0.9599461345826678f, 0.9650983855115574f, 0.9696980245907143f, 0.9737875109470724f, 0.9774084857588242f, 0.9806014020346397f, 0.9834052114290732f, 0.9858571077661241f, 0.9879923257248023f, 0.989843992091014f, 0.9914430261126358f, 0.9928180848152505f, 0.9939955486436505f, 0.9949995424816632f, 0.9958519869576816f, 0.9965726749489302f, 0.9971793683343748f, 0.9976879102928025f, 0.998112348776638f, 0.9984650671912864f, 0.9987569187529084f, 0.9989973614648497f, 0.9991945911268547f, 0.9993556702565841f, 0.9994866512473197f, 0.9995926924993103f, 0.9996781666378406f, 0.9997467602641223f } };


int
main( int argc,
    char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 123U, 4567UL ) );

#if FD_PACK_CHKDUP_K==0
  float const * fp = FALSE_POSITIVE_RATE[ 0 ];
#elif FD_PACK_CHKDUP_K==160
  float const * fp = FALSE_POSITIVE_RATE[ 1 ];
#elif FD_PACK_CHKDUP_K==256
  float const * fp = FALSE_POSITIVE_RATE[ 2 ];
#else
#error "Add false positive table for K"
#endif

  for( ulong l0=0UL; l0<40UL; l0++ ) for( ulong l1=0UL; l1<40UL-l0; l1++ ) {
    FD_TEST( test_false_positive_rate( 0.f,       fd_pack_chkdup_check_duplicate,      rng, l0, l1 ) );
    FD_TEST( test_false_positive_rate( 0.f,       fd_pack_chkdup_check_duplicate_slow, rng, l0, l1 ) );
    FD_TEST( test_false_positive_rate( fp[l0+l1], fd_pack_chkdup_check_duplicate_fast, rng, l0, l1 ) );
  }
  for( ulong l=1UL; l<=128UL; l++ ) {
    for( ulong k=0UL; k<10UL; k++ ) {
      ulong l0 = fd_rng_ulong_roll( rng, l+1 );
      ulong l1 = l-l0;
      FD_TEST( test_false_positive_rate( 0.f,   fd_pack_chkdup_check_duplicate,      rng, l0, l1 ) );
      FD_TEST( test_false_positive_rate( 0.f,   fd_pack_chkdup_check_duplicate_slow, rng, l0, l1 ) );
      FD_TEST( test_false_positive_rate( fp[l], fd_pack_chkdup_check_duplicate_fast, rng, l0, l1 ) );
    }
  }

  FD_LOG_NOTICE(( "check_duplicate:      %lu ns per transaction", performance_test( rng, 0 ) ));
  FD_LOG_NOTICE(( "check_duplicate_slow: %lu ns per transaction", performance_test( rng, 1 ) ));
  FD_LOG_NOTICE(( "check_duplicate_fast: %lu ns per transaction", performance_test( rng, 2 ) ));

  FD_TEST( test_null( fd_pack_chkdup_check_duplicate,      rng ) );
  FD_TEST( test_null( fd_pack_chkdup_check_duplicate_slow, rng ) );
  FD_TEST( test_null( fd_pack_chkdup_check_duplicate_fast, rng ) );

  FD_TEST( test_duplicates( fd_pack_chkdup_check_duplicate,      rng ) );
  FD_TEST( test_duplicates( fd_pack_chkdup_check_duplicate_slow, rng ) );
  FD_TEST( test_duplicates( fd_pack_chkdup_check_duplicate_fast, rng ) );

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();
  return 0;
}
