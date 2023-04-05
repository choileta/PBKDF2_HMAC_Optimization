#include "type.cuh"

#define SHA256_DIGEST	32
#define SHA256_BLOCK	64
#define hc_add3(a, b, c)	(a + b + c)
#define hc_rotl32(x, n)		(((x) << (n)) | ((x) >> (32 - (n))))
#define SHIFT_RIGHT_32(x,n) ((x) >> (n))

#define SHA256_F0(x,y,z)	(((x) & (y)) | ((z) & ((x) ^ (y))))
#define SHA256_F1(x,y,z)	((z) ^ ((x) & ((y) ^ (z))))
#define SHA256_F0o(x,y,z) (SHA256_F0 ((x), (y), (z)))
#define SHA256_F1o(x,y,z) (SHA256_F1 ((x), (y), (z)))

#define SHA256_S0(x) (hc_rotl32 ((x), 25u) ^ hc_rotl32 ((x), 14u) ^ SHIFT_RIGHT_32 ((x),  3u))
#define SHA256_S1(x) (hc_rotl32 ((x), 15u) ^ hc_rotl32 ((x), 13u) ^ SHIFT_RIGHT_32 ((x), 10u))
#define SHA256_S2(x) (hc_rotl32 ((x), 30u) ^ hc_rotl32 ((x), 19u) ^ hc_rotl32 ((x), 10u))
#define SHA256_S3(x) (hc_rotl32 ((x), 26u) ^ hc_rotl32 ((x), 21u) ^ hc_rotl32 ((x),  7u))

#define SHA256_STEP(F0,F1,a,b,c,d,e,f,g,h,x,K)    \
{                                                 \
  h = hc_add3 (h, K, x);                          \
  h = hc_add3 (h, SHA256_S3 (e), F1 (e,f,g));     \
  d += h;                                         \
  h = hc_add3 (h, SHA256_S2 (a), F0 (a,b,c));     \
}

#define SHA256_EXPAND(x,y,z,w) (SHA256_S1 (x) + y + SHA256_S0 (z) + w)
#define ROTL32(x, n)			(((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR32(x, n)			(((x) >> (n)) | ((x) << (32 - (n))))
#define ENDIAN_CHANGE32(X)		((ROTL32((X),  8) & 0x00ff00ff) | (ROTL32((X), 24) & 0xff00ff00))

typedef struct {
	uint32_t digest[8];
	uint64_t ptLen;
	uint8_t BUF[SHA256_BLOCK];
	uint32_t lastLen;
}SHA256_INFO;

typedef struct {
	uint32_t IPAD[8];
	uint32_t OPAD[8];
	uint64_t ptLen;
}PBKDF2_HMAC_SHA256_INFO;


//Function Part
void GPU_PBKDF2_SHA256_performance_analysis(uint64_t Blocksize, uint64_t Threadsize);
void PBKDF2_HMAC_SHA256_coalesed_test();