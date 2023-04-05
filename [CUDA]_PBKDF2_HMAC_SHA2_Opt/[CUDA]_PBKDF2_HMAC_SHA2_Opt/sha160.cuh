#include "type.cuh"

#define SHA1_F0(x,y,z)  ((z) ^ ((x) & ((y) ^ (z))))
#define SHA1_F1(x,y,z)  ((x) ^ (y) ^ (z))
#define SHA1_F2(x,y,z)  (((x) & (y)) | ((z) & ((x) ^ (y))))
#define SHA1_F0o(x,y,z) (SHA1_F0 ((x), (y), (z)))
#define SHA1_F2o(x,y,z) (SHA1_F2 ((x), (y), (z)))

#define hc_add3_S(a, b, c)	(a + b + c)
#define hc_add3(a, b, c)	(a + b + c)
#define hc_rotl32(x, n)		(((x) << (n)) | ((x) >> (32 - (n))))

#define SHA1_STEP_S(f,a,b,c,d,e,x)    \
{                                     \
  e += K;                             \
  e  = hc_add3_S (e, x, f (b, c, d)); \
  e += hc_rotl32 (a,  5u);          \
  b  = hc_rotl32 (b, 30u);          \
}

#define SHA1_STEP(f,a,b,c,d,e,x)    \
{                                   \
  e += K;                           \
  e  = hc_add3 (e, x, f (b, c, d)); \
  e += hc_rotl32 (a,  5u);          \
  b  = hc_rotl32 (b, 30u);          \
}

#define SHA1_STEPX(f,a,b,c,d,e,x)   \
{                                   \
  e  = hc_add3 (e, x, f (b, c, d)); \
  e += hc_rotl32 (a,  5u);          \
  b  = hc_rotl32 (b, 30u);          \
}

#define SHA160_BLOCK	64
#define SHA160_DIGEST	20
#define ROTL32(x, n)			(((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR32(x, n)			(((x) >> (n)) | ((x) << (32 - (n))))
#define ENDIAN_CHANGE32(X)		((ROTL32((X),  8) & 0x00ff00ff) | (ROTL32((X), 24) & 0xff00ff00))

typedef struct {
	uint32_t digest[5];
	uint64_t ptLen;
	uint8_t BUF[SHA160_BLOCK];
	uint32_t lastLen;
}SHA160_INFO;

typedef struct {
	uint32_t IPAD[5];
	uint32_t OPAD[5];
	uint64_t ptLen;
}PBKDF2_HMAC_SHA160_INFO;

//Function Part

//PBKDF2 Function Part
__global__ void PBKDF2_HMAC_SHA160_testVector_Check_Function();
void PBKDF2_HMAC_SHA160_coalesed_test(uint64_t blocksize, uint64_t threadsize);