#include "sha160.cuh"

__device__ void _SHA160_init(SHA160_INFO* info) {
	for (int i = 0; i < SHA160_BLOCK; i++)
		info->BUF[i] = 0;
	info->ptLen = 0, info->lastLen = 0;
	info->digest[0] = 0x67452301;
	info->digest[1] = 0xefcdab89;
	info->digest[2] = 0x98badcfe;
	info->digest[3] = 0x10325476;
	info->digest[4] = 0xc3d2e1f0;
}

__device__ void _SHA160_core(uint32_t* input, uint32_t* digest) {
	for (int i = 0; i < 16; i++)
		input[i] = ENDIAN_CHANGE32(input[i]);

	uint32_t w0 = input[0];
	uint32_t c_16s = hc_rotl32((input[13] ^ input[8] ^ input[2]), 1);
	uint32_t c_17s = hc_rotl32((input[14] ^ input[9] ^ input[3] ^ input[1]), 1);
	uint32_t c_18s = hc_rotl32((input[15] ^ input[10] ^ input[4] ^ input[2]), 1);
	uint32_t c_19s = hc_rotl32((c_16s ^ input[11] ^ input[5] ^ input[3]), 1);
	uint32_t c_20s = hc_rotl32((c_17s ^ input[12] ^ input[6] ^ input[4]), 1);
	uint32_t c_21s = hc_rotl32((c_18s ^ input[13] ^ input[7] ^ input[5]), 1);
	uint32_t c_22s = hc_rotl32((c_19s ^ input[14] ^ input[8] ^ input[6]), 1);
	uint32_t c_23s = hc_rotl32((c_20s ^ input[15] ^ input[9] ^ input[7]), 1);
	uint32_t c_24s = hc_rotl32((c_21s ^ c_16s ^ input[10] ^ input[8]), 1);
	uint32_t c_25s = hc_rotl32((c_22s ^ c_17s ^ input[11] ^ input[9]), 1);
	uint32_t c_26s = hc_rotl32((c_23s ^ c_18s ^ input[12] ^ input[10]), 1);
	uint32_t c_27s = hc_rotl32((c_24s ^ c_19s ^ input[13] ^ input[11]), 1);
	uint32_t c_28s = hc_rotl32((c_25s ^ c_20s ^ input[14] ^ input[12]), 1);
	uint32_t c_29s = hc_rotl32((c_26s ^ c_21s ^ input[15] ^ input[13]), 1);
	uint32_t c_30s = hc_rotl32((c_27s ^ c_22s ^ c_16s ^ input[14]), 1);

	uint32_t c_31s = hc_rotl32((c_28s ^ c_23s ^ c_17s ^ input[15]), 1u);
	uint32_t c_32s = hc_rotl32((c_29s ^ c_24s ^ c_18s ^ c_16s), 1u);
	uint32_t c_33s = hc_rotl32((c_30s ^ c_25s ^ c_19s ^ c_17s), 1u);
	uint32_t c_34s = hc_rotl32((c_31s ^ c_26s ^ c_20s ^ c_18s), 1u);
	uint32_t c_35s = hc_rotl32((c_32s ^ c_27s ^ c_21s ^ c_19s), 1u);
	uint32_t c_36s = hc_rotl32((c_33s ^ c_28s ^ c_22s ^ c_20s), 1u);
	uint32_t c_37s = hc_rotl32((c_34s ^ c_29s ^ c_23s ^ c_21s), 1u);
	uint32_t c_38s = hc_rotl32((c_35s ^ c_30s ^ c_24s ^ c_22s), 1u);
	uint32_t c_39s = hc_rotl32((c_36s ^ c_31s ^ c_25s ^ c_23s), 1u);

	uint32_t c_40s = hc_rotl32((c_37s ^ c_32s ^ c_26s ^ c_24s), 1u);
	uint32_t c_41s = hc_rotl32((c_38s ^ c_33s ^ c_27s ^ c_25s), 1u);
	uint32_t c_42s = hc_rotl32((c_39s ^ c_34s ^ c_28s ^ c_26s), 1u);
	uint32_t c_43s = hc_rotl32((c_40s ^ c_35s ^ c_29s ^ c_27s), 1u);
	uint32_t c_44s = hc_rotl32((c_41s ^ c_36s ^ c_30s ^ c_28s), 1u);
	uint32_t c_45s = hc_rotl32((c_42s ^ c_37s ^ c_31s ^ c_29s), 1u);
	uint32_t c_46s = hc_rotl32((c_43s ^ c_38s ^ c_32s ^ c_30s), 1u);
	uint32_t c_47s = hc_rotl32((c_44s ^ c_39s ^ c_33s ^ c_31s), 1u);
	uint32_t c_48s = hc_rotl32((c_45s ^ c_40s ^ c_34s ^ c_32s), 1u);
	uint32_t c_49s = hc_rotl32((c_46s ^ c_41s ^ c_35s ^ c_33s), 1u);
	uint32_t c_50s = hc_rotl32((c_47s ^ c_42s ^ c_36s ^ c_34s), 1u);
	uint32_t c_51s = hc_rotl32((c_48s ^ c_43s ^ c_37s ^ c_35s), 1u);
	uint32_t c_52s = hc_rotl32((c_49s ^ c_44s ^ c_38s ^ c_36s), 1u);
	uint32_t c_53s = hc_rotl32((c_50s ^ c_45s ^ c_39s ^ c_37s), 1u);
	uint32_t c_54s = hc_rotl32((c_51s ^ c_46s ^ c_40s ^ c_38s), 1u);
	uint32_t c_55s = hc_rotl32((c_52s ^ c_47s ^ c_41s ^ c_39s), 1u);
	uint32_t c_56s = hc_rotl32((c_53s ^ c_48s ^ c_42s ^ c_40s), 1u);
	uint32_t c_57s = hc_rotl32((c_54s ^ c_49s ^ c_43s ^ c_41s), 1u);
	uint32_t c_58s = hc_rotl32((c_55s ^ c_50s ^ c_44s ^ c_42s), 1u);
	uint32_t c_59s = hc_rotl32((c_56s ^ c_51s ^ c_45s ^ c_43s), 1u);

	uint32_t c_60s = hc_rotl32((c_57s ^ c_52s ^ c_46s ^ c_44s), 1u);
	uint32_t c_61s = hc_rotl32((c_58s ^ c_53s ^ c_47s ^ c_45s), 1u);
	uint32_t c_62s = hc_rotl32((c_59s ^ c_54s ^ c_48s ^ c_46s), 1u);
	uint32_t c_63s = hc_rotl32((c_60s ^ c_55s ^ c_49s ^ c_47s), 1u);
	uint32_t c_64s = hc_rotl32((c_61s ^ c_56s ^ c_50s ^ c_48s), 1u);
	uint32_t c_65s = hc_rotl32((c_62s ^ c_57s ^ c_51s ^ c_49s), 1u);
	uint32_t c_66s = hc_rotl32((c_63s ^ c_58s ^ c_52s ^ c_50s), 1u);
	uint32_t c_67s = hc_rotl32((c_64s ^ c_59s ^ c_53s ^ c_51s), 1u);
	uint32_t c_68s = hc_rotl32((c_65s ^ c_60s ^ c_54s ^ c_52s), 1u);
	uint32_t c_69s = hc_rotl32((c_66s ^ c_61s ^ c_55s ^ c_53s), 1u);
	uint32_t c_70s = hc_rotl32((c_67s ^ c_62s ^ c_56s ^ c_54s), 1u);
	uint32_t c_71s = hc_rotl32((c_68s ^ c_63s ^ c_57s ^ c_55s), 1u);
	uint32_t c_72s = hc_rotl32((c_69s ^ c_64s ^ c_58s ^ c_56s), 1u);
	uint32_t c_73s = hc_rotl32((c_70s ^ c_65s ^ c_59s ^ c_57s), 1u);
	uint32_t c_74s = hc_rotl32((c_71s ^ c_66s ^ c_60s ^ c_58s), 1u);
	uint32_t c_75s = hc_rotl32((c_72s ^ c_67s ^ c_61s ^ c_59s), 1u);

	uint32_t c_17sK = c_17s + 0x5a827999;
	uint32_t c_18sK = c_18s + 0x5a827999;

	uint32_t c_20sK = c_20s + 0x6ed9eba1;
	uint32_t c_21sK = c_21s + 0x6ed9eba1;
	uint32_t c_23sK = c_23s + 0x6ed9eba1;
	uint32_t c_26sK = c_26s + 0x6ed9eba1;
	uint32_t c_27sK = c_27s + 0x6ed9eba1;
	uint32_t c_29sK = c_29s + 0x6ed9eba1;
	uint32_t c_33sK = c_33s + 0x6ed9eba1;
	uint32_t c_39sK = c_39s + 0x6ed9eba1;

	uint32_t c_41sK = c_41s + 0x8f1bbcdc;
	uint32_t c_45sK = c_45s + 0x8f1bbcdc;
	uint32_t c_53sK = c_53s + 0x8f1bbcdc;

	uint32_t c_65sK = c_65s + 0xca62c1d6;
	uint32_t c_69sK = c_69s + 0xca62c1d6;

	uint32_t w0s01 = hc_rotl32(w0, 1u);
	uint32_t w0s02 = hc_rotl32(w0, 2u);
	uint32_t w0s03 = hc_rotl32(w0, 3u);
	uint32_t w0s04 = hc_rotl32(w0, 4u);
	uint32_t w0s05 = hc_rotl32(w0, 5u);
	uint32_t w0s06 = hc_rotl32(w0, 6u);
	uint32_t w0s07 = hc_rotl32(w0, 7u);
	uint32_t w0s08 = hc_rotl32(w0, 8u);
	uint32_t w0s09 = hc_rotl32(w0, 9u);
	uint32_t w0s10 = hc_rotl32(w0, 10u);
	uint32_t w0s11 = hc_rotl32(w0, 11u);
	uint32_t w0s12 = hc_rotl32(w0, 12u);
	uint32_t w0s13 = hc_rotl32(w0, 13u);
	uint32_t w0s14 = hc_rotl32(w0, 14u);
	uint32_t w0s15 = hc_rotl32(w0, 15u);
	uint32_t w0s16 = hc_rotl32(w0, 16u);
	uint32_t w0s17 = hc_rotl32(w0, 17u);
	uint32_t w0s18 = hc_rotl32(w0, 18u);
	uint32_t w0s19 = hc_rotl32(w0, 19u);
	uint32_t w0s20 = hc_rotl32(w0, 20u);

	uint32_t w0s04___w0s06 = w0s04 ^ w0s06;
	uint32_t w0s04___w0s08 = w0s04 ^ w0s08;
	uint32_t w0s08___w0s12 = w0s08 ^ w0s12;
	uint32_t w0s04___w0s06___w0s07 = w0s04___w0s06 ^ w0s07;

	uint32_t a = digest[0];
	uint32_t b = digest[1];
	uint32_t c = digest[2];
	uint32_t d = digest[3];
	uint32_t e = digest[4];

#define K  0x5a827999
	SHA1_STEP(SHA1_F0o, a, b, c, d, e, w0);
	SHA1_STEP(SHA1_F0o, e, a, b, c, d, input[1]);
	SHA1_STEP(SHA1_F0o, d, e, a, b, c, input[2]);
	SHA1_STEP(SHA1_F0o, c, d, e, a, b, input[3]);
	SHA1_STEP(SHA1_F0o, b, c, d, e, a, input[4]);
	SHA1_STEP(SHA1_F0o, a, b, c, d, e, input[5]);
	SHA1_STEP(SHA1_F0o, e, a, b, c, d, input[6]);
	SHA1_STEP(SHA1_F0o, d, e, a, b, c, input[7]);
	SHA1_STEP(SHA1_F0o, c, d, e, a, b, input[8]);
	SHA1_STEP(SHA1_F0o, b, c, d, e, a, input[9]);
	SHA1_STEP(SHA1_F0o, a, b, c, d, e, input[10]);
	SHA1_STEP(SHA1_F0o, e, a, b, c, d, input[11]);
	SHA1_STEP(SHA1_F0o, d, e, a, b, c, input[12]);
	SHA1_STEP(SHA1_F0o, c, d, e, a, b, input[13]);
	SHA1_STEP(SHA1_F0o, b, c, d, e, a, input[14]);
	SHA1_STEP(SHA1_F0o, a, b, c, d, e, input[15]);
	SHA1_STEP(SHA1_F0o, e, a, b, c, d, (c_16s ^ w0s01));
	SHA1_STEPX(SHA1_F0o, d, e, a, b, c, (c_17sK));
	SHA1_STEPX(SHA1_F0o, c, d, e, a, b, (c_18sK));
	SHA1_STEP(SHA1_F0o, b, c, d, e, a, (c_19s ^ w0s02));

#undef K
#define K 0x6ed9eba1

	SHA1_STEPX(SHA1_F1, a, b, c, d, e, (c_20sK));
	SHA1_STEPX(SHA1_F1, e, a, b, c, d, (c_21sK));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_22s ^ w0s03));
	SHA1_STEPX(SHA1_F1, c, d, e, a, b, (c_23sK));
	SHA1_STEP(SHA1_F1, b, c, d, e, a, (c_24s ^ w0s02));
	SHA1_STEP(SHA1_F1, a, b, c, d, e, (c_25s ^ w0s04));
	SHA1_STEPX(SHA1_F1, e, a, b, c, d, (c_26sK));
	SHA1_STEPX(SHA1_F1, d, e, a, b, c, (c_27sK));
	SHA1_STEP(SHA1_F1, c, d, e, a, b, (c_28s ^ w0s05));
	SHA1_STEPX(SHA1_F1, b, c, d, e, a, (c_29sK));

	SHA1_STEP(SHA1_F1, a, b, c, d, e, (c_30s ^ w0s02 ^ w0s04));
	SHA1_STEP(SHA1_F1, e, a, b, c, d, (c_31s ^ w0s06));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_32s ^ w0s02 ^ w0s03));
	SHA1_STEPX(SHA1_F1, c, d, e, a, b, (c_33sK));
	SHA1_STEP(SHA1_F1, b, c, d, e, a, (c_34s ^ w0s07));

	SHA1_STEP(SHA1_F1, a, b, c, d, e, (c_35s ^ w0s04));
	SHA1_STEP(SHA1_F1, e, a, b, c, d, (c_36s ^ w0s04___w0s06));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_37s ^ w0s08));
	SHA1_STEP(SHA1_F1, c, d, e, a, b, (c_38s ^ w0s04));
	SHA1_STEPX(SHA1_F1, b, c, d, e, a, (c_39sK));

#undef K
#define K 0x8f1bbcdc

	SHA1_STEP(SHA1_F2o, a, b, c, d, e, (c_40s ^ w0s04 ^ w0s09));
	SHA1_STEPX(SHA1_F2o, e, a, b, c, d, (c_41sK));
	SHA1_STEP(SHA1_F2o, d, e, a, b, c, (c_42s ^ w0s06 ^ w0s08));
	SHA1_STEP(SHA1_F2o, c, d, e, a, b, (c_43s ^ w0s10));
	SHA1_STEP(SHA1_F2o, b, c, d, e, a, (c_44s ^ w0s03 ^ w0s06 ^ w0s07));
	SHA1_STEPX(SHA1_F2o, a, b, c, d, e, (c_45sK));
	SHA1_STEP(SHA1_F2o, e, a, b, c, d, (c_46s ^ w0s04 ^ w0s11));
	SHA1_STEP(SHA1_F2o, d, e, a, b, c, (c_47s ^ w0s04___w0s08));
	SHA1_STEP(SHA1_F2o, c, d, e, a, b, (c_48s ^ w0s03 ^ w0s04___w0s08 ^ w0s05 ^ w0s10));
	SHA1_STEP(SHA1_F2o, b, c, d, e, a, (c_49s ^ w0s12));
	SHA1_STEP(SHA1_F2o, a, b, c, d, e, (c_50s ^ w0s08));
	SHA1_STEP(SHA1_F2o, e, a, b, c, d, (c_51s ^ w0s04___w0s06));
	SHA1_STEP(SHA1_F2o, d, e, a, b, c, (c_52s ^ w0s04___w0s08 ^ w0s13));
	SHA1_STEPX(SHA1_F2o, c, d, e, a, b, (c_53sK));
	SHA1_STEP(SHA1_F2o, b, c, d, e, a, (c_54s ^ w0s07 ^ w0s10 ^ w0s12));
	SHA1_STEP(SHA1_F2o, a, b, c, d, e, (c_55s ^ w0s14));
	SHA1_STEP(SHA1_F2o, e, a, b, c, d, (c_56s ^ w0s04___w0s06___w0s07 ^ w0s10 ^ w0s11));
	SHA1_STEP(SHA1_F2o, d, e, a, b, c, (c_57s ^ w0s08));
	SHA1_STEP(SHA1_F2o, c, d, e, a, b, (c_58s ^ w0s04___w0s08 ^ w0s15));
	SHA1_STEP(SHA1_F2o, b, c, d, e, a, (c_59s ^ w0s08___w0s12));

#undef K
#define K 0xca62c1d6

	SHA1_STEP(SHA1_F1, a, b, c, d, e, (c_60s ^ w0s04 ^ w0s08___w0s12 ^ w0s07 ^ w0s14));
	SHA1_STEP(SHA1_F1, e, a, b, c, d, (c_61s ^ w0s16));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_62s ^ w0s04___w0s06 ^ w0s08___w0s12));
	SHA1_STEP(SHA1_F1, c, d, e, a, b, (c_63s ^ w0s08));
	SHA1_STEP(SHA1_F1, b, c, d, e, a, (c_64s ^ w0s04___w0s06___w0s07 ^ w0s08___w0s12 ^ w0s17));
	SHA1_STEPX(SHA1_F1, a, b, c, d, e, (c_65sK));
	SHA1_STEP(SHA1_F1, e, a, b, c, d, (c_66s ^ w0s14 ^ w0s16));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_67s ^ w0s08 ^ w0s18));
	SHA1_STEP(SHA1_F1, c, d, e, a, b, (c_68s ^ w0s11 ^ w0s14 ^ w0s15));
	SHA1_STEPX(SHA1_F1, b, c, d, e, a, (c_69sK));
	SHA1_STEP(SHA1_F1, a, b, c, d, e, (c_70s ^ w0s12 ^ w0s19));
	SHA1_STEP(SHA1_F1, e, a, b, c, d, (c_71s ^ w0s12 ^ w0s16));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_72s ^ w0s05 ^ w0s11 ^ w0s12 ^ w0s13 ^ w0s16 ^ w0s18));
	SHA1_STEP(SHA1_F1, c, d, e, a, b, (c_73s ^ w0s20));
	SHA1_STEP(SHA1_F1, b, c, d, e, a, (c_74s ^ w0s08 ^ w0s16));
	SHA1_STEP(SHA1_F1, a, b, c, d, e, (c_75s ^ w0s06 ^ w0s12 ^ w0s14));

	uint32_t c_76s = hc_rotl32((c_73s ^ c_68s ^ c_62s ^ c_60s), 1u);
	uint32_t c_77s = hc_rotl32((c_74s ^ c_69s ^ c_63s ^ c_61s), 1u);
	uint32_t c_78s = hc_rotl32((c_75s ^ c_70s ^ c_64s ^ c_62s), 1u);
	uint32_t c_79s = hc_rotl32((c_76s ^ c_71s ^ c_65s ^ c_63s), 1u);

	uint32_t w0s21 = hc_rotl32(w0, 21u);
	uint32_t w0s22 = hc_rotl32(w0, 22U);

	SHA1_STEP(SHA1_F1, e, a, b, c, d, (c_76s ^ w0s07 ^ w0s08___w0s12 ^ w0s16 ^ w0s21));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_77s));
	SHA1_STEP(SHA1_F1, c, d, e, a, b, (c_78s ^ w0s07 ^ w0s08 ^ w0s15 ^ w0s18 ^ w0s20));
	SHA1_STEP(SHA1_F1, b, c, d, e, a, (c_79s ^ w0s08 ^ w0s22));

	digest[0] += a;
	digest[1] += b;
	digest[2] += c;
	digest[3] += d;
	digest[4] += e;
}

__device__ void _SHA160_process(uint8_t* pt, uint64_t ptLen, SHA160_INFO* info) {
	uint64_t pt_index = 0;
	while ((ptLen + info->lastLen) >= SHA160_BLOCK) {
		for (int i = info->lastLen; i < (SHA160_BLOCK - info->lastLen); i++) {
			info->BUF[i] = pt[i + pt_index];
		}
		_SHA160_core((uint32_t*)info->BUF, info->digest);
		ptLen -= (SHA160_BLOCK - info->lastLen);
		info->ptLen += (SHA160_BLOCK - info->lastLen);
		pt_index += (SHA160_BLOCK - info->lastLen);
		info->lastLen = 0;

	}
	for (int i = 0; i < ptLen; i++) {
		info->BUF[i + info->lastLen] = pt[i + pt_index];
	}
	info->lastLen += ptLen;
	pt_index = 0;
}

__device__ void _SHA160_final(SHA160_INFO* info, uint8_t* out) {
	uint64_t r = (info->lastLen) % SHA160_BLOCK;
	info->BUF[r++] = 0x80;
	if (r >= SHA160_BLOCK - 8) {
		for (uint64_t i = r; i < SHA160_BLOCK; i++)
			info->BUF[i] = 0;
		_SHA160_core((uint32_t*)info->BUF, info->digest);
		for (int i = 0; i < SHA160_BLOCK - 8; i++)
			info->BUF[i] = 0;
	}
	else {
		for (uint64_t i = r; i < SHA160_BLOCK - 8; i++)
			info->BUF[i] = 0;
	}
	((uint32_t*)info->BUF)[SHA160_BLOCK / 4 - 2] = ENDIAN_CHANGE32((info->ptLen + info->lastLen) >> 29);
	((uint32_t*)info->BUF)[SHA160_BLOCK / 4 - 1] = ENDIAN_CHANGE32((info->ptLen + info->lastLen) << 3) & 0xffffffff;
	_SHA160_core((uint32_t*)info->BUF, info->digest);

	out[0] = (info->digest[0] >> 24) & 0xff;
	out[1] = (info->digest[0] >> 16) & 0xff;
	out[2] = (info->digest[0] >> 8) & 0xff;
	out[3] = (info->digest[0]) & 0xff;

	out[4] = (info->digest[1] >> 24) & 0xff;
	out[5] = (info->digest[1] >> 16) & 0xff;
	out[6] = (info->digest[1] >> 8) & 0xff;
	out[7] = (info->digest[1]) & 0xff;

	out[8] = (info->digest[2] >> 24) & 0xff;
	out[9] = (info->digest[2] >> 16) & 0xff;
	out[10] = (info->digest[2] >> 8) & 0xff;
	out[11] = (info->digest[2]) & 0xff;

	out[12] = (info->digest[3] >> 24) & 0xff;
	out[13] = (info->digest[3] >> 16) & 0xff;
	out[14] = (info->digest[3] >> 8) & 0xff;
	out[15] = (info->digest[3]) & 0xff;

	out[16] = (info->digest[4] >> 24) & 0xff;
	out[17] = (info->digest[4] >> 16) & 0xff;
	out[18] = (info->digest[4] >> 8) & 0xff;
	out[19] = (info->digest[4]) & 0xff;
}

__device__ void _SHA160(uint8_t* pt, uint64_t ptLen, uint8_t* digest) {
	SHA160_INFO info;
	_SHA160_init(&info);
	_SHA160_process(pt, ptLen, &info);
	_SHA160_final(&info, digest);
}

__device__ void _SHA160_preCompute_core(uint32_t* input, uint32_t* digest) {
	for (int i = 0; i < 16; i++)
		input[i] = ENDIAN_CHANGE32(input[i]);

	uint32_t w0 = input[0];
	uint32_t c_16s = hc_rotl32((input[13] ^ input[8] ^ input[2]), 1);
	uint32_t c_17s = hc_rotl32((input[14] ^ input[9] ^ input[3] ^ input[1]), 1);
	uint32_t c_18s = hc_rotl32((input[15] ^ input[10] ^ input[4] ^ input[2]), 1);
	uint32_t c_19s = hc_rotl32((c_16s ^ input[11] ^ input[5] ^ input[3]), 1);
	uint32_t c_20s = hc_rotl32((c_17s ^ input[12] ^ input[6] ^ input[4]), 1);
	uint32_t c_21s = hc_rotl32((c_18s ^ input[13] ^ input[7] ^ input[5]), 1);
	uint32_t c_22s = hc_rotl32((c_19s ^ input[14] ^ input[8] ^ input[6]), 1);
	uint32_t c_23s = hc_rotl32((c_20s ^ input[15] ^ input[9] ^ input[7]), 1);
	uint32_t c_24s = hc_rotl32((c_21s ^ c_16s ^ input[10] ^ input[8]), 1);
	uint32_t c_25s = hc_rotl32((c_22s ^ c_17s ^ input[11] ^ input[9]), 1);
	uint32_t c_26s = hc_rotl32((c_23s ^ c_18s ^ input[12] ^ input[10]), 1);
	uint32_t c_27s = hc_rotl32((c_24s ^ c_19s ^ input[13] ^ input[11]), 1);
	uint32_t c_28s = hc_rotl32((c_25s ^ c_20s ^ input[14] ^ input[12]), 1);
	uint32_t c_29s = hc_rotl32((c_26s ^ c_21s ^ input[15] ^ input[13]), 1);
	uint32_t c_30s = hc_rotl32((c_27s ^ c_22s ^ c_16s ^ input[14]), 1);

	uint32_t c_31s = hc_rotl32((c_28s ^ c_23s ^ c_17s ^ input[15]), 1u);
	uint32_t c_32s = hc_rotl32((c_29s ^ c_24s ^ c_18s ^ c_16s), 1u);
	uint32_t c_33s = hc_rotl32((c_30s ^ c_25s ^ c_19s ^ c_17s), 1u);
	uint32_t c_34s = hc_rotl32((c_31s ^ c_26s ^ c_20s ^ c_18s), 1u);
	uint32_t c_35s = hc_rotl32((c_32s ^ c_27s ^ c_21s ^ c_19s), 1u);
	uint32_t c_36s = hc_rotl32((c_33s ^ c_28s ^ c_22s ^ c_20s), 1u);
	uint32_t c_37s = hc_rotl32((c_34s ^ c_29s ^ c_23s ^ c_21s), 1u);
	uint32_t c_38s = hc_rotl32((c_35s ^ c_30s ^ c_24s ^ c_22s), 1u);
	uint32_t c_39s = hc_rotl32((c_36s ^ c_31s ^ c_25s ^ c_23s), 1u);

	uint32_t c_40s = hc_rotl32((c_37s ^ c_32s ^ c_26s ^ c_24s), 1u);
	uint32_t c_41s = hc_rotl32((c_38s ^ c_33s ^ c_27s ^ c_25s), 1u);
	uint32_t c_42s = hc_rotl32((c_39s ^ c_34s ^ c_28s ^ c_26s), 1u);
	uint32_t c_43s = hc_rotl32((c_40s ^ c_35s ^ c_29s ^ c_27s), 1u);
	uint32_t c_44s = hc_rotl32((c_41s ^ c_36s ^ c_30s ^ c_28s), 1u);
	uint32_t c_45s = hc_rotl32((c_42s ^ c_37s ^ c_31s ^ c_29s), 1u);
	uint32_t c_46s = hc_rotl32((c_43s ^ c_38s ^ c_32s ^ c_30s), 1u);
	uint32_t c_47s = hc_rotl32((c_44s ^ c_39s ^ c_33s ^ c_31s), 1u);
	uint32_t c_48s = hc_rotl32((c_45s ^ c_40s ^ c_34s ^ c_32s), 1u);
	uint32_t c_49s = hc_rotl32((c_46s ^ c_41s ^ c_35s ^ c_33s), 1u);
	uint32_t c_50s = hc_rotl32((c_47s ^ c_42s ^ c_36s ^ c_34s), 1u);
	uint32_t c_51s = hc_rotl32((c_48s ^ c_43s ^ c_37s ^ c_35s), 1u);
	uint32_t c_52s = hc_rotl32((c_49s ^ c_44s ^ c_38s ^ c_36s), 1u);
	uint32_t c_53s = hc_rotl32((c_50s ^ c_45s ^ c_39s ^ c_37s), 1u);
	uint32_t c_54s = hc_rotl32((c_51s ^ c_46s ^ c_40s ^ c_38s), 1u);
	uint32_t c_55s = hc_rotl32((c_52s ^ c_47s ^ c_41s ^ c_39s), 1u);
	uint32_t c_56s = hc_rotl32((c_53s ^ c_48s ^ c_42s ^ c_40s), 1u);
	uint32_t c_57s = hc_rotl32((c_54s ^ c_49s ^ c_43s ^ c_41s), 1u);
	uint32_t c_58s = hc_rotl32((c_55s ^ c_50s ^ c_44s ^ c_42s), 1u);
	uint32_t c_59s = hc_rotl32((c_56s ^ c_51s ^ c_45s ^ c_43s), 1u);

	uint32_t c_60s = hc_rotl32((c_57s ^ c_52s ^ c_46s ^ c_44s), 1u);
	uint32_t c_61s = hc_rotl32((c_58s ^ c_53s ^ c_47s ^ c_45s), 1u);
	uint32_t c_62s = hc_rotl32((c_59s ^ c_54s ^ c_48s ^ c_46s), 1u);
	uint32_t c_63s = hc_rotl32((c_60s ^ c_55s ^ c_49s ^ c_47s), 1u);
	uint32_t c_64s = hc_rotl32((c_61s ^ c_56s ^ c_50s ^ c_48s), 1u);
	uint32_t c_65s = hc_rotl32((c_62s ^ c_57s ^ c_51s ^ c_49s), 1u);
	uint32_t c_66s = hc_rotl32((c_63s ^ c_58s ^ c_52s ^ c_50s), 1u);
	uint32_t c_67s = hc_rotl32((c_64s ^ c_59s ^ c_53s ^ c_51s), 1u);
	uint32_t c_68s = hc_rotl32((c_65s ^ c_60s ^ c_54s ^ c_52s), 1u);
	uint32_t c_69s = hc_rotl32((c_66s ^ c_61s ^ c_55s ^ c_53s), 1u);
	uint32_t c_70s = hc_rotl32((c_67s ^ c_62s ^ c_56s ^ c_54s), 1u);
	uint32_t c_71s = hc_rotl32((c_68s ^ c_63s ^ c_57s ^ c_55s), 1u);
	uint32_t c_72s = hc_rotl32((c_69s ^ c_64s ^ c_58s ^ c_56s), 1u);
	uint32_t c_73s = hc_rotl32((c_70s ^ c_65s ^ c_59s ^ c_57s), 1u);
	uint32_t c_74s = hc_rotl32((c_71s ^ c_66s ^ c_60s ^ c_58s), 1u);
	uint32_t c_75s = hc_rotl32((c_72s ^ c_67s ^ c_61s ^ c_59s), 1u);

	uint32_t c_17sK = c_17s + 0x5a827999;
	uint32_t c_18sK = c_18s + 0x5a827999;

	uint32_t c_20sK = c_20s + 0x6ed9eba1;
	uint32_t c_21sK = c_21s + 0x6ed9eba1;
	uint32_t c_23sK = c_23s + 0x6ed9eba1;
	uint32_t c_26sK = c_26s + 0x6ed9eba1;
	uint32_t c_27sK = c_27s + 0x6ed9eba1;
	uint32_t c_29sK = c_29s + 0x6ed9eba1;
	uint32_t c_33sK = c_33s + 0x6ed9eba1;
	uint32_t c_39sK = c_39s + 0x6ed9eba1;

	uint32_t c_41sK = c_41s + 0x8f1bbcdc;
	uint32_t c_45sK = c_45s + 0x8f1bbcdc;
	uint32_t c_53sK = c_53s + 0x8f1bbcdc;

	uint32_t c_65sK = c_65s + 0xca62c1d6;
	uint32_t c_69sK = c_69s + 0xca62c1d6;

	uint32_t w0s01 = hc_rotl32(w0, 1u);
	uint32_t w0s02 = hc_rotl32(w0, 2u);
	uint32_t w0s03 = hc_rotl32(w0, 3u);
	uint32_t w0s04 = hc_rotl32(w0, 4u);
	uint32_t w0s05 = hc_rotl32(w0, 5u);
	uint32_t w0s06 = hc_rotl32(w0, 6u);
	uint32_t w0s07 = hc_rotl32(w0, 7u);
	uint32_t w0s08 = hc_rotl32(w0, 8u);
	uint32_t w0s09 = hc_rotl32(w0, 9u);
	uint32_t w0s10 = hc_rotl32(w0, 10u);
	uint32_t w0s11 = hc_rotl32(w0, 11u);
	uint32_t w0s12 = hc_rotl32(w0, 12u);
	uint32_t w0s13 = hc_rotl32(w0, 13u);
	uint32_t w0s14 = hc_rotl32(w0, 14u);
	uint32_t w0s15 = hc_rotl32(w0, 15u);
	uint32_t w0s16 = hc_rotl32(w0, 16u);
	uint32_t w0s17 = hc_rotl32(w0, 17u);
	uint32_t w0s18 = hc_rotl32(w0, 18u);
	uint32_t w0s19 = hc_rotl32(w0, 19u);
	uint32_t w0s20 = hc_rotl32(w0, 20u);

	uint32_t w0s04___w0s06 = w0s04 ^ w0s06;
	uint32_t w0s04___w0s08 = w0s04 ^ w0s08;
	uint32_t w0s08___w0s12 = w0s08 ^ w0s12;
	uint32_t w0s04___w0s06___w0s07 = w0s04___w0s06 ^ w0s07;

	uint32_t a = 0x67452301;
	uint32_t b = 0xefcdab89;
	uint32_t c = 0x98badcfe;
	uint32_t d = 0x10325476;
	uint32_t e = 0xc3d2e1f0;

#define K  0x5a827999
	SHA1_STEP(SHA1_F0o, a, b, c, d, e, w0);
	SHA1_STEP(SHA1_F0o, e, a, b, c, d, input[1]);
	SHA1_STEP(SHA1_F0o, d, e, a, b, c, input[2]);
	SHA1_STEP(SHA1_F0o, c, d, e, a, b, input[3]);
	SHA1_STEP(SHA1_F0o, b, c, d, e, a, input[4]);
	SHA1_STEP(SHA1_F0o, a, b, c, d, e, input[5]);
	SHA1_STEP(SHA1_F0o, e, a, b, c, d, input[6]);
	SHA1_STEP(SHA1_F0o, d, e, a, b, c, input[7]);
	SHA1_STEP(SHA1_F0o, c, d, e, a, b, input[8]);
	SHA1_STEP(SHA1_F0o, b, c, d, e, a, input[9]);
	SHA1_STEP(SHA1_F0o, a, b, c, d, e, input[10]);
	SHA1_STEP(SHA1_F0o, e, a, b, c, d, input[11]);
	SHA1_STEP(SHA1_F0o, d, e, a, b, c, input[12]);
	SHA1_STEP(SHA1_F0o, c, d, e, a, b, input[13]);
	SHA1_STEP(SHA1_F0o, b, c, d, e, a, input[14]);
	SHA1_STEP(SHA1_F0o, a, b, c, d, e, input[15]);
	SHA1_STEP(SHA1_F0o, e, a, b, c, d, (c_16s ^ w0s01));
	SHA1_STEPX(SHA1_F0o, d, e, a, b, c, (c_17sK));
	SHA1_STEPX(SHA1_F0o, c, d, e, a, b, (c_18sK));
	SHA1_STEP(SHA1_F0o, b, c, d, e, a, (c_19s ^ w0s02));

#undef K
#define K 0x6ed9eba1

	SHA1_STEPX(SHA1_F1, a, b, c, d, e, (c_20sK));
	SHA1_STEPX(SHA1_F1, e, a, b, c, d, (c_21sK));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_22s ^ w0s03));
	SHA1_STEPX(SHA1_F1, c, d, e, a, b, (c_23sK));
	SHA1_STEP(SHA1_F1, b, c, d, e, a, (c_24s ^ w0s02));
	SHA1_STEP(SHA1_F1, a, b, c, d, e, (c_25s ^ w0s04));
	SHA1_STEPX(SHA1_F1, e, a, b, c, d, (c_26sK));
	SHA1_STEPX(SHA1_F1, d, e, a, b, c, (c_27sK));
	SHA1_STEP(SHA1_F1, c, d, e, a, b, (c_28s ^ w0s05));
	SHA1_STEPX(SHA1_F1, b, c, d, e, a, (c_29sK));

	SHA1_STEP(SHA1_F1, a, b, c, d, e, (c_30s ^ w0s02 ^ w0s04));
	SHA1_STEP(SHA1_F1, e, a, b, c, d, (c_31s ^ w0s06));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_32s ^ w0s02 ^ w0s03));
	SHA1_STEPX(SHA1_F1, c, d, e, a, b, (c_33sK));
	SHA1_STEP(SHA1_F1, b, c, d, e, a, (c_34s ^ w0s07));

	SHA1_STEP(SHA1_F1, a, b, c, d, e, (c_35s ^ w0s04));
	SHA1_STEP(SHA1_F1, e, a, b, c, d, (c_36s ^ w0s04___w0s06));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_37s ^ w0s08));
	SHA1_STEP(SHA1_F1, c, d, e, a, b, (c_38s ^ w0s04));
	SHA1_STEPX(SHA1_F1, b, c, d, e, a, (c_39sK));

#undef K
#define K 0x8f1bbcdc

	SHA1_STEP(SHA1_F2o, a, b, c, d, e, (c_40s ^ w0s04 ^ w0s09));
	SHA1_STEPX(SHA1_F2o, e, a, b, c, d, (c_41sK));
	SHA1_STEP(SHA1_F2o, d, e, a, b, c, (c_42s ^ w0s06 ^ w0s08));
	SHA1_STEP(SHA1_F2o, c, d, e, a, b, (c_43s ^ w0s10));
	SHA1_STEP(SHA1_F2o, b, c, d, e, a, (c_44s ^ w0s03 ^ w0s06 ^ w0s07));
	SHA1_STEPX(SHA1_F2o, a, b, c, d, e, (c_45sK));
	SHA1_STEP(SHA1_F2o, e, a, b, c, d, (c_46s ^ w0s04 ^ w0s11));
	SHA1_STEP(SHA1_F2o, d, e, a, b, c, (c_47s ^ w0s04___w0s08));
	SHA1_STEP(SHA1_F2o, c, d, e, a, b, (c_48s ^ w0s03 ^ w0s04___w0s08 ^ w0s05 ^ w0s10));
	SHA1_STEP(SHA1_F2o, b, c, d, e, a, (c_49s ^ w0s12));
	SHA1_STEP(SHA1_F2o, a, b, c, d, e, (c_50s ^ w0s08));
	SHA1_STEP(SHA1_F2o, e, a, b, c, d, (c_51s ^ w0s04___w0s06));
	SHA1_STEP(SHA1_F2o, d, e, a, b, c, (c_52s ^ w0s04___w0s08 ^ w0s13));
	SHA1_STEPX(SHA1_F2o, c, d, e, a, b, (c_53sK));
	SHA1_STEP(SHA1_F2o, b, c, d, e, a, (c_54s ^ w0s07 ^ w0s10 ^ w0s12));
	SHA1_STEP(SHA1_F2o, a, b, c, d, e, (c_55s ^ w0s14));
	SHA1_STEP(SHA1_F2o, e, a, b, c, d, (c_56s ^ w0s04___w0s06___w0s07 ^ w0s10 ^ w0s11));
	SHA1_STEP(SHA1_F2o, d, e, a, b, c, (c_57s ^ w0s08));
	SHA1_STEP(SHA1_F2o, c, d, e, a, b, (c_58s ^ w0s04___w0s08 ^ w0s15));
	SHA1_STEP(SHA1_F2o, b, c, d, e, a, (c_59s ^ w0s08___w0s12));

#undef K
#define K 0xca62c1d6

	SHA1_STEP(SHA1_F1, a, b, c, d, e, (c_60s ^ w0s04 ^ w0s08___w0s12 ^ w0s07 ^ w0s14));
	SHA1_STEP(SHA1_F1, e, a, b, c, d, (c_61s ^ w0s16));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_62s ^ w0s04___w0s06 ^ w0s08___w0s12));
	SHA1_STEP(SHA1_F1, c, d, e, a, b, (c_63s ^ w0s08));
	SHA1_STEP(SHA1_F1, b, c, d, e, a, (c_64s ^ w0s04___w0s06___w0s07 ^ w0s08___w0s12 ^ w0s17));
	SHA1_STEPX(SHA1_F1, a, b, c, d, e, (c_65sK));
	SHA1_STEP(SHA1_F1, e, a, b, c, d, (c_66s ^ w0s14 ^ w0s16));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_67s ^ w0s08 ^ w0s18));
	SHA1_STEP(SHA1_F1, c, d, e, a, b, (c_68s ^ w0s11 ^ w0s14 ^ w0s15));
	SHA1_STEPX(SHA1_F1, b, c, d, e, a, (c_69sK));
	SHA1_STEP(SHA1_F1, a, b, c, d, e, (c_70s ^ w0s12 ^ w0s19));
	SHA1_STEP(SHA1_F1, e, a, b, c, d, (c_71s ^ w0s12 ^ w0s16));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_72s ^ w0s05 ^ w0s11 ^ w0s12 ^ w0s13 ^ w0s16 ^ w0s18));
	SHA1_STEP(SHA1_F1, c, d, e, a, b, (c_73s ^ w0s20));
	SHA1_STEP(SHA1_F1, b, c, d, e, a, (c_74s ^ w0s08 ^ w0s16));
	SHA1_STEP(SHA1_F1, a, b, c, d, e, (c_75s ^ w0s06 ^ w0s12 ^ w0s14));

	uint32_t c_76s = hc_rotl32((c_73s ^ c_68s ^ c_62s ^ c_60s), 1u);
	uint32_t c_77s = hc_rotl32((c_74s ^ c_69s ^ c_63s ^ c_61s), 1u);
	uint32_t c_78s = hc_rotl32((c_75s ^ c_70s ^ c_64s ^ c_62s), 1u);
	uint32_t c_79s = hc_rotl32((c_76s ^ c_71s ^ c_65s ^ c_63s), 1u);

	uint32_t w0s21 = hc_rotl32(w0, 21u);
	uint32_t w0s22 = hc_rotl32(w0, 22U);

	SHA1_STEP(SHA1_F1, e, a, b, c, d, (c_76s ^ w0s07 ^ w0s08___w0s12 ^ w0s16 ^ w0s21));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_77s));
	SHA1_STEP(SHA1_F1, c, d, e, a, b, (c_78s ^ w0s07 ^ w0s08 ^ w0s15 ^ w0s18 ^ w0s20));
	SHA1_STEP(SHA1_F1, b, c, d, e, a, (c_79s ^ w0s08 ^ w0s22));

	digest[0] = a + 0x67452301;
	digest[1] = b + 0xefcdab89;
	digest[2] = c + 0x98badcfe;
	digest[3] = d + 0x10325476;
	digest[4] = e + 0xc3d2e1f0;
}

__device__ void _SHA160_salt_compute_final(SHA160_INFO* info, uint32_t* out) {
	uint64_t r = (info->lastLen) % SHA160_BLOCK;
	info->BUF[r++] = 0x80;
	if (r >= SHA160_BLOCK - 8) {
		for (uint64_t i = r; i < SHA160_BLOCK; i++)
			info->BUF[i] = 0;
		_SHA160_core((uint32_t*)info->BUF, info->digest);
		for (int i = 0; i < SHA160_BLOCK - 8; i++)
			info->BUF[i] = 0;
	}
	else {
		for (uint64_t i = r; i < SHA160_BLOCK - 8; i++)
			info->BUF[i] = 0;
	}
	((uint32_t*)info->BUF)[SHA160_BLOCK / 4 - 2] = ENDIAN_CHANGE32((info->ptLen + info->lastLen) >> 29);
	((uint32_t*)info->BUF)[SHA160_BLOCK / 4 - 1] = ENDIAN_CHANGE32((info->ptLen + info->lastLen) << 3) & 0xffffffff;
	_SHA160_core((uint32_t*)info->BUF, info->digest);

	out[0] = ((info->digest[0]));
	out[1] = (info->digest[1]);
	out[2] = (info->digest[2]);
	out[3] = (info->digest[3]);
	out[4] = (info->digest[4]);
}

__device__ void _PBKDF2_HMAC_SHA160_precompute(uint8_t* pt, uint8_t ptLen, PBKDF2_HMAC_SHA160_INFO* info) {
	uint8_t K1[SHA160_BLOCK];
	uint8_t K2[SHA160_BLOCK];

	for (int i = 0; i < ptLen; i++) {
		K1[i] = 0x36 ^ pt[i];
		K2[i] = 0x5c ^ pt[i];
	}
	for (int i = ptLen; i < SHA160_BLOCK; i++) {
		K1[i] = 0x36;
		K2[i] = 0x5c;
	}
	_SHA160_preCompute_core((uint32_t*)K1, info->IPAD);
	_SHA160_preCompute_core((uint32_t*)K2, info->OPAD);
}

__device__ void _PBKDF2_HMAC_SHA160_salt_compute(uint8_t* salt, uint64_t saLen, uint32_t integer, PBKDF2_HMAC_SHA160_INFO* INFO, uint32_t* out) {
	SHA160_INFO info;
	uint8_t temp[4] = { (integer >> 24) & 0xff, (integer >> 16) & 0xff, (integer >> 8) & 0xff, (integer & 0xff) };

	info.digest[0] = INFO->IPAD[0];
	info.digest[1] = INFO->IPAD[1];
	info.digest[2] = INFO->IPAD[2];
	info.digest[3] = INFO->IPAD[3];
	info.digest[4] = INFO->IPAD[4];
	info.ptLen = 64;
	info.lastLen = 0;
	_SHA160_process(salt, saLen, &info);
	_SHA160_process(temp, 4, &info);
	_SHA160_salt_compute_final(&info, out);
}

__device__ void _PBKDF2_HMAC_SHA160_core_final(uint32_t* _prestate, uint32_t* digest, const uint32_t* in) {

	uint32_t input[16];
	input[0] = in[0];
	input[1] = in[1];
	input[2] = in[2];
	input[3] = in[3];
	input[4] = in[4];
	input[5] = 0x80000000;
	input[6] = 0;
	input[7] = 0;
	input[8] = 0;
	input[9] = 0;
	input[10] = 0;
	input[11] = 0;
	input[12] = 0;
	input[13] = 0;
	input[14] = 0;
	input[15] = (64 + 20) << 3;

	uint32_t w0 = input[0];
	uint32_t c_16s = hc_rotl32((input[13] ^ input[8] ^ input[2]), 1);
	uint32_t c_17s = hc_rotl32((input[14] ^ input[9] ^ input[3] ^ input[1]), 1);
	uint32_t c_18s = hc_rotl32((input[15] ^ input[10] ^ input[4] ^ input[2]), 1);
	uint32_t c_19s = hc_rotl32((c_16s ^ input[11] ^ input[5] ^ input[3]), 1);
	uint32_t c_20s = hc_rotl32((c_17s ^ input[12] ^ input[6] ^ input[4]), 1);
	uint32_t c_21s = hc_rotl32((c_18s ^ input[13] ^ input[7] ^ input[5]), 1);
	uint32_t c_22s = hc_rotl32((c_19s ^ input[14] ^ input[8] ^ input[6]), 1);
	uint32_t c_23s = hc_rotl32((c_20s ^ input[15] ^ input[9] ^ input[7]), 1);
	uint32_t c_24s = hc_rotl32((c_21s ^ c_16s ^ input[10] ^ input[8]), 1);
	uint32_t c_25s = hc_rotl32((c_22s ^ c_17s ^ input[11] ^ input[9]), 1);
	uint32_t c_26s = hc_rotl32((c_23s ^ c_18s ^ input[12] ^ input[10]), 1);
	uint32_t c_27s = hc_rotl32((c_24s ^ c_19s ^ input[13] ^ input[11]), 1);
	uint32_t c_28s = hc_rotl32((c_25s ^ c_20s ^ input[14] ^ input[12]), 1);
	uint32_t c_29s = hc_rotl32((c_26s ^ c_21s ^ input[15] ^ input[13]), 1);
	uint32_t c_30s = hc_rotl32((c_27s ^ c_22s ^ c_16s ^ input[14]), 1);

	uint32_t c_31s = hc_rotl32((c_28s ^ c_23s ^ c_17s ^ input[15]), 1u);
	uint32_t c_32s = hc_rotl32((c_29s ^ c_24s ^ c_18s ^ c_16s), 1u);
	uint32_t c_33s = hc_rotl32((c_30s ^ c_25s ^ c_19s ^ c_17s), 1u);
	uint32_t c_34s = hc_rotl32((c_31s ^ c_26s ^ c_20s ^ c_18s), 1u);
	uint32_t c_35s = hc_rotl32((c_32s ^ c_27s ^ c_21s ^ c_19s), 1u);
	uint32_t c_36s = hc_rotl32((c_33s ^ c_28s ^ c_22s ^ c_20s), 1u);
	uint32_t c_37s = hc_rotl32((c_34s ^ c_29s ^ c_23s ^ c_21s), 1u);
	uint32_t c_38s = hc_rotl32((c_35s ^ c_30s ^ c_24s ^ c_22s), 1u);
	uint32_t c_39s = hc_rotl32((c_36s ^ c_31s ^ c_25s ^ c_23s), 1u);

	uint32_t c_40s = hc_rotl32((c_37s ^ c_32s ^ c_26s ^ c_24s), 1u);
	uint32_t c_41s = hc_rotl32((c_38s ^ c_33s ^ c_27s ^ c_25s), 1u);
	uint32_t c_42s = hc_rotl32((c_39s ^ c_34s ^ c_28s ^ c_26s), 1u);
	uint32_t c_43s = hc_rotl32((c_40s ^ c_35s ^ c_29s ^ c_27s), 1u);
	uint32_t c_44s = hc_rotl32((c_41s ^ c_36s ^ c_30s ^ c_28s), 1u);
	uint32_t c_45s = hc_rotl32((c_42s ^ c_37s ^ c_31s ^ c_29s), 1u);
	uint32_t c_46s = hc_rotl32((c_43s ^ c_38s ^ c_32s ^ c_30s), 1u);
	uint32_t c_47s = hc_rotl32((c_44s ^ c_39s ^ c_33s ^ c_31s), 1u);
	uint32_t c_48s = hc_rotl32((c_45s ^ c_40s ^ c_34s ^ c_32s), 1u);
	uint32_t c_49s = hc_rotl32((c_46s ^ c_41s ^ c_35s ^ c_33s), 1u);
	uint32_t c_50s = hc_rotl32((c_47s ^ c_42s ^ c_36s ^ c_34s), 1u);
	uint32_t c_51s = hc_rotl32((c_48s ^ c_43s ^ c_37s ^ c_35s), 1u);
	uint32_t c_52s = hc_rotl32((c_49s ^ c_44s ^ c_38s ^ c_36s), 1u);
	uint32_t c_53s = hc_rotl32((c_50s ^ c_45s ^ c_39s ^ c_37s), 1u);
	uint32_t c_54s = hc_rotl32((c_51s ^ c_46s ^ c_40s ^ c_38s), 1u);
	uint32_t c_55s = hc_rotl32((c_52s ^ c_47s ^ c_41s ^ c_39s), 1u);
	uint32_t c_56s = hc_rotl32((c_53s ^ c_48s ^ c_42s ^ c_40s), 1u);
	uint32_t c_57s = hc_rotl32((c_54s ^ c_49s ^ c_43s ^ c_41s), 1u);
	uint32_t c_58s = hc_rotl32((c_55s ^ c_50s ^ c_44s ^ c_42s), 1u);
	uint32_t c_59s = hc_rotl32((c_56s ^ c_51s ^ c_45s ^ c_43s), 1u);

	uint32_t c_60s = hc_rotl32((c_57s ^ c_52s ^ c_46s ^ c_44s), 1u);
	uint32_t c_61s = hc_rotl32((c_58s ^ c_53s ^ c_47s ^ c_45s), 1u);
	uint32_t c_62s = hc_rotl32((c_59s ^ c_54s ^ c_48s ^ c_46s), 1u);
	uint32_t c_63s = hc_rotl32((c_60s ^ c_55s ^ c_49s ^ c_47s), 1u);
	uint32_t c_64s = hc_rotl32((c_61s ^ c_56s ^ c_50s ^ c_48s), 1u);
	uint32_t c_65s = hc_rotl32((c_62s ^ c_57s ^ c_51s ^ c_49s), 1u);
	uint32_t c_66s = hc_rotl32((c_63s ^ c_58s ^ c_52s ^ c_50s), 1u);
	uint32_t c_67s = hc_rotl32((c_64s ^ c_59s ^ c_53s ^ c_51s), 1u);
	uint32_t c_68s = hc_rotl32((c_65s ^ c_60s ^ c_54s ^ c_52s), 1u);
	uint32_t c_69s = hc_rotl32((c_66s ^ c_61s ^ c_55s ^ c_53s), 1u);
	uint32_t c_70s = hc_rotl32((c_67s ^ c_62s ^ c_56s ^ c_54s), 1u);
	uint32_t c_71s = hc_rotl32((c_68s ^ c_63s ^ c_57s ^ c_55s), 1u);
	uint32_t c_72s = hc_rotl32((c_69s ^ c_64s ^ c_58s ^ c_56s), 1u);
	uint32_t c_73s = hc_rotl32((c_70s ^ c_65s ^ c_59s ^ c_57s), 1u);
	uint32_t c_74s = hc_rotl32((c_71s ^ c_66s ^ c_60s ^ c_58s), 1u);
	uint32_t c_75s = hc_rotl32((c_72s ^ c_67s ^ c_61s ^ c_59s), 1u);

	uint32_t c_17sK = c_17s + 0x5a827999;
	uint32_t c_18sK = c_18s + 0x5a827999;

	uint32_t c_20sK = c_20s + 0x6ed9eba1;
	uint32_t c_21sK = c_21s + 0x6ed9eba1;
	uint32_t c_23sK = c_23s + 0x6ed9eba1;
	uint32_t c_26sK = c_26s + 0x6ed9eba1;
	uint32_t c_27sK = c_27s + 0x6ed9eba1;
	uint32_t c_29sK = c_29s + 0x6ed9eba1;
	uint32_t c_33sK = c_33s + 0x6ed9eba1;
	uint32_t c_39sK = c_39s + 0x6ed9eba1;

	uint32_t c_41sK = c_41s + 0x8f1bbcdc;
	uint32_t c_45sK = c_45s + 0x8f1bbcdc;
	uint32_t c_53sK = c_53s + 0x8f1bbcdc;

	uint32_t c_65sK = c_65s + 0xca62c1d6;
	uint32_t c_69sK = c_69s + 0xca62c1d6;

	uint32_t w0s01 = hc_rotl32(w0, 1u);
	uint32_t w0s02 = hc_rotl32(w0, 2u);
	uint32_t w0s03 = hc_rotl32(w0, 3u);
	uint32_t w0s04 = hc_rotl32(w0, 4u);
	uint32_t w0s05 = hc_rotl32(w0, 5u);
	uint32_t w0s06 = hc_rotl32(w0, 6u);
	uint32_t w0s07 = hc_rotl32(w0, 7u);
	uint32_t w0s08 = hc_rotl32(w0, 8u);
	uint32_t w0s09 = hc_rotl32(w0, 9u);
	uint32_t w0s10 = hc_rotl32(w0, 10u);
	uint32_t w0s11 = hc_rotl32(w0, 11u);
	uint32_t w0s12 = hc_rotl32(w0, 12u);
	uint32_t w0s13 = hc_rotl32(w0, 13u);
	uint32_t w0s14 = hc_rotl32(w0, 14u);
	uint32_t w0s15 = hc_rotl32(w0, 15u);
	uint32_t w0s16 = hc_rotl32(w0, 16u);
	uint32_t w0s17 = hc_rotl32(w0, 17u);
	uint32_t w0s18 = hc_rotl32(w0, 18u);
	uint32_t w0s19 = hc_rotl32(w0, 19u);
	uint32_t w0s20 = hc_rotl32(w0, 20u);

	uint32_t w0s04___w0s06 = w0s04 ^ w0s06;
	uint32_t w0s04___w0s08 = w0s04 ^ w0s08;
	uint32_t w0s08___w0s12 = w0s08 ^ w0s12;
	uint32_t w0s04___w0s06___w0s07 = w0s04___w0s06 ^ w0s07;

	uint32_t a = _prestate[0];
	uint32_t b = _prestate[1];
	uint32_t c = _prestate[2];
	uint32_t d = _prestate[3];
	uint32_t e = _prestate[4];

#define K  0x5a827999
	SHA1_STEP(SHA1_F0o, a, b, c, d, e, w0);
	SHA1_STEP(SHA1_F0o, e, a, b, c, d, input[1]);
	SHA1_STEP(SHA1_F0o, d, e, a, b, c, input[2]);
	SHA1_STEP(SHA1_F0o, c, d, e, a, b, input[3]);
	SHA1_STEP(SHA1_F0o, b, c, d, e, a, input[4]);
	SHA1_STEP(SHA1_F0o, a, b, c, d, e, input[5]);
	SHA1_STEP(SHA1_F0o, e, a, b, c, d, input[6]);
	SHA1_STEP(SHA1_F0o, d, e, a, b, c, input[7]);
	SHA1_STEP(SHA1_F0o, c, d, e, a, b, input[8]);
	SHA1_STEP(SHA1_F0o, b, c, d, e, a, input[9]);
	SHA1_STEP(SHA1_F0o, a, b, c, d, e, input[10]);
	SHA1_STEP(SHA1_F0o, e, a, b, c, d, input[11]);
	SHA1_STEP(SHA1_F0o, d, e, a, b, c, input[12]);
	SHA1_STEP(SHA1_F0o, c, d, e, a, b, input[13]);
	SHA1_STEP(SHA1_F0o, b, c, d, e, a, input[14]);
	SHA1_STEP(SHA1_F0o, a, b, c, d, e, input[15]);
	SHA1_STEP(SHA1_F0o, e, a, b, c, d, (c_16s ^ w0s01));
	SHA1_STEPX(SHA1_F0o, d, e, a, b, c, (c_17sK));
	SHA1_STEPX(SHA1_F0o, c, d, e, a, b, (c_18sK));
	SHA1_STEP(SHA1_F0o, b, c, d, e, a, (c_19s ^ w0s02));

#undef K
#define K 0x6ed9eba1

	SHA1_STEPX(SHA1_F1, a, b, c, d, e, (c_20sK));
	SHA1_STEPX(SHA1_F1, e, a, b, c, d, (c_21sK));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_22s ^ w0s03));
	SHA1_STEPX(SHA1_F1, c, d, e, a, b, (c_23sK));
	SHA1_STEP(SHA1_F1, b, c, d, e, a, (c_24s ^ w0s02));
	SHA1_STEP(SHA1_F1, a, b, c, d, e, (c_25s ^ w0s04));
	SHA1_STEPX(SHA1_F1, e, a, b, c, d, (c_26sK));
	SHA1_STEPX(SHA1_F1, d, e, a, b, c, (c_27sK));
	SHA1_STEP(SHA1_F1, c, d, e, a, b, (c_28s ^ w0s05));
	SHA1_STEPX(SHA1_F1, b, c, d, e, a, (c_29sK));

	SHA1_STEP(SHA1_F1, a, b, c, d, e, (c_30s ^ w0s02 ^ w0s04));
	SHA1_STEP(SHA1_F1, e, a, b, c, d, (c_31s ^ w0s06));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_32s ^ w0s02 ^ w0s03));
	SHA1_STEPX(SHA1_F1, c, d, e, a, b, (c_33sK));
	SHA1_STEP(SHA1_F1, b, c, d, e, a, (c_34s ^ w0s07));

	SHA1_STEP(SHA1_F1, a, b, c, d, e, (c_35s ^ w0s04));
	SHA1_STEP(SHA1_F1, e, a, b, c, d, (c_36s ^ w0s04___w0s06));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_37s ^ w0s08));
	SHA1_STEP(SHA1_F1, c, d, e, a, b, (c_38s ^ w0s04));
	SHA1_STEPX(SHA1_F1, b, c, d, e, a, (c_39sK));

#undef K
#define K 0x8f1bbcdc

	SHA1_STEP(SHA1_F2o, a, b, c, d, e, (c_40s ^ w0s04 ^ w0s09));
	SHA1_STEPX(SHA1_F2o, e, a, b, c, d, (c_41sK));
	SHA1_STEP(SHA1_F2o, d, e, a, b, c, (c_42s ^ w0s06 ^ w0s08));
	SHA1_STEP(SHA1_F2o, c, d, e, a, b, (c_43s ^ w0s10));
	SHA1_STEP(SHA1_F2o, b, c, d, e, a, (c_44s ^ w0s03 ^ w0s06 ^ w0s07));
	SHA1_STEPX(SHA1_F2o, a, b, c, d, e, (c_45sK));
	SHA1_STEP(SHA1_F2o, e, a, b, c, d, (c_46s ^ w0s04 ^ w0s11));
	SHA1_STEP(SHA1_F2o, d, e, a, b, c, (c_47s ^ w0s04___w0s08));
	SHA1_STEP(SHA1_F2o, c, d, e, a, b, (c_48s ^ w0s03 ^ w0s04___w0s08 ^ w0s05 ^ w0s10));
	SHA1_STEP(SHA1_F2o, b, c, d, e, a, (c_49s ^ w0s12));
	SHA1_STEP(SHA1_F2o, a, b, c, d, e, (c_50s ^ w0s08));
	SHA1_STEP(SHA1_F2o, e, a, b, c, d, (c_51s ^ w0s04___w0s06));
	SHA1_STEP(SHA1_F2o, d, e, a, b, c, (c_52s ^ w0s04___w0s08 ^ w0s13));
	SHA1_STEPX(SHA1_F2o, c, d, e, a, b, (c_53sK));
	SHA1_STEP(SHA1_F2o, b, c, d, e, a, (c_54s ^ w0s07 ^ w0s10 ^ w0s12));
	SHA1_STEP(SHA1_F2o, a, b, c, d, e, (c_55s ^ w0s14));
	SHA1_STEP(SHA1_F2o, e, a, b, c, d, (c_56s ^ w0s04___w0s06___w0s07 ^ w0s10 ^ w0s11));
	SHA1_STEP(SHA1_F2o, d, e, a, b, c, (c_57s ^ w0s08));
	SHA1_STEP(SHA1_F2o, c, d, e, a, b, (c_58s ^ w0s04___w0s08 ^ w0s15));
	SHA1_STEP(SHA1_F2o, b, c, d, e, a, (c_59s ^ w0s08___w0s12));

#undef K
#define K 0xca62c1d6

	SHA1_STEP(SHA1_F1, a, b, c, d, e, (c_60s ^ w0s04 ^ w0s08___w0s12 ^ w0s07 ^ w0s14));
	SHA1_STEP(SHA1_F1, e, a, b, c, d, (c_61s ^ w0s16));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_62s ^ w0s04___w0s06 ^ w0s08___w0s12));
	SHA1_STEP(SHA1_F1, c, d, e, a, b, (c_63s ^ w0s08));
	SHA1_STEP(SHA1_F1, b, c, d, e, a, (c_64s ^ w0s04___w0s06___w0s07 ^ w0s08___w0s12 ^ w0s17));
	SHA1_STEPX(SHA1_F1, a, b, c, d, e, (c_65sK));
	SHA1_STEP(SHA1_F1, e, a, b, c, d, (c_66s ^ w0s14 ^ w0s16));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_67s ^ w0s08 ^ w0s18));
	SHA1_STEP(SHA1_F1, c, d, e, a, b, (c_68s ^ w0s11 ^ w0s14 ^ w0s15));
	SHA1_STEPX(SHA1_F1, b, c, d, e, a, (c_69sK));
	SHA1_STEP(SHA1_F1, a, b, c, d, e, (c_70s ^ w0s12 ^ w0s19));
	SHA1_STEP(SHA1_F1, e, a, b, c, d, (c_71s ^ w0s12 ^ w0s16));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_72s ^ w0s05 ^ w0s11 ^ w0s12 ^ w0s13 ^ w0s16 ^ w0s18));
	SHA1_STEP(SHA1_F1, c, d, e, a, b, (c_73s ^ w0s20));
	SHA1_STEP(SHA1_F1, b, c, d, e, a, (c_74s ^ w0s08 ^ w0s16));
	SHA1_STEP(SHA1_F1, a, b, c, d, e, (c_75s ^ w0s06 ^ w0s12 ^ w0s14));

	uint32_t c_76s = hc_rotl32((c_73s ^ c_68s ^ c_62s ^ c_60s), 1u);
	uint32_t c_77s = hc_rotl32((c_74s ^ c_69s ^ c_63s ^ c_61s), 1u);
	uint32_t c_78s = hc_rotl32((c_75s ^ c_70s ^ c_64s ^ c_62s), 1u);
	uint32_t c_79s = hc_rotl32((c_76s ^ c_71s ^ c_65s ^ c_63s), 1u);

	uint32_t w0s21 = hc_rotl32(w0, 21u);
	uint32_t w0s22 = hc_rotl32(w0, 22U);

	SHA1_STEP(SHA1_F1, e, a, b, c, d, (c_76s ^ w0s07 ^ w0s08___w0s12 ^ w0s16 ^ w0s21));
	SHA1_STEP(SHA1_F1, d, e, a, b, c, (c_77s));
	SHA1_STEP(SHA1_F1, c, d, e, a, b, (c_78s ^ w0s07 ^ w0s08 ^ w0s15 ^ w0s18 ^ w0s20));
	SHA1_STEP(SHA1_F1, b, c, d, e, a, (c_79s ^ w0s08 ^ w0s22));

	digest[0] = _prestate[0] + a;
	digest[1] = _prestate[1] + b;
	digest[2] = _prestate[2] + c;
	digest[3] = _prestate[3] + d;
	digest[4] = _prestate[4] + e;
}

__device__ void _PBKDF2_HMAC_SHA160_core(uint32_t* PAD, uint32_t* temp, uint32_t* out) {
	_PBKDF2_HMAC_SHA160_core_final(PAD, out, temp);
}

__device__ void PBKDF2_HMAC_SHA160(uint8_t* pt, uint64_t ptLen, uint8_t* salt, uint64_t saLen, uint32_t* dk, uint32_t dkLen, uint32_t iter) {
	uint8_t buf[SHA160_BLOCK];
	uint32_t _first[5];
	uint32_t _second[5];
	uint32_t temp[5];
	PBKDF2_HMAC_SHA160_INFO info;
	uint32_t _TkLen = dkLen / SHA160_DIGEST;
	if (dkLen % 20 != 0) { _TkLen++; }

	if (ptLen > SHA160_BLOCK) {
		_SHA160(pt, ptLen, buf);
		_PBKDF2_HMAC_SHA160_precompute(buf, SHA160_DIGEST, &info);
		info.ptLen = SHA160_DIGEST;
	}

	else {
		_PBKDF2_HMAC_SHA160_precompute(pt, ptLen, &info);
		info.ptLen = ptLen;
	}

	for (uint32_t i = 0; i < _TkLen; i++) {
		_PBKDF2_HMAC_SHA160_salt_compute(salt, saLen, i + 1, &info, _first);
		_PBKDF2_HMAC_SHA160_core(info.OPAD, _first, _second);
		for (int j = 0; j < 5; j++)
			temp[j] = _second[j];

		for (int k = 1; k < iter; k++) {
			_PBKDF2_HMAC_SHA160_core(info.IPAD, _second, _first);
			_PBKDF2_HMAC_SHA160_core(info.OPAD, _first, _second);
			for (int x = 0; x < 5; x++)
				temp[x] ^= _second[x];
		}
		for (int z = 0; z < 5; z++) {
			dk[5 * i + z] = temp[z];
		}
	}
}

__global__ void PBKDF2_HMAC_SHA160_testVector_Check_Function() {
	uint8_t password[8] = { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64 };//"password" to ASCII
	uint8_t salt[4] = { 0x73, 0x61, 0x6c, 0x74 };//"salt" to ASCII
	uint32_t iter = 2;
	uint32_t dkLen = 20;
	uint32_t dk[10];
	PBKDF2_HMAC_SHA160(password, 8, salt, 4, dk, 20, 4096);
	for (int i = 0; i < 5; i++)
		printf("%08X ", dk[i]);
	printf("\n");
}


#define FIX_PTLEN	8
#define FIX_SALTLEN	4

__global__ void PBKDF2_HMAC_SHA160_fixed_Coalseced_memory(uint8_t* pt, uint8_t* salt, uint32_t* dk, uint32_t iteration_count) {

	uint8_t iternal_pt[8];
	uint8_t iternal_salt[4];
	uint32_t iternal_dk[5];

	uint64_t iternal_tid = (blockDim.x * blockIdx.x) + threadIdx.x;
	uint64_t iternal_index = (blockDim.x * gridDim.x);

	//pt Copy
	iternal_pt[0] = pt[0 * iternal_index + iternal_tid];
	iternal_pt[1] = pt[1 * iternal_index + iternal_tid];
	iternal_pt[2] = pt[2 * iternal_index + iternal_tid];
	iternal_pt[3] = pt[3 * iternal_index + iternal_tid];
	iternal_pt[4] = pt[4 * iternal_index + iternal_tid];
	iternal_pt[5] = pt[5 * iternal_index + iternal_tid];
	iternal_pt[6] = pt[6 * iternal_index + iternal_tid];
	iternal_pt[7] = pt[7 * iternal_index + iternal_tid];

	//salt Copy
	iternal_salt[0] = salt[0 * iternal_index + iternal_tid];
	iternal_salt[1] = salt[1 * iternal_index + iternal_tid];
	iternal_salt[2] = salt[2 * iternal_index + iternal_tid];
	iternal_salt[3] = salt[3 * iternal_index + iternal_tid];


	PBKDF2_HMAC_SHA160(iternal_pt, 8, iternal_salt, 4, iternal_dk, 20, iteration_count);

	//dk copy
	dk[0 * iternal_index + iternal_tid] = iternal_dk[0];
	dk[1 * iternal_index + iternal_tid] = iternal_dk[1];
	dk[2 * iternal_index + iternal_tid] = iternal_dk[2];
	dk[3 * iternal_index + iternal_tid] = iternal_dk[3];
	dk[4 * iternal_index + iternal_tid] = iternal_dk[4];
}

static void state_transform(uint8_t* state, uint64_t block_size, uint64_t thread_size) {
	uint8_t* buffer = (uint8_t*)malloc(block_size * thread_size * sizeof(uint8_t) * FIX_PTLEN);
	if (buffer == NULL)
		return;
	memcpy(buffer, state, block_size * thread_size * sizeof(uint8_t) * FIX_PTLEN);
	for (uint64_t i = 0; i < block_size * thread_size; i++) {
		state[i] = buffer[FIX_PTLEN * i];
		state[(1 * block_size * thread_size) + i] = buffer[FIX_PTLEN * i + 1];
		state[(2 * block_size * thread_size) + i] = buffer[FIX_PTLEN * i + 2];
		state[(3 * block_size * thread_size + i)] = buffer[FIX_PTLEN * i + 3];
		state[(4 * block_size * thread_size + i)] = buffer[FIX_PTLEN * i + 4];
		state[(5 * block_size * thread_size + i)] = buffer[FIX_PTLEN * i + 5];
		state[(6 * block_size * thread_size + i)] = buffer[FIX_PTLEN * i + 6];
		state[(7 * block_size * thread_size + i)] = buffer[FIX_PTLEN * i + 7];
	}
	free(buffer);
}


static void salt_transform(uint8_t* state, uint64_t block_size, uint64_t thread_size) {
	uint8_t* buffer = (uint8_t*)malloc(block_size * thread_size * sizeof(uint8_t) * FIX_SALTLEN);
	if (buffer == NULL)
		return;
	memcpy(buffer, state, block_size * thread_size * sizeof(uint8_t) * FIX_SALTLEN);
	for (uint64_t i = 0; i < block_size * thread_size; i++) {
		state[i] = buffer[FIX_SALTLEN * i];
		state[(1 * block_size * thread_size) + i] = buffer[FIX_SALTLEN * i + 1];
		state[(2 * block_size * thread_size) + i] = buffer[FIX_SALTLEN * i + 2];
		state[(3 * block_size * thread_size + i)] = buffer[FIX_SALTLEN * i + 3];
	}
	free(buffer);
}

static void dk_transform(uint32_t* state, uint64_t block_size, uint64_t thread_size) {
	uint32_t* buffer = (uint32_t*)malloc(block_size * thread_size * sizeof(uint32_t) * 5);
	if (buffer == NULL)
		return;
	memcpy(buffer, state, block_size * thread_size * sizeof(uint32_t) * 5);
	for (uint64_t i = 0; i < block_size * thread_size; i++) {
		state[5 * i] = buffer[i];
		state[5 * i + 1] = buffer[(1 * block_size * thread_size) + i];
		state[5 * i + 2] = buffer[(2 * block_size * thread_size) + i];
		state[5 * i + 3] = buffer[(3 * block_size * thread_size) + i];
		state[5 * i + 4] = buffer[(4 * block_size * thread_size) + i];
	}
	free(buffer);
}

void PBKDF2_HMAC_SHA160_coalesed_test(uint64_t blocksize, uint64_t threadsize) {

	cudaEvent_t start, stop;
	cudaError_t err;
	float elapsed_time_ms = 0.0f;

	uint8_t test_pt[8] = { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64 };
	uint8_t test_sa[4] = { 0x73, 0x61, 0x6c, 0x74 };

	uint8_t* temp = (uint8_t*)malloc(blocksize * threadsize * 8);
	uint8_t* sa_temp = (uint8_t*)malloc(blocksize * threadsize * 4);
	uint32_t* dk_temp = (uint32_t*)malloc(blocksize * threadsize * 5 * sizeof(uint32_t));
	//for (int i = 0; i < blocksize * threadsize; i++) {
	//	memcpy(temp + 8 * i, test_pt, 8);
	//	memcpy(sa_temp + 4 * i, test_sa, 4);
	//}

	for (int i = 0; i < blocksize * threadsize * 8; i++) {
		temp[i] = rand() % 0x100;
	}
	for (int i = 0; i < blocksize * threadsize * 4; i++) {
		sa_temp[i] = rand() % 0x100;
	}

	state_transform(temp, blocksize, threadsize);
	salt_transform(sa_temp, blocksize, threadsize);

	uint8_t* gpu_pt = NULL;
	uint8_t* gpu_salt = NULL;
	uint32_t* gpu_dk = NULL;

	cudaMalloc((void**)&gpu_pt, blocksize * threadsize * 8);
	cudaMalloc((void**)&gpu_salt, blocksize * threadsize * 4);
	cudaMalloc((void**)&gpu_dk, blocksize * threadsize * sizeof(uint32_t) * 5);

	cudaMemcpy(gpu_pt, temp, blocksize * threadsize * 8, cudaMemcpyHostToDevice);
	cudaMemcpy(gpu_salt, sa_temp, blocksize * threadsize * 4, cudaMemcpyHostToDevice);
	cudaEventCreate(&start);
	cudaEventCreate(&stop);
	cudaEventRecord(start, 0);
	for (int i = 0; i < 100; i++) {
		PBKDF2_HMAC_SHA160_fixed_Coalseced_memory << <blocksize, threadsize >> > (gpu_pt, gpu_salt, gpu_dk, 1000);
		cudaMemcpy(dk_temp, gpu_dk, blocksize * threadsize * sizeof(uint32_t) * 5, cudaMemcpyDeviceToHost);
	}
	cudaEventRecord(stop, 0);
	cudaDeviceSynchronize();
	cudaEventSynchronize(start);
	cudaEventSynchronize(stop);
	cudaEventElapsedTime(&elapsed_time_ms, start, stop);
	elapsed_time_ms /= 1;
	printf("Performance : %4.2f ms\n", elapsed_time_ms);


	//for (int i = 0; i < blocksize * threadsize * 5; i++) {
	//	printf("%08x ", dk_temp[i]);
	//	if ((i + 1) % 5 == 0)
	//		printf("\n");
	//}
	//dk_transform(dk_temp, blocksize, threadsize);
	//getchar();
	//printf("\n");
	//for (int i = 0; i < blocksize * threadsize * 5; i++) {
	//	printf("%08x ", dk_temp[i]);
	//	if ((i + 1) % 5 == 0)
	//		printf("\n");
	//}

}