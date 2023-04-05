#include "sha256.cuh"

__device__ void _SHA256_init(SHA256_INFO* info) {
	info->digest[0] = 0x6a09e667;
	info->digest[1] = 0xbb67ae85;
	info->digest[2] = 0x3c6ef372;
	info->digest[3] = 0xa54ff53a;
	info->digest[4] = 0x510e527f;
	info->digest[5] = 0x9b05688c;
	info->digest[6] = 0x1f83d9ab;
	info->digest[7] = 0x5be0cd19;

	for (int i = 0; i < SHA256_BLOCK; i++)
		info->BUF[i] = 0;

	info->ptLen = 0, info->lastLen = 0;
}

__device__ void _SHA256_core(uint32_t* input, uint32_t* digest)
{
	for (int i = 0; i < 16; i++)
		input[i] = ENDIAN_CHANGE32(input[i]);

	uint32_t w0_t = input[0];
	uint32_t w1_t = input[1];
	uint32_t w2_t = input[2];
	uint32_t w3_t = input[3];
	uint32_t w4_t = input[4];
	uint32_t w5_t = input[5];
	uint32_t w6_t = input[6];
	uint32_t w7_t = input[7];
	uint32_t w8_t = input[8];
	uint32_t w9_t = input[9];
	uint32_t wa_t = input[10];
	uint32_t wb_t = input[11];
	uint32_t wc_t = input[12];
	uint32_t wd_t = input[13];
	uint32_t we_t = input[14];
	uint32_t wf_t = input[15];

	uint32_t a = digest[0];
	uint32_t b = digest[1];
	uint32_t c = digest[2];
	uint32_t d = digest[3];
	uint32_t e = digest[4];
	uint32_t f = digest[5];
	uint32_t g = digest[6];
	uint32_t h = digest[7];

	SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x428a2f98);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x71374491);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcf);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba5);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x3956c25b);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x59f111f1);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x923f82a4);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0xd807aa98);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0x12835b01);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0x243185be);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0x72be5d74);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0x9bdc06a7);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0xc19bf174);

	w0_t = SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0xe49b69c1);
	w1_t = SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0xefbe4786);
	w2_t = SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x0fc19dc6);
	w3_t = SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x240ca1cc);
	w4_t = SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x2de92c6f);
	w5_t = SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x4a7484aa);
	w6_t = SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x5cb0a9dc);
	w7_t = SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x76f988da);
	w8_t = SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0x983e5152);
	w9_t = SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0xa831c66d);
	wa_t = SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0xb00327c8);
	wb_t = SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0xbf597fc7);
	wc_t = SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0xc6e00bf3);
	wd_t = SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xd5a79147);
	we_t = SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0x06ca6351);
	wf_t = SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0x14292967);

	w0_t = SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x27b70a85);
	w1_t = SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x2e1b2138);
	w2_t = SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x4d2c6dfc);
	w3_t = SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x53380d13);
	w4_t = SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x650a7354);
	w5_t = SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x766a0abb);
	w6_t = SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x81c2c92e);
	w7_t = SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x92722c85);
	w8_t = SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0xa2bfe8a1);
	w9_t = SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0xa81a664b);
	wa_t = SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0xc24b8b70);
	wb_t = SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0xc76c51a3);
	wc_t = SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0xd192e819);
	wd_t = SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xd6990624);
	we_t = SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0xf40e3585);
	wf_t = SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0x106aa070);

	w0_t = SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x19a4c116);
	w1_t = SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x1e376c08);
	w2_t = SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x2748774c);
	w3_t = SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x34b0bcb5);
	w4_t = SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x391c0cb3);
	w5_t = SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x4ed8aa4a);
	w6_t = SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x5b9cca4f);
	w7_t = SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x682e6ff3);
	w8_t = SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0x748f82ee);
	w9_t = SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0x78a5636f);
	wa_t = SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0x84c87814);
	wb_t = SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0x8cc70208);
	wc_t = SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0x90befffa);
	wd_t = SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xa4506ceb);
	we_t = SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0xbef9a3f7);
	wf_t = SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0xc67178f2);

	digest[0] += a;
	digest[1] += b;
	digest[2] += c;
	digest[3] += d;
	digest[4] += e;
	digest[5] += f;
	digest[6] += g;
	digest[7] += h;
}

__device__ void _SHA256_process(uint8_t* pt, uint64_t ptLen, SHA256_INFO* info) {
	uint64_t pt_index = 0;
	while ((ptLen + info->lastLen) >= SHA256_BLOCK) {
		for (int i = info->lastLen; i < (SHA256_BLOCK - info->lastLen); i++) {
			info->BUF[i] = pt[i + pt_index];
		}
		_SHA256_core((uint32_t*)info->BUF, info->digest);
		ptLen -= (SHA256_BLOCK - info->lastLen);
		info->ptLen += (SHA256_BLOCK - info->lastLen);
		pt_index += (SHA256_BLOCK - info->lastLen);
		info->lastLen = 0;

	}
	for (int i = 0; i < ptLen; i++) {
		info->BUF[i + info->lastLen] = pt[i + pt_index];
	}
	info->lastLen += ptLen;
	pt_index = 0;
}

__device__ void _SHA256_final(SHA256_INFO* info, uint8_t* out) {
	uint64_t r = (info->lastLen) % SHA256_BLOCK;
	info->BUF[r++] = 0x80;
	if (r >= SHA256_BLOCK - 8) {
		for (uint64_t i = r; i < SHA256_BLOCK; i++)
			info->BUF[i] = 0;
		_SHA256_core((uint32_t*)info->BUF, info->digest);
		for (int i = 0; i < SHA256_BLOCK - 8; i++)
			info->BUF[i] = 0;
	}
	else {
		for (uint64_t i = r; i < SHA256_BLOCK - 8; i++)
			info->BUF[i] = 0;
	}
	((uint32_t*)info->BUF)[SHA256_BLOCK / 4 - 2] = ENDIAN_CHANGE32((info->ptLen + info->lastLen) >> 29);
	((uint32_t*)info->BUF)[SHA256_BLOCK / 4 - 1] = ENDIAN_CHANGE32((info->ptLen + info->lastLen) << 3) & 0xffffffff;
	_SHA256_core((uint32_t*)info->BUF, info->digest);

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

	out[20] = (info->digest[5] >> 24) & 0xff;
	out[21] = (info->digest[5] >> 16) & 0xff;
	out[22] = (info->digest[5] >> 8) & 0xff;
	out[23] = (info->digest[5]) & 0xff;

	out[24] = (info->digest[6] >> 24) & 0xff;
	out[25] = (info->digest[6] >> 16) & 0xff;
	out[26] = (info->digest[6] >> 8) & 0xff;
	out[27] = (info->digest[6]) & 0xff;

	out[28] = (info->digest[7] >> 24) & 0xff;
	out[29] = (info->digest[7] >> 16) & 0xff;
	out[30] = (info->digest[7] >> 8) & 0xff;
	out[31] = (info->digest[7]) & 0xff;
}

__device__ void _SHA256(uint8_t* pt, uint64_t ptLen, uint8_t* digest) {
	SHA256_INFO info;
	_SHA256_init(&info);
	_SHA256_process(pt, ptLen, &info);
	_SHA256_final(&info, digest);
}

__device__ void _SHA256_preCompute_core(uint32_t* input, uint32_t* digest) {
	for (int i = 0; i < 16; i++)
		input[i] = ENDIAN_CHANGE32(input[i]);

	uint32_t w0_t = input[0];
	uint32_t w1_t = input[1];
	uint32_t w2_t = input[2];
	uint32_t w3_t = input[3];
	uint32_t w4_t = input[4];
	uint32_t w5_t = input[5];
	uint32_t w6_t = input[6];
	uint32_t w7_t = input[7];
	uint32_t w8_t = input[8];
	uint32_t w9_t = input[9];
	uint32_t wa_t = input[10];
	uint32_t wb_t = input[11];
	uint32_t wc_t = input[12];
	uint32_t wd_t = input[13];
	uint32_t we_t = input[14];
	uint32_t wf_t = input[15];


	uint32_t a = 0x6a09e667;
	uint32_t b = 0xbb67ae85;
	uint32_t c = 0x3c6ef372;
	uint32_t d = 0xa54ff53a;
	uint32_t e = 0x510e527f;
	uint32_t f = 0x9b05688c;
	uint32_t g = 0x1f83d9ab;
	uint32_t h = 0x5be0cd19;


	SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x428a2f98);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x71374491);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcf);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba5);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x3956c25b);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x59f111f1);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x923f82a4);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0xd807aa98);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0x12835b01);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0x243185be);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0x72be5d74);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0x9bdc06a7);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0xc19bf174);

	w0_t = SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0xe49b69c1);
	w1_t = SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0xefbe4786);
	w2_t = SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x0fc19dc6);
	w3_t = SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x240ca1cc);
	w4_t = SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x2de92c6f);
	w5_t = SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x4a7484aa);
	w6_t = SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x5cb0a9dc);
	w7_t = SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x76f988da);
	w8_t = SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0x983e5152);
	w9_t = SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0xa831c66d);
	wa_t = SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0xb00327c8);
	wb_t = SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0xbf597fc7);
	wc_t = SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0xc6e00bf3);
	wd_t = SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xd5a79147);
	we_t = SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0x06ca6351);
	wf_t = SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0x14292967);

	w0_t = SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x27b70a85);
	w1_t = SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x2e1b2138);
	w2_t = SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x4d2c6dfc);
	w3_t = SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x53380d13);
	w4_t = SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x650a7354);
	w5_t = SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x766a0abb);
	w6_t = SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x81c2c92e);
	w7_t = SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x92722c85);
	w8_t = SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0xa2bfe8a1);
	w9_t = SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0xa81a664b);
	wa_t = SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0xc24b8b70);
	wb_t = SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0xc76c51a3);
	wc_t = SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0xd192e819);
	wd_t = SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xd6990624);
	we_t = SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0xf40e3585);
	wf_t = SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0x106aa070);

	w0_t = SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x19a4c116);
	w1_t = SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x1e376c08);
	w2_t = SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x2748774c);
	w3_t = SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x34b0bcb5);
	w4_t = SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x391c0cb3);
	w5_t = SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x4ed8aa4a);
	w6_t = SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x5b9cca4f);
	w7_t = SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x682e6ff3);
	w8_t = SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0x748f82ee);
	w9_t = SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0x78a5636f);
	wa_t = SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0x84c87814);
	wb_t = SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0x8cc70208);
	wc_t = SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0x90befffa);
	wd_t = SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xa4506ceb);
	we_t = SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0xbef9a3f7);
	wf_t = SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0xc67178f2);

	digest[0] = a + 0x6a09e667;
	digest[1] = b + 0xbb67ae85;
	digest[2] = c + 0x3c6ef372;
	digest[3] = d + 0xa54ff53a;
	digest[4] = e + 0x510e527f;
	digest[5] = f + 0x9b05688c;
	digest[6] = g + 0x1f83d9ab;
	digest[7] = h + 0x5be0cd19;
}

__device__ void _SHA256_salt_compute_final(SHA256_INFO* info, uint32_t* out) {
	uint64_t r = (info->lastLen) % SHA256_BLOCK;
	info->BUF[r++] = 0x80;
	if (r >= SHA256_BLOCK - 8) {
		for (uint64_t i = r; i < SHA256_BLOCK; i++)
			info->BUF[i] = 0;
		_SHA256_core((uint32_t*)info->BUF, info->digest);
		for (int i = 0; i < SHA256_BLOCK - 8; i++)
			info->BUF[i] = 0;
	}
	else {
		for (uint64_t i = r; i < SHA256_BLOCK - 8; i++)
			info->BUF[i] = 0;
	}
	((uint32_t*)info->BUF)[SHA256_BLOCK / 4 - 2] = ENDIAN_CHANGE32((info->ptLen + info->lastLen) >> 29);
	((uint32_t*)info->BUF)[SHA256_BLOCK / 4 - 1] = ENDIAN_CHANGE32((info->ptLen + info->lastLen) << 3) & 0xffffffff;
	_SHA256_core((uint32_t*)info->BUF, info->digest);

	out[0] = info->digest[0];
	out[1] = info->digest[1];
	out[2] = info->digest[2];
	out[3] = info->digest[3];
	out[4] = info->digest[4];
	out[5] = info->digest[5];
	out[6] = info->digest[6];
	out[7] = info->digest[7];
}

__device__ void _PBKDF2_HMAC_SHA256_precompute(uint8_t* pt, uint8_t ptLen, PBKDF2_HMAC_SHA256_INFO* info) {
	uint8_t K1[SHA256_BLOCK];
	uint8_t K2[SHA256_BLOCK];

	for (int i = 0; i < ptLen; i++) {
		K1[i] = 0x36 ^ pt[i];
		K2[i] = 0x5c ^ pt[i];
	}
	for (int i = ptLen; i < SHA256_BLOCK; i++) {
		K1[i] = 0x36;
		K2[i] = 0x5c;
	}
	_SHA256_preCompute_core((uint32_t*)K1, info->IPAD);
	_SHA256_preCompute_core((uint32_t*)K2, info->OPAD);
}

__device__ void _PBKDF2_HMAC_SHA256_salt_compute(uint8_t* salt, uint64_t saLen, uint32_t integer, PBKDF2_HMAC_SHA256_INFO* INFO, uint32_t* out) {
	SHA256_INFO info;
	uint8_t temp[4] = { (integer >> 24) & 0xff, (integer >> 16) & 0xff, (integer >> 8) & 0xff, (integer & 0xff) };
	info.digest[0] = INFO->IPAD[0];
	info.digest[1] = INFO->IPAD[1];
	info.digest[2] = INFO->IPAD[2];
	info.digest[3] = INFO->IPAD[3];
	info.digest[4] = INFO->IPAD[4];
	info.digest[5] = INFO->IPAD[5];
	info.digest[6] = INFO->IPAD[6];
	info.digest[7] = INFO->IPAD[7];
	info.ptLen = 64;
	info.lastLen = 0;
	_SHA256_process(salt, saLen, &info);
	_SHA256_process(temp, 4, &info);
	_SHA256_salt_compute_final(&info, out);
}

__device__ void _PBKDF2_HMAC_SHA256_core(uint32_t* _prestate, uint32_t* digest, uint32_t* in) {

	uint32_t w0_t = in[0];
	uint32_t w1_t = in[1];
	uint32_t w2_t = in[2];
	uint32_t w3_t = in[3];
	uint32_t w4_t = in[4];
	uint32_t w5_t = in[5];
	uint32_t w6_t = in[6];
	uint32_t w7_t = in[7];
	uint32_t w8_t = 0x80000000;
	uint32_t w9_t = 0;
	uint32_t wa_t = 0;
	uint32_t wb_t = 0;
	uint32_t wc_t = 0;
	uint32_t wd_t = 0;
	uint32_t we_t = 0;
	uint32_t wf_t = (64 + 32) << 3;

	uint32_t a = _prestate[0];
	uint32_t b = _prestate[1];
	uint32_t c = _prestate[2];
	uint32_t d = _prestate[3];
	uint32_t e = _prestate[4];
	uint32_t f = _prestate[5];
	uint32_t g = _prestate[6];
	uint32_t h = _prestate[7];

	SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x428a2f98);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x71374491);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcf);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba5);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x3956c25b);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x59f111f1);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x923f82a4);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0xd807aa98);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0x12835b01);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0x243185be);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0x72be5d74);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0x9bdc06a7);
	SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0xc19bf174);

	w0_t = SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0xe49b69c1);
	w1_t = SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0xefbe4786);
	w2_t = SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x0fc19dc6);
	w3_t = SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x240ca1cc);
	w4_t = SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x2de92c6f);
	w5_t = SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x4a7484aa);
	w6_t = SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x5cb0a9dc);
	w7_t = SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x76f988da);
	w8_t = SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0x983e5152);
	w9_t = SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0xa831c66d);
	wa_t = SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0xb00327c8);
	wb_t = SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0xbf597fc7);
	wc_t = SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0xc6e00bf3);
	wd_t = SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xd5a79147);
	we_t = SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0x06ca6351);
	wf_t = SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0x14292967);

	w0_t = SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x27b70a85);
	w1_t = SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x2e1b2138);
	w2_t = SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x4d2c6dfc);
	w3_t = SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x53380d13);
	w4_t = SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x650a7354);
	w5_t = SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x766a0abb);
	w6_t = SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x81c2c92e);
	w7_t = SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x92722c85);
	w8_t = SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0xa2bfe8a1);
	w9_t = SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0xa81a664b);
	wa_t = SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0xc24b8b70);
	wb_t = SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0xc76c51a3);
	wc_t = SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0xd192e819);
	wd_t = SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xd6990624);
	we_t = SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0xf40e3585);
	wf_t = SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0x106aa070);

	w0_t = SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x19a4c116);
	w1_t = SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x1e376c08);
	w2_t = SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x2748774c);
	w3_t = SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x34b0bcb5);
	w4_t = SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x391c0cb3);
	w5_t = SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x4ed8aa4a);
	w6_t = SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x5b9cca4f);
	w7_t = SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x682e6ff3);
	w8_t = SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0x748f82ee);
	w9_t = SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0x78a5636f);
	wa_t = SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0x84c87814);
	wb_t = SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0x8cc70208);
	wc_t = SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0x90befffa);
	wd_t = SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xa4506ceb);
	we_t = SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0xbef9a3f7);
	wf_t = SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0xc67178f2);

	digest[0] = _prestate[0] + a;
	digest[1] = _prestate[1] + b;
	digest[2] = _prestate[2] + c;
	digest[3] = _prestate[3] + d;
	digest[4] = _prestate[4] + e;
	digest[5] = _prestate[5] + f;
	digest[6] = _prestate[6] + g;
	digest[7] = _prestate[7] + h;
}

__device__ void PBKDF2_HMAC_SHA256(uint8_t* pt, uint64_t ptLen, uint8_t* salt, uint64_t saLen, uint32_t* dk, uint32_t dkLen, uint32_t iter) {
	uint8_t buf[SHA256_BLOCK];
	uint32_t _first[8];
	uint32_t _second[8];
	uint32_t temp[8];
	PBKDF2_HMAC_SHA256_INFO info;
	uint32_t _TkLen = dkLen / SHA256_DIGEST;
	if (dkLen % SHA256_DIGEST != 0) { _TkLen++; }


	if (ptLen > SHA256_BLOCK) {
		_SHA256(pt, ptLen, buf);
		_PBKDF2_HMAC_SHA256_precompute(buf, SHA256_DIGEST, &info);
		info.ptLen = SHA256_DIGEST;
	}
	else {
		_PBKDF2_HMAC_SHA256_precompute(pt, ptLen, &info);
		info.ptLen = ptLen;
	}
	for (uint32_t i = 0; i < _TkLen; i++) {
		_PBKDF2_HMAC_SHA256_salt_compute(salt, saLen, i + 1, &info, _first);
		_PBKDF2_HMAC_SHA256_core(info.OPAD, _second, _first);
		for (int j = 0; j < 8; j++)
			temp[j] = _second[j];


		for (int k = 1; k < iter; k++) {
			_PBKDF2_HMAC_SHA256_core(info.IPAD, _first, _second);
			_PBKDF2_HMAC_SHA256_core(info.OPAD, _second, _first);
			for (int x = 0; x < 8; x++)
				temp[x] ^= _second[x];
		}
		for (int z = 0; z < 8; z++) {
			dk[8 * i + z] = temp[z];
		}
	}
}

__global__ void PBKDF2_HMAC_SHA256_testVector_Check_Function(uint8_t* pt, uint64_t* pt_len, uint8_t* salt, uint64_t* salt_len, uint32_t* dk) {
	uint64_t index = (8 * blockDim.x * blockIdx.x) + (8 * threadIdx.x);
	uint64_t gpu_pt_len = pt_len[blockDim.x * blockIdx.x + threadIdx.x];
	uint64_t gpu_salt_len = salt_len[blockDim.x * blockIdx.x + threadIdx.x];
	uint8_t* gpu_password = (uint8_t*)malloc(sizeof(uint8_t) * gpu_pt_len);
	uint8_t* gpu_salt = (uint8_t*)malloc(sizeof(uint8_t) * gpu_salt_len);

	uint64_t pt_index = (blockDim.x * blockIdx.x) + (threadIdx.x);
	uint64_t salt_index = (blockDim.x * blockIdx.x) + (threadIdx.x);
	for (int i = 0; i < gpu_pt_len; i++)
		gpu_password[i] = pt[pt_index + i];
	for (int i = 0; i < gpu_salt_len; i++)
		gpu_salt[i] = salt[salt_index + i];
	PBKDF2_HMAC_SHA256(gpu_password, gpu_pt_len, gpu_salt, gpu_salt_len, dk + index, 32, 65536);
	free(gpu_password);
	free(gpu_salt);
}

void GPU_PBKDF2_SHA256_performance_analysis(uint64_t Blocksize, uint64_t Threadsize) {
	cudaEvent_t start, stop;
	cudaError_t err;
	float elapsed_time_ms = 0.0f;
	uint32_t* GPU_out = NULL;
	uint32_t* CPU_out = NULL;
	uint8_t* pt = NULL;
	uint64_t* pt_len = NULL;
	uint64_t* GPU_pt_len = NULL;
	uint8_t* GPU_pt = NULL;

	uint8_t* salt = NULL;
	uint8_t* GPU_salt = NULL;
	uint64_t* GPU_salt_len = NULL;
	uint64_t* salt_len = NULL;


	/*!memory allocation*/
	//CPU Phase
	pt = (uint8_t*)malloc(sizeof(uint8_t) * Blocksize * Threadsize * 8);
	if (pt == NULL)
		return;
	salt = (uint8_t*)malloc(sizeof(uint8_t) * Blocksize * Threadsize * 4);
	if (pt == NULL)
		return;

	pt_len = (uint64_t*)malloc(sizeof(uint64_t) * Blocksize * Threadsize);
	if (pt_len == NULL)
		return;
	salt_len = (uint64_t*)malloc(sizeof(uint64_t) * Blocksize * Threadsize);
	if (pt_len == NULL)
		return;

	CPU_out = (uint32_t*)malloc(sizeof(uint32_t) * (Blocksize * Threadsize) * 8);
	if (CPU_out == NULL)
		return;

	//GPU Phase
	err = cudaMalloc((void**)&GPU_pt, Blocksize * Threadsize * 8 * sizeof(uint8_t));
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA256_performance_analysis, GPU_pt : CUDA error : %s\n", cudaGetErrorString(err));
	}

	err = cudaMalloc((void**)&GPU_salt, Blocksize * Threadsize * 4 * sizeof(uint8_t));
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA256_performance_analysis, GPU_salt : CUDA error : %s\n", cudaGetErrorString(err));
	}
	err = cudaMalloc((void**)&GPU_pt_len, Blocksize * Threadsize * sizeof(uint64_t));
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA256_performance_analysis, GPU_pt_len : CUDA error : %s\n", cudaGetErrorString(err));
	}

	err = cudaMalloc((void**)&GPU_salt_len, Blocksize * Threadsize * sizeof(uint64_t));
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA256_performance_analysis, GPU_salt_len : CUDA error : %s\n", cudaGetErrorString(err));
	}

	err = cudaMalloc((void**)&GPU_out, Blocksize * Threadsize * 8 * sizeof(uint32_t));
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA256_performance_analysis, GPU_out : CUDA error : %s\n", cudaGetErrorString(err));
	}

	/*!Data set + memory copy*/
	//CPU Phase
	//printf("*! pt = ");
	for (int i = 0; i < Blocksize * Threadsize * 8; i++) {
		pt[i] = rand() % (0x100);
		//printf("%02X ", pt[i]);
	}
	//printf("\n");
	//printf("*! salt = ");
	for (int i = 0; i < Blocksize * Threadsize * 4; i++) {
		salt[i] = rand() % (0x100);
		//printf("%02X ", salt[i]);
	}
	//printf("\n");
	for (int i = 0; i < Blocksize * Threadsize; i++) {
		pt_len[i] = 8;
		salt_len[i] = 4;
	}

	err = cudaMemcpy(GPU_pt, pt, sizeof(uint8_t) * Threadsize * Blocksize * 8, cudaMemcpyHostToDevice);
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA256_performance_analysis, GPU_pt : CUDA error : %s\n", cudaGetErrorString(err));
	}
	err = cudaMemcpy(GPU_salt, salt, sizeof(uint8_t) * Threadsize * Blocksize * 4, cudaMemcpyHostToDevice);
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA256_performance_analysis, GPU_salt : CUDA error : %s\n", cudaGetErrorString(err));
	}
	err = cudaMemcpy(GPU_pt_len, pt_len, sizeof(uint64_t) * Threadsize * Blocksize, cudaMemcpyHostToDevice);
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA256_performance_analysis, GPU_pt_len : CUDA error : %s\n", cudaGetErrorString(err));
	}
	err = cudaMemcpy(GPU_salt_len, salt_len, sizeof(uint64_t) * Threadsize * Blocksize, cudaMemcpyHostToDevice);
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA256_performance_analysis, GPU_salt_len : CUDA error : %s\n", cudaGetErrorString(err));
	}

	//operation start
	cudaEventCreate(&start);
	cudaEventCreate(&stop);
	cudaEventRecord(start, 0);
	for (int i = 0; i < 1; i++) {
		//state_Transform(CPU_in, Blocksize, Threadsize);
		PBKDF2_HMAC_SHA256_testVector_Check_Function << <Blocksize, Threadsize >> > (GPU_pt, GPU_pt_len, GPU_salt, GPU_salt_len, GPU_out);
	}
	cudaEventRecord(stop, 0);
	cudaDeviceSynchronize();
	cudaEventSynchronize(start);
	cudaEventSynchronize(stop);
	cudaEventElapsedTime(&elapsed_time_ms, start, stop);
	elapsed_time_ms /= 1;
	printf("Performance : %4.2f PBKDF2 time per second \n", Blocksize * Threadsize / ((elapsed_time_ms / 1000)));
	printf("Performance : %4.2f PBKDF2 time per second \n", elapsed_time_ms);

	err = cudaMemcpy(CPU_out, GPU_out, Blocksize * Threadsize * sizeof(uint32_t) * 8, cudaMemcpyDeviceToHost);
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA256_performance_analysis[CUDAMEMCPY], CPU_out : CUDA error : %s\n", cudaGetErrorString(err));
	}
	cudaFree(GPU_out);
	cudaFree(GPU_pt);
	cudaFree(GPU_salt);
	cudaFree(GPU_pt_len);
	cudaFree(GPU_salt_len);
	free(pt);
	free(salt);
	free(salt_len);
	free(pt_len);

	getchar();
	for (int i = 0; i < Blocksize * Threadsize * 8; i++) {
		printf("%08x ", CPU_out[i]);
		if ((i + 1) % 8 == 0)
			printf("\n");
	}
	free(CPU_out);
}

#define FIX_PTLEN	8
#define FIX_SALTLEN	4
#define FIX_DKLEN	64
#define FIX_DKOUT	(FIX_DKLEN >> 3)

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
	uint32_t* buffer = (uint32_t*)malloc(block_size * thread_size * sizeof(uint32_t) * 8);
	if (buffer == NULL)
		return;
	memcpy(buffer, state, block_size * thread_size * sizeof(uint32_t) * 8);
	for (uint64_t i = 0; i < block_size * thread_size; i++) {
		state[FIX_PTLEN * i] = buffer[i];
		state[FIX_PTLEN * i + 1] = buffer[(1 * block_size * thread_size) + i];
		state[FIX_PTLEN * i + 2] = buffer[(2 * block_size * thread_size) + i];
		state[FIX_PTLEN * i + 3] = buffer[(3 * block_size * thread_size) + i];
		state[FIX_PTLEN * i + 4] = buffer[(4 * block_size * thread_size) + i];
		state[FIX_PTLEN * i + 5] = buffer[(5 * block_size * thread_size) + i];
		state[FIX_PTLEN * i + 6] = buffer[(6 * block_size * thread_size) + i];
		state[FIX_PTLEN * i + 7] = buffer[(7 * block_size * thread_size) + i];
	}
	free(buffer);
}

__global__ void PBKDF2_HMAC_SHA256_fixed_Coalseced_memory(uint8_t* pt, uint8_t* salt, uint32_t* dk, uint32_t iteration_count) {

	uint8_t iternal_pt[FIX_PTLEN];
	uint8_t iternal_salt[FIX_SALTLEN];
	uint32_t iternal_dk[FIX_DKOUT];

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


	PBKDF2_HMAC_SHA256(iternal_pt, FIX_PTLEN, iternal_salt, FIX_SALTLEN, iternal_dk, 32, iteration_count);

	//dk copy
	dk[0 * iternal_index + iternal_tid] = iternal_dk[0];
	dk[1 * iternal_index + iternal_tid] = iternal_dk[1];
	dk[2 * iternal_index + iternal_tid] = iternal_dk[2];
	dk[3 * iternal_index + iternal_tid] = iternal_dk[3];
	dk[4 * iternal_index + iternal_tid] = iternal_dk[4];
	dk[5 * iternal_index + iternal_tid] = iternal_dk[5];
	dk[6 * iternal_index + iternal_tid] = iternal_dk[6];
	dk[7 * iternal_index + iternal_tid] = iternal_dk[7];
}

void PBKDF2_HMAC_SHA256_coalesed_test() {

	cudaEvent_t start, stop;
	cudaError_t err;
	float elapsed_time_ms = 0.0f;

	uint64_t blocksize = 512;
	uint64_t threadsize = 256;

	uint8_t test_pt[8] = { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64 };
	uint8_t test_sa[4] = { 0x73, 0x61, 0x6c, 0x74 };

	uint8_t* temp = (uint8_t*)malloc(blocksize * threadsize * 8);
	uint8_t* sa_temp = (uint8_t*)malloc(blocksize * threadsize * 4);
	uint32_t* dk_temp = (uint32_t*)malloc(blocksize * threadsize * 8 * sizeof(uint32_t));
	/*for (int i = 0; i < blocksize * threadsize; i++) {
		memcpy(temp + 8 * i, test_pt, 8);
		memcpy(sa_temp + 4 * i, test_sa, 4);
	}
	*/for (int i = 0; i < blocksize * threadsize * 8; i++) {
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
	cudaMalloc((void**)&gpu_dk, blocksize * threadsize * sizeof(uint32_t) * 8);

	cudaMemcpy(gpu_pt, temp, blocksize * threadsize * 8, cudaMemcpyHostToDevice);
	cudaMemcpy(gpu_salt, sa_temp, blocksize * threadsize * 4, cudaMemcpyHostToDevice);
	cudaEventCreate(&start);
	cudaEventCreate(&stop);
	cudaEventRecord(start, 0);
	for (int i = 0; i < 100; i++) {
		PBKDF2_HMAC_SHA256_fixed_Coalseced_memory << <blocksize, threadsize >> > (gpu_pt, gpu_salt, gpu_dk, 65536);
	}
	cudaEventRecord(stop, 0);
	cudaDeviceSynchronize();
	cudaEventSynchronize(start);
	cudaEventSynchronize(stop);
	cudaEventElapsedTime(&elapsed_time_ms, start, stop);
	elapsed_time_ms /= 1;
	printf("Performance : %4.2f ms\n", elapsed_time_ms);

	cudaMemcpy(dk_temp, gpu_dk, blocksize * threadsize * sizeof(uint32_t) * 8, cudaMemcpyDeviceToHost);
	//dk_transform(dk_temp, blocksize, threadsize);
	getchar();
	printf("\n");
	for (int i = 0; i < blocksize * threadsize * 8; i++) {
		printf("%08x ", dk_temp[i]);
		if ((i + 1) % 8 == 0)
			printf("\n");
	}

}