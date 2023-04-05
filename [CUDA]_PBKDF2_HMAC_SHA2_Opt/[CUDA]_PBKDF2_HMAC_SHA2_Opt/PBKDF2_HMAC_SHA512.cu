#include "sha512.cuh"

__device__ void _SHA512_init(SHA512_INFO* info) {
	for (int i = 0; i < SHA512_BLOCK; i++)
		info->BUF[i] = 0;
	info->lastLen = 0, info->ptLen = 0;
	info->digest[0] = 0x6a09e667f3bcc908;
	info->digest[1] = 0xbb67ae8584caa73b;
	info->digest[2] = 0x3c6ef372fe94f82b;
	info->digest[3] = 0xa54ff53a5f1d36f1;
	info->digest[4] = 0x510e527fade682d1;
	info->digest[5] = 0x9b05688c2b3e6c1f;
	info->digest[6] = 0x1f83d9abfb41bd6b;
	info->digest[7] = 0x5be0cd19137e2179;
}
__device__ void _SHA512_core(const uint64_t* input, uint64_t* digest) {
	uint64_t w0_t = ENDIAN_CHANGE64(input[0]);
	uint64_t w1_t = ENDIAN_CHANGE64(input[1]);
	uint64_t w2_t = ENDIAN_CHANGE64(input[2]);
	uint64_t w3_t = ENDIAN_CHANGE64(input[3]);
	uint64_t w4_t = ENDIAN_CHANGE64(input[4]);
	uint64_t w5_t = ENDIAN_CHANGE64(input[5]);
	uint64_t w6_t = ENDIAN_CHANGE64(input[6]);
	uint64_t w7_t = ENDIAN_CHANGE64(input[7]);
	uint64_t w8_t = ENDIAN_CHANGE64(input[8]);
	uint64_t w9_t = ENDIAN_CHANGE64(input[9]);
	uint64_t wa_t = ENDIAN_CHANGE64(input[10]);
	uint64_t wb_t = ENDIAN_CHANGE64(input[11]);
	uint64_t wc_t = ENDIAN_CHANGE64(input[12]);
	uint64_t wd_t = ENDIAN_CHANGE64(input[13]);
	uint64_t we_t = ENDIAN_CHANGE64(input[14]);
	uint64_t wf_t = ENDIAN_CHANGE64(input[15]);
	uint64_t a, b, c, d, e, f, g, h = 0;

	a = digest[0];
	b = digest[1];
	c = digest[2];
	d = digest[3];
	e = digest[4];
	f = digest[5];
	g = digest[6];
	h = digest[7];

	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x428a2f98d728ae22);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x7137449123ef65cd);
	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcfec4d3b2f);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba58189dbbc);
	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x3956c25bf348b538);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x59f111f1b605d019);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x923f82a4af194f9b);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5da6d8118);
	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xd807aa98a3030242);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x12835b0145706fbe);
	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x243185be4ee4b28c);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3d5ffb4e2);
	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x72be5d74f27b896f);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe3b1696b1);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x9bdc06a725c71235);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc19bf174cf692694);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xe49b69c19ef14ad2);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xefbe4786384f25e3);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x0fc19dc68b8cd5b5);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x240ca1cc77ac9c65);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x2de92c6f592b0275);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4a7484aa6ea6e483);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5cb0a9dcbd41fbd4);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x76f988da831153b5);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x983e5152ee66dfab);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa831c66d2db43210);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xb00327c898fb213f);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xbf597fc7beef0ee4);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xc6e00bf33da88fc2);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd5a79147930aa725);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x06ca6351e003826f);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x142929670a0e6e70);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x27b70a8546d22ffc);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x2e1b21385c26c926);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x4d2c6dfc5ac42aed);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x53380d139d95b3df);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x650a73548baf63de);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x766a0abb3c77b2a8);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x81c2c92e47edaee6);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x92722c851482353b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xa2bfe8a14cf10364);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa81a664bbc423001);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xc24b8b70d0f89791);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xc76c51a30654be30);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xd192e819d6ef5218);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd69906245565a910);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xf40e35855771202a);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x106aa07032bbd1b8);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x19a4c116b8d2d0c8);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x1e376c085141ab53);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x2748774cdf8eeb99);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x34b0bcb5e19b48a8);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x391c0cb3c5c95a63);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4ed8aa4ae3418acb);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5b9cca4f7763e373);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x682e6ff3d6b2b8a3);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x748f82ee5defb2fc);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x78a5636f43172f60);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x84c87814a1f0ab72);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x8cc702081a6439ec);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x90befffa23631e28);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xa4506cebde82bde9);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xbef9a3f7b2c67915);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc67178f2e372532b);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xca273eceea26619c);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xd186b8c721c0c207);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xeada7dd6cde0eb1e);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xf57d4f7fee6ed178);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x06f067aa72176fba);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x0a637dc5a2c898a6);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x113f9804bef90dae);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x1b710b35131c471b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x28db77f523047d84);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x32caab7b40c72493);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x3c9ebe0a15c9bebc);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x431d67c49c100d4c);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x4cc5d4becb3e42b6);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x597f299cfc657e2a);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x5fcb6fab3ad6faec);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x6c44198c4a475817);

	digest[0] += a;
	digest[1] += b;
	digest[2] += c;
	digest[3] += d;
	digest[4] += e;
	digest[5] += f;
	digest[6] += g;
	digest[7] += h;
}
__device__ void _SHA512_process(uint8_t* pt, uint64_t ptLen, SHA512_INFO* info) {
	uint64_t pt_index = 0;
	while ((ptLen + info->lastLen) >= SHA512_BLOCK) {
		for (int i = info->lastLen; i < (SHA512_BLOCK - info->lastLen); i++) {
			info->BUF[i] = pt[i + pt_index];
		}
		_SHA512_core((uint64_t*)info->BUF, info->digest);
		ptLen -= (SHA512_BLOCK - info->lastLen);
		info->ptLen += (SHA512_BLOCK - info->lastLen);
		pt_index += (SHA512_BLOCK - info->lastLen);
		info->lastLen = 0;
	}
	for (int i = 0; i < ptLen; i++) {
		info->BUF[i + info->lastLen] = pt[i + pt_index];
	}
	info->lastLen += ptLen;
	pt_index = 0;
}
__device__ void _SHA512_final(SHA512_INFO* info, uint8_t* out) {
	uint64_t r = (info->lastLen) % SHA512_BLOCK;
	info->BUF[r] = 0x80;
	if (r >= SHA512_BLOCK - 16) {
		for (uint64_t i = r; i < SHA512_BLOCK; i++)
			info->BUF[i] = 0;
		_SHA512_core((uint64_t*)info->BUF, info->digest);
		for (int i = 0; i < SHA512_BLOCK - 16; i++)
			info->BUF[i] = 0;
	}
	else {
		for (uint64_t i = r; i < SHA512_BLOCK - 16; i++)
			info->BUF[i] = 0;
	}
	((uint64_t*)info->BUF)[SHA512_BLOCK / 8 - 2] = ENDIAN_CHANGE64((info->ptLen + info->lastLen) >> 61);
	((uint64_t*)info->BUF)[SHA512_BLOCK / 8 - 1] = ENDIAN_CHANGE64((info->ptLen + info->lastLen) << 3) & 0xffffffffffffffff;
	_SHA512_core((uint64_t*)info->BUF, info->digest);

	out[0] = (info->digest[0] >> 56) & 0xff;
	out[1] = (info->digest[0] >> 48) & 0xff;
	out[2] = (info->digest[0] >> 40) & 0xff;
	out[3] = (info->digest[0] >> 32) & 0xff;
	out[4] = (info->digest[0] >> 24) & 0xff;
	out[5] = (info->digest[0] >> 16) & 0xff;
	out[6] = (info->digest[0] >> 8) & 0xff;
	out[7] = (info->digest[0]) & 0xff;

	out[8] = (info->digest[1] >> 56) & 0xff;
	out[9] = (info->digest[1] >> 48) & 0xff;
	out[10] = (info->digest[1] >> 40) & 0xff;
	out[11] = (info->digest[1] >> 32) & 0xff;
	out[12] = (info->digest[1] >> 24) & 0xff;
	out[13] = (info->digest[1] >> 16) & 0xff;
	out[14] = (info->digest[1] >> 8) & 0xff;
	out[15] = (info->digest[1]) & 0xff;

	out[16] = (info->digest[2] >> 56) & 0xff;
	out[17] = (info->digest[2] >> 48) & 0xff;
	out[18] = (info->digest[2] >> 40) & 0xff;
	out[19] = (info->digest[2] >> 32) & 0xff;
	out[20] = (info->digest[2] >> 24) & 0xff;
	out[21] = (info->digest[2] >> 16) & 0xff;
	out[22] = (info->digest[2] >> 8) & 0xff;
	out[23] = (info->digest[2]) & 0xff;

	out[24] = (info->digest[3] >> 56) & 0xff;
	out[25] = (info->digest[3] >> 48) & 0xff;
	out[26] = (info->digest[3] >> 40) & 0xff;
	out[27] = (info->digest[3] >> 32) & 0xff;
	out[28] = (info->digest[3] >> 24) & 0xff;
	out[29] = (info->digest[3] >> 16) & 0xff;
	out[30] = (info->digest[3] >> 8) & 0xff;
	out[31] = (info->digest[3]) & 0xff;

	out[32] = (info->digest[4] >> 56) & 0xff;
	out[33] = (info->digest[4] >> 48) & 0xff;
	out[34] = (info->digest[4] >> 40) & 0xff;
	out[35] = (info->digest[4] >> 32) & 0xff;
	out[36] = (info->digest[4] >> 24) & 0xff;
	out[37] = (info->digest[4] >> 16) & 0xff;
	out[38] = (info->digest[4] >> 8) & 0xff;
	out[39] = (info->digest[4]) & 0xff;

	out[40] = (info->digest[5] >> 56) & 0xff;
	out[41] = (info->digest[5] >> 48) & 0xff;
	out[42] = (info->digest[5] >> 40) & 0xff;
	out[43] = (info->digest[5] >> 32) & 0xff;
	out[44] = (info->digest[5] >> 24) & 0xff;
	out[45] = (info->digest[5] >> 16) & 0xff;
	out[46] = (info->digest[5] >> 8) & 0xff;
	out[47] = (info->digest[5]) & 0xff;

	out[48] = (info->digest[6] >> 56) & 0xff;
	out[49] = (info->digest[6] >> 48) & 0xff;
	out[50] = (info->digest[6] >> 40) & 0xff;
	out[51] = (info->digest[6] >> 32) & 0xff;
	out[52] = (info->digest[6] >> 24) & 0xff;
	out[53] = (info->digest[6] >> 16) & 0xff;
	out[54] = (info->digest[6] >> 8) & 0xff;
	out[55] = (info->digest[6]) & 0xff;

	out[56] = (info->digest[7] >> 56) & 0xff;
	out[57] = (info->digest[7] >> 48) & 0xff;
	out[58] = (info->digest[7] >> 40) & 0xff;
	out[59] = (info->digest[7] >> 32) & 0xff;
	out[60] = (info->digest[7] >> 24) & 0xff;
	out[61] = (info->digest[7] >> 16) & 0xff;
	out[62] = (info->digest[7] >> 8) & 0xff;
	out[63] = (info->digest[7]) & 0xff;
}
__device__ void _SHA512(uint8_t* pt, uint64_t ptLen, uint8_t* digest) {
	SHA512_INFO info;

	/* if(ptLen < 128)
	{
		SHA-512 straight;
		_SHA512_fast_version
	}*/

	_SHA512_init(&info);
	_SHA512_process(pt, ptLen, &info);
	_SHA512_final(&info, digest);
}
__device__ void _SHA512_preCompute_core(uint64_t* input, uint64_t* digest) {

	uint64_t w0_t = ENDIAN_CHANGE64(input[0]);
	uint64_t w1_t = ENDIAN_CHANGE64(input[1]);
	uint64_t w2_t = ENDIAN_CHANGE64(input[2]);
	uint64_t w3_t = ENDIAN_CHANGE64(input[3]);
	uint64_t w4_t = ENDIAN_CHANGE64(input[4]);
	uint64_t w5_t = ENDIAN_CHANGE64(input[5]);
	uint64_t w6_t = ENDIAN_CHANGE64(input[6]);
	uint64_t w7_t = ENDIAN_CHANGE64(input[7]);
	uint64_t w8_t = ENDIAN_CHANGE64(input[8]);
	uint64_t w9_t = ENDIAN_CHANGE64(input[9]);
	uint64_t wa_t = ENDIAN_CHANGE64(input[10]);
	uint64_t wb_t = ENDIAN_CHANGE64(input[11]);
	uint64_t wc_t = ENDIAN_CHANGE64(input[12]);
	uint64_t wd_t = ENDIAN_CHANGE64(input[13]);
	uint64_t we_t = ENDIAN_CHANGE64(input[14]);
	uint64_t wf_t = ENDIAN_CHANGE64(input[15]);
	uint64_t a, b, c, d, e, f, g, h = 0;

	a = 0x6a09e667f3bcc908;
	b = 0xbb67ae8584caa73b;
	c = 0x3c6ef372fe94f82b;
	d = 0xa54ff53a5f1d36f1;
	e = 0x510e527fade682d1;
	f = 0x9b05688c2b3e6c1f;
	g = 0x1f83d9abfb41bd6b;
	h = 0x5be0cd19137e2179;

	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x428a2f98d728ae22);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x7137449123ef65cd);
	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcfec4d3b2f);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba58189dbbc);
	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x3956c25bf348b538);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x59f111f1b605d019);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x923f82a4af194f9b);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5da6d8118);
	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xd807aa98a3030242);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x12835b0145706fbe);
	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x243185be4ee4b28c);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3d5ffb4e2);
	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x72be5d74f27b896f);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe3b1696b1);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x9bdc06a725c71235);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc19bf174cf692694);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xe49b69c19ef14ad2);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xefbe4786384f25e3);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x0fc19dc68b8cd5b5);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x240ca1cc77ac9c65);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x2de92c6f592b0275);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4a7484aa6ea6e483);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5cb0a9dcbd41fbd4);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x76f988da831153b5);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x983e5152ee66dfab);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa831c66d2db43210);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xb00327c898fb213f);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xbf597fc7beef0ee4);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xc6e00bf33da88fc2);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd5a79147930aa725);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x06ca6351e003826f);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x142929670a0e6e70);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x27b70a8546d22ffc);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x2e1b21385c26c926);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x4d2c6dfc5ac42aed);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x53380d139d95b3df);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x650a73548baf63de);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x766a0abb3c77b2a8);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x81c2c92e47edaee6);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x92722c851482353b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xa2bfe8a14cf10364);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa81a664bbc423001);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xc24b8b70d0f89791);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xc76c51a30654be30);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xd192e819d6ef5218);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd69906245565a910);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xf40e35855771202a);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x106aa07032bbd1b8);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x19a4c116b8d2d0c8);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x1e376c085141ab53);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x2748774cdf8eeb99);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x34b0bcb5e19b48a8);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x391c0cb3c5c95a63);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4ed8aa4ae3418acb);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5b9cca4f7763e373);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x682e6ff3d6b2b8a3);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x748f82ee5defb2fc);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x78a5636f43172f60);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x84c87814a1f0ab72);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x8cc702081a6439ec);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x90befffa23631e28);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xa4506cebde82bde9);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xbef9a3f7b2c67915);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc67178f2e372532b);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xca273eceea26619c);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xd186b8c721c0c207);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xeada7dd6cde0eb1e);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xf57d4f7fee6ed178);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x06f067aa72176fba);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x0a637dc5a2c898a6);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x113f9804bef90dae);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x1b710b35131c471b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x28db77f523047d84);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x32caab7b40c72493);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x3c9ebe0a15c9bebc);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x431d67c49c100d4c);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x4cc5d4becb3e42b6);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x597f299cfc657e2a);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x5fcb6fab3ad6faec);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x6c44198c4a475817);


	digest[0] = a + 0x6a09e667f3bcc908;
	digest[1] = b + 0xbb67ae8584caa73b;
	digest[2] = c + 0x3c6ef372fe94f82b;
	digest[3] = d + 0xa54ff53a5f1d36f1;
	digest[4] = e + 0x510e527fade682d1;
	digest[5] = f + 0x9b05688c2b3e6c1f;
	digest[6] = g + 0x1f83d9abfb41bd6b;
	digest[7] = h + 0x5be0cd19137e2179;
}
__device__ void _SHA512_salt_compute_final(SHA512_INFO* info, uint64_t* out) {
	uint64_t r = (info->lastLen) % SHA512_BLOCK;
	info->BUF[r++] = 0x80;
	if (r >= SHA512_BLOCK - 16) {
		for (uint64_t i = r; i < SHA512_BLOCK; i++)
			info->BUF[i] = 0;
		_SHA512_core((uint64_t*)info->BUF, info->digest);
		for (int i = 0; i < SHA512_BLOCK - 16; i++)
			info->BUF[i] = 0;
	}
	else {
		for (uint64_t i = r; i < SHA512_BLOCK - 16; i++)
			info->BUF[i] = 0;
	}
	((uint64_t*)info->BUF)[SHA512_BLOCK / 8 - 2] = ENDIAN_CHANGE64((info->ptLen + info->lastLen) >> 61);
	((uint64_t*)info->BUF)[SHA512_BLOCK / 8 - 1] = ENDIAN_CHANGE64((info->ptLen + info->lastLen) << 3) & 0xffffffffffffffff;
	_SHA512_core((uint64_t*)info->BUF, info->digest);
	out[0] = info->digest[0];
	out[1] = info->digest[1];
	out[2] = info->digest[2];
	out[3] = info->digest[3];
	out[4] = info->digest[4];
	out[5] = info->digest[5];
	out[6] = info->digest[6];
	out[7] = info->digest[7];
}
__device__ void _PBKDF2_HMAC_SHA512_precompute(uint8_t* pt, uint64_t ptLen, PBKDF2_HMAC_SHA512_INFO* info) {
	uint8_t K1[SHA512_BLOCK];
	uint8_t K2[SHA512_BLOCK];

	for (int i = 0; i < ptLen; i++) {
		K1[i] = 0x36 ^ pt[i];
		K2[i] = 0x5c ^ pt[i];
	}
	for (int i = ptLen; i < SHA512_BLOCK; i++) {
		K1[i] = 0x36;
		K2[i] = 0x5c;
	}
	_SHA512_preCompute_core((uint64_t*)K1, info->IPAD);
	_SHA512_preCompute_core((uint64_t*)K2, info->OPAD);
}
__device__ void _PBKDF2_HMAC_SHA512_salt_compute(uint8_t* salt, uint64_t saLen, uint32_t integer, PBKDF2_HMAC_SHA512_INFO* INFO, uint64_t* out) {
	SHA512_INFO info;
	uint8_t temp[4] = { (integer >> 24) & 0xff, (integer >> 16) & 0xff, (integer >> 8) & 0xff, (integer & 0xff) };
	info.digest[0] = INFO->IPAD[0];
	info.digest[1] = INFO->IPAD[1];
	info.digest[2] = INFO->IPAD[2];
	info.digest[3] = INFO->IPAD[3];
	info.digest[4] = INFO->IPAD[4];
	info.digest[5] = INFO->IPAD[5];
	info.digest[6] = INFO->IPAD[6];
	info.digest[7] = INFO->IPAD[7];
	info.ptLen = SHA512_BLOCK;
	info.lastLen = 0;
	_SHA512_process(salt, saLen, &info);
	_SHA512_process(temp, 4, &info);
	_SHA512_salt_compute_final(&info, out);
}
__device__ void _PBKDF2_HMAC_SHA512_core(uint64_t* _prestate, uint64_t* digest, uint64_t* in) {
	uint64_t w0_t = in[0];
	uint64_t w1_t = in[1];
	uint64_t w2_t = in[2];
	uint64_t w3_t = in[3];
	uint64_t w4_t = in[4];
	uint64_t w5_t = in[5];
	uint64_t w6_t = in[6];
	uint64_t w7_t = in[7];
	uint64_t w8_t = 0x8000000000000000;
	uint64_t w9_t = 0;
	uint64_t wa_t = 0;
	uint64_t wb_t = 0;
	uint64_t wc_t = 0;
	uint64_t wd_t = 0;
	uint64_t we_t = 0;
	uint64_t wf_t = (128 + 64) << 3;

	uint64_t a = _prestate[0];
	uint64_t b = _prestate[1];
	uint64_t c = _prestate[2];
	uint64_t d = _prestate[3];
	uint64_t e = _prestate[4];
	uint64_t f = _prestate[5];
	uint64_t g = _prestate[6];
	uint64_t h = _prestate[7];

	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x428a2f98d728ae22);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x7137449123ef65cd);
	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcfec4d3b2f);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba58189dbbc);
	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x3956c25bf348b538);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x59f111f1b605d019);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x923f82a4af194f9b);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5da6d8118);
	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xd807aa98a3030242);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x12835b0145706fbe);
	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x243185be4ee4b28c);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3d5ffb4e2);
	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x72be5d74f27b896f);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe3b1696b1);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x9bdc06a725c71235);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc19bf174cf692694);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xe49b69c19ef14ad2);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xefbe4786384f25e3);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x0fc19dc68b8cd5b5);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x240ca1cc77ac9c65);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x2de92c6f592b0275);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4a7484aa6ea6e483);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5cb0a9dcbd41fbd4);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x76f988da831153b5);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x983e5152ee66dfab);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa831c66d2db43210);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xb00327c898fb213f);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xbf597fc7beef0ee4);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xc6e00bf33da88fc2);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd5a79147930aa725);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x06ca6351e003826f);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x142929670a0e6e70);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x27b70a8546d22ffc);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x2e1b21385c26c926);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x4d2c6dfc5ac42aed);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x53380d139d95b3df);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x650a73548baf63de);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x766a0abb3c77b2a8);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x81c2c92e47edaee6);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x92722c851482353b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xa2bfe8a14cf10364);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa81a664bbc423001);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xc24b8b70d0f89791);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xc76c51a30654be30);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xd192e819d6ef5218);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd69906245565a910);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xf40e35855771202a);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x106aa07032bbd1b8);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x19a4c116b8d2d0c8);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x1e376c085141ab53);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x2748774cdf8eeb99);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x34b0bcb5e19b48a8);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x391c0cb3c5c95a63);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4ed8aa4ae3418acb);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5b9cca4f7763e373);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x682e6ff3d6b2b8a3);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x748f82ee5defb2fc);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x78a5636f43172f60);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x84c87814a1f0ab72);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x8cc702081a6439ec);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x90befffa23631e28);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xa4506cebde82bde9);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xbef9a3f7b2c67915);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc67178f2e372532b);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xca273eceea26619c);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xd186b8c721c0c207);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xeada7dd6cde0eb1e);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xf57d4f7fee6ed178);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x06f067aa72176fba);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x0a637dc5a2c898a6);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x113f9804bef90dae);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x1b710b35131c471b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x28db77f523047d84);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x32caab7b40c72493);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x3c9ebe0a15c9bebc);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x431d67c49c100d4c);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x4cc5d4becb3e42b6);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x597f299cfc657e2a);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x5fcb6fab3ad6faec);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x6c44198c4a475817);

	digest[0] = _prestate[0] + a;
	digest[1] = _prestate[1] + b;
	digest[2] = _prestate[2] + c;
	digest[3] = _prestate[3] + d;
	digest[4] = _prestate[4] + e;
	digest[5] = _prestate[5] + f;
	digest[6] = _prestate[6] + g;
	digest[7] = _prestate[7] + h;

}

__device__ void _PBKDF2_HMAC_SHA512_core_test(uint64_t* _prestate_1, uint64_t* _prestate_2, uint64_t* digest, uint64_t* in) {
	uint64_t w0_t = in[0];
	uint64_t w1_t = in[1];
	uint64_t w2_t = in[2];
	uint64_t w3_t = in[3];
	uint64_t w4_t = in[4];
	uint64_t w5_t = in[5];
	uint64_t w6_t = in[6];
	uint64_t w7_t = in[7];
	uint64_t w8_t = 0x8000000000000000;
	uint64_t w9_t = 0;
	uint64_t wa_t = 0;
	uint64_t wb_t = 0;
	uint64_t wc_t = 0;
	uint64_t wd_t = 0;
	uint64_t we_t = 0;
	uint64_t wf_t = (128 + 64) << 3;

	uint64_t a = _prestate_1[0];
	uint64_t b = _prestate_1[1];
	uint64_t c = _prestate_1[2];
	uint64_t d = _prestate_1[3];
	uint64_t e = _prestate_1[4];
	uint64_t f = _prestate_1[5];
	uint64_t g = _prestate_1[6];
	uint64_t h = _prestate_1[7];

	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x428a2f98d728ae22);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x7137449123ef65cd);
	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcfec4d3b2f);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba58189dbbc);
	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x3956c25bf348b538);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x59f111f1b605d019);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x923f82a4af194f9b);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5da6d8118);
	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xd807aa98a3030242);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x12835b0145706fbe);
	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x243185be4ee4b28c);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3d5ffb4e2);
	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x72be5d74f27b896f);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe3b1696b1);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x9bdc06a725c71235);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc19bf174cf692694);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xe49b69c19ef14ad2);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xefbe4786384f25e3);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x0fc19dc68b8cd5b5);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x240ca1cc77ac9c65);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x2de92c6f592b0275);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4a7484aa6ea6e483);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5cb0a9dcbd41fbd4);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x76f988da831153b5);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x983e5152ee66dfab);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa831c66d2db43210);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xb00327c898fb213f);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xbf597fc7beef0ee4);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xc6e00bf33da88fc2);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd5a79147930aa725);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x06ca6351e003826f);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x142929670a0e6e70);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x27b70a8546d22ffc);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x2e1b21385c26c926);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x4d2c6dfc5ac42aed);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x53380d139d95b3df);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x650a73548baf63de);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x766a0abb3c77b2a8);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x81c2c92e47edaee6);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x92722c851482353b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xa2bfe8a14cf10364);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa81a664bbc423001);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xc24b8b70d0f89791);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xc76c51a30654be30);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xd192e819d6ef5218);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd69906245565a910);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xf40e35855771202a);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x106aa07032bbd1b8);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x19a4c116b8d2d0c8);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x1e376c085141ab53);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x2748774cdf8eeb99);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x34b0bcb5e19b48a8);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x391c0cb3c5c95a63);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4ed8aa4ae3418acb);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5b9cca4f7763e373);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x682e6ff3d6b2b8a3);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x748f82ee5defb2fc);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x78a5636f43172f60);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x84c87814a1f0ab72);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x8cc702081a6439ec);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x90befffa23631e28);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xa4506cebde82bde9);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xbef9a3f7b2c67915);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc67178f2e372532b);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xca273eceea26619c);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xd186b8c721c0c207);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xeada7dd6cde0eb1e);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xf57d4f7fee6ed178);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x06f067aa72176fba);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x0a637dc5a2c898a6);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x113f9804bef90dae);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x1b710b35131c471b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x28db77f523047d84);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x32caab7b40c72493);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x3c9ebe0a15c9bebc);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x431d67c49c100d4c);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x4cc5d4becb3e42b6);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x597f299cfc657e2a);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x5fcb6fab3ad6faec);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x6c44198c4a475817);

	w0_t = _prestate_1[0] + a;
	w1_t = _prestate_1[1] + b;
	w2_t = _prestate_1[2] + c;
	w3_t = _prestate_1[3] + d;
	w4_t = _prestate_1[4] + e;
	w5_t = _prestate_1[5] + f;
	w6_t = _prestate_1[6] + g;
	w7_t = _prestate_1[7] + h;
	w8_t = 0x8000000000000000;
	w9_t = 0;
	wa_t = 0;
	wb_t = 0;
	wc_t = 0;
	wd_t = 0;
	we_t = 0;
	wf_t = (128 + 64) << 3;

	a = _prestate_2[0];
	b = _prestate_2[1];
	c = _prestate_2[2];
	d = _prestate_2[3];
	e = _prestate_2[4];
	f = _prestate_2[5];
	g = _prestate_2[6];
	h = _prestate_2[7];

	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x428a2f98d728ae22);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x7137449123ef65cd);
	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcfec4d3b2f);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba58189dbbc);
	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x3956c25bf348b538);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x59f111f1b605d019);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x923f82a4af194f9b);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5da6d8118);
	SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xd807aa98a3030242);
	SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x12835b0145706fbe);
	SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x243185be4ee4b28c);
	SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3d5ffb4e2);
	SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x72be5d74f27b896f);
	SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe3b1696b1);
	SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x9bdc06a725c71235);
	SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc19bf174cf692694);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xe49b69c19ef14ad2);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xefbe4786384f25e3);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x0fc19dc68b8cd5b5);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x240ca1cc77ac9c65);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x2de92c6f592b0275);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4a7484aa6ea6e483);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5cb0a9dcbd41fbd4);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x76f988da831153b5);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x983e5152ee66dfab);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa831c66d2db43210);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xb00327c898fb213f);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xbf597fc7beef0ee4);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xc6e00bf33da88fc2);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd5a79147930aa725);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x06ca6351e003826f);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x142929670a0e6e70);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x27b70a8546d22ffc);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x2e1b21385c26c926);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x4d2c6dfc5ac42aed);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x53380d139d95b3df);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x650a73548baf63de);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x766a0abb3c77b2a8);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x81c2c92e47edaee6);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x92722c851482353b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0xa2bfe8a14cf10364);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0xa81a664bbc423001);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0xc24b8b70d0f89791);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0xc76c51a30654be30);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0xd192e819d6ef5218);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xd69906245565a910);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xf40e35855771202a);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x106aa07032bbd1b8);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0x19a4c116b8d2d0c8);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0x1e376c085141ab53);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0x2748774cdf8eeb99);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0x34b0bcb5e19b48a8);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x391c0cb3c5c95a63);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x4ed8aa4ae3418acb);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x5b9cca4f7763e373);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x682e6ff3d6b2b8a3);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x748f82ee5defb2fc);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x78a5636f43172f60);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x84c87814a1f0ab72);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x8cc702081a6439ec);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x90befffa23631e28);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0xa4506cebde82bde9);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0xbef9a3f7b2c67915);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0xc67178f2e372532b);

	w0_t = SHA512_EXPAND(we_t, w9_t, w1_t, w0_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w0_t, 0xca273eceea26619c);
	w1_t = SHA512_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w1_t, 0xd186b8c721c0c207);
	w2_t = SHA512_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, w2_t, 0xeada7dd6cde0eb1e);
	w3_t = SHA512_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, w3_t, 0xf57d4f7fee6ed178);
	w4_t = SHA512_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, w4_t, 0x06f067aa72176fba);
	w5_t = SHA512_EXPAND(w3_t, we_t, w6_t, w5_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, w5_t, 0x0a637dc5a2c898a6);
	w6_t = SHA512_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, w6_t, 0x113f9804bef90dae);
	w7_t = SHA512_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, w7_t, 0x1b710b35131c471b);
	w8_t = SHA512_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA512_STEP(SHA512_F0, SHA512_F1, a, b, c, d, e, f, g, h, w8_t, 0x28db77f523047d84);
	w9_t = SHA512_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA512_STEP(SHA512_F0, SHA512_F1, h, a, b, c, d, e, f, g, w9_t, 0x32caab7b40c72493);
	wa_t = SHA512_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA512_STEP(SHA512_F0, SHA512_F1, g, h, a, b, c, d, e, f, wa_t, 0x3c9ebe0a15c9bebc);
	wb_t = SHA512_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA512_STEP(SHA512_F0, SHA512_F1, f, g, h, a, b, c, d, e, wb_t, 0x431d67c49c100d4c);
	wc_t = SHA512_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA512_STEP(SHA512_F0, SHA512_F1, e, f, g, h, a, b, c, d, wc_t, 0x4cc5d4becb3e42b6);
	wd_t = SHA512_EXPAND(wb_t, w6_t, we_t, wd_t); SHA512_STEP(SHA512_F0, SHA512_F1, d, e, f, g, h, a, b, c, wd_t, 0x597f299cfc657e2a);
	we_t = SHA512_EXPAND(wc_t, w7_t, wf_t, we_t); SHA512_STEP(SHA512_F0, SHA512_F1, c, d, e, f, g, h, a, b, we_t, 0x5fcb6fab3ad6faec);
	wf_t = SHA512_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA512_STEP(SHA512_F0, SHA512_F1, b, c, d, e, f, g, h, a, wf_t, 0x6c44198c4a475817);

	digest[0] = _prestate_2[0] + a;
	digest[1] = _prestate_2[1] + b;
	digest[2] = _prestate_2[2] + c;
	digest[3] = _prestate_2[3] + d;
	digest[4] = _prestate_2[4] + e;
	digest[5] = _prestate_2[5] + f;
	digest[6] = _prestate_2[6] + g;
	digest[7] = _prestate_2[7] + h;
}

__device__ void PBKDF2_HMAC_SHA512(uint8_t* pt, uint64_t ptLen, uint8_t* salt, uint64_t saLen, uint64_t* dk, uint64_t dkLen, uint32_t iter) {
	uint8_t buf[SHA512_BLOCK];
	uint64_t _first[8];
	uint64_t _second[8];
	uint64_t temp[8];
	uint64_t _temp[8];
	PBKDF2_HMAC_SHA512_INFO info;
	uint64_t _tkLen = dkLen / SHA512_DIGEST;
	int k = 0;
	int i = 0;
	uint64_t test_arr[16];
	_PBKDF2_HMAC_SHA512_precompute(pt, ptLen, &info);
	_PBKDF2_HMAC_SHA512_salt_compute(salt, saLen, i + 1, &info, _first);
	_PBKDF2_HMAC_SHA512_core(info.OPAD, _second, _first);

	for (int j = 0; j < 8; j++) {
		_temp[j] = _second[j];
	}

	temp[0] = _second[0];
	temp[1] = _second[1];
	temp[2] = _second[2];
	temp[3] = _second[3];
	temp[4] = _second[4];
	temp[5] = _second[5];
	temp[6] = _second[6];
	temp[7] = _second[7];
	temp[8] = _second[8];

	for (k = 1; k < iter; k++) {
		_PBKDF2_HMAC_SHA512_core_test(info.IPAD, info.OPAD, _first, temp);

		_temp[0] ^= _first[0];
		_temp[1] ^= _first[1];
		_temp[2] ^= _first[2];
		_temp[3] ^= _first[3];
		_temp[4] ^= _first[4];
		_temp[5] ^= _first[5];
		_temp[6] ^= _first[6];
		_temp[7] ^= _first[7];

		temp[0] = _first[0];
		temp[1] = _first[1];
		temp[2] = _first[2];
		temp[3] = _first[3];
		temp[4] = _first[4];
		temp[5] = _first[5];
		temp[6] = _first[6];
		temp[7] = _first[7];
		temp[8] = _first[8];
	}

	for (int z = 0; z < 8; z++) {
		dk[8 * i + z] = _temp[z];
	}
}

__global__ void PBKDF2_HMAC_SHA512_testVector_Check_Function(uint8_t* pt, uint64_t* pt_len, uint8_t* salt, uint64_t* salt_len, uint64_t* dk) {
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

	PBKDF2_HMAC_SHA512(gpu_password, gpu_pt_len, gpu_salt, gpu_salt_len, dk + index, 64, 129977);
	free(gpu_password);
	free(gpu_salt);
}

#define FIX_PTLEN	8
#define FIX_SALTLEN	4
#define FIX_DKLEN	64
#define FIX_DKOUT	(FIX_DKLEN >> 3)
__global__ void PBKDF2_HMAC_SHA512_fixed_Len(uint8_t* pt, uint8_t* salt, uint64_t* dk, uint32_t iteration_count) {

	//Non coalesced Memory Access Version
	uint64_t pt_index = (blockIdx.x * blockDim.x * FIX_PTLEN) + (FIX_PTLEN * threadIdx.x);
	uint64_t salt_index = (blockIdx.x * blockDim.x * FIX_SALTLEN) + (FIX_SALTLEN * threadIdx.x);
	uint64_t dk_index = (blockIdx.x * blockDim.x * FIX_DKOUT) + (FIX_DKOUT * threadIdx.x);
	uint8_t iternal_pt[FIX_PTLEN];
	uint8_t iternal_salt[FIX_SALTLEN];
	uint64_t iternal_dk[FIX_DKOUT];
	for (int i = 0; i < FIX_PTLEN; i++)
		iternal_pt[i] = pt[pt_index + i];
	for (int i = 0; i < FIX_SALTLEN; i++)
		iternal_salt[i] = salt[i];
	PBKDF2_HMAC_SHA512(iternal_pt, FIX_PTLEN, iternal_salt, FIX_SALTLEN, iternal_dk, FIX_DKLEN, iteration_count);
	for (int i = 0; i < FIX_DKOUT; i++)
		dk[i + dk_index] = iternal_dk[i];
	//Coalesced Memory Access Version
	//To Do list
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
static void dk_transform(uint64_t* state, uint64_t block_size, uint64_t thread_size) {
	uint64_t* buffer = (uint64_t*)malloc(block_size * thread_size * sizeof(uint64_t) * 8);
	if (buffer == NULL)
		return;
	memcpy(buffer, state, block_size * thread_size * sizeof(uint64_t) * 8);
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
__global__ void PBKDF2_HMAC_SHA512_fixed_Coalseced_memory(uint8_t* pt, uint8_t* salt, uint64_t* dk, uint32_t iteration_count) {

	//uint8_t iternal_pt[FIX_PTLEN];
	//uint8_t iternal_salt[FIX_SALTLEN];
	//uint64_t iternal_dk[FIX_DKOUT];

	uint64_t iternal_tid = (blockDim.x * blockIdx.x) + threadIdx.x;
	uint64_t iternal_index = (blockDim.x * gridDim.x);

	__shared__ uint8_t shared_pt[THREAD_SIZE * FIX_PTLEN];
	__shared__ uint8_t shared_salt[THREAD_SIZE * FIX_SALTLEN];
	__shared__ uint64_t shared_dkout[THREAD_SIZE * FIX_DKOUT];

	//pt Copy
	shared_pt[0 + FIX_PTLEN * threadIdx.x] = pt[0 * iternal_index + iternal_tid];
	shared_pt[1 + FIX_PTLEN * threadIdx.x] = pt[1 * iternal_index + iternal_tid];
	shared_pt[2 + FIX_PTLEN * threadIdx.x] = pt[2 * iternal_index + iternal_tid];
	shared_pt[3 + FIX_PTLEN * threadIdx.x] = pt[3 * iternal_index + iternal_tid];
	shared_pt[4 + FIX_PTLEN * threadIdx.x] = pt[4 * iternal_index + iternal_tid];
	shared_pt[5 + FIX_PTLEN * threadIdx.x] = pt[5 * iternal_index + iternal_tid];
	shared_pt[6 + FIX_PTLEN * threadIdx.x] = pt[6 * iternal_index + iternal_tid];
	shared_pt[7 + FIX_PTLEN * threadIdx.x] = pt[7 * iternal_index + iternal_tid];

	//salt Copy
	shared_salt[0 + FIX_SALTLEN * threadIdx.x] = salt[0 * iternal_index + iternal_tid];
	shared_salt[1 + FIX_SALTLEN * threadIdx.x] = salt[1 * iternal_index + iternal_tid];
	shared_salt[2 + FIX_SALTLEN * threadIdx.x] = salt[2 * iternal_index + iternal_tid];
	shared_salt[3 + FIX_SALTLEN * threadIdx.x] = salt[3 * iternal_index + iternal_tid];


	PBKDF2_HMAC_SHA512(shared_pt + 8 * threadIdx.x, FIX_PTLEN, shared_salt + 4 * threadIdx.x, FIX_SALTLEN, shared_dkout + FIX_DKOUT * threadIdx.x, FIX_DKLEN, iteration_count);

	//dk copy
	dk[0 * iternal_index + iternal_tid] = shared_dkout[0 + FIX_DKOUT * threadIdx.x];
	dk[1 * iternal_index + iternal_tid] = shared_dkout[1 + FIX_DKOUT * threadIdx.x];
	dk[2 * iternal_index + iternal_tid] = shared_dkout[2 + FIX_DKOUT * threadIdx.x];
	dk[3 * iternal_index + iternal_tid] = shared_dkout[3 + FIX_DKOUT * threadIdx.x];
	dk[4 * iternal_index + iternal_tid] = shared_dkout[4 + FIX_DKOUT * threadIdx.x];
	dk[5 * iternal_index + iternal_tid] = shared_dkout[5 + FIX_DKOUT * threadIdx.x];
	dk[6 * iternal_index + iternal_tid] = shared_dkout[6 + FIX_DKOUT * threadIdx.x];
	dk[7 * iternal_index + iternal_tid] = shared_dkout[7 + FIX_DKOUT * threadIdx.x];
}

void PBKDF2_HMAC_SHA512_coalesed_test(uint64_t blocksize, uint64_t threadsize) {

	cudaEvent_t start, stop;
	cudaError_t err;
	float elapsed_time_ms = 0.0f;

	uint8_t test_pt[8] = { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64 };
	uint8_t test_sa[4] = { 0x73, 0x61, 0x6c, 0x74 };

	uint8_t* temp = (uint8_t*)malloc(blocksize * threadsize * 8);
	uint8_t* sa_temp = (uint8_t*)malloc(blocksize * threadsize * 4);
	uint64_t* dk_temp = (uint64_t*)malloc(blocksize * threadsize * 8 * sizeof(uint64_t));
	for (int i = 0; i < blocksize * threadsize; i++) {
		memcpy(temp + 8 * i, test_pt, 8);
		memcpy(sa_temp + 4 * i, test_sa, 4);
	}

	//printf("PT\n");
	//for (int i = 0; i < blocksize * threadsize; i++) {
	//	printf("%X", temp[i]);
	//	if (i % 8 == 7) {
	//		printf("\n");
	//	}
	//}
	//for (int i = 0; i < blocksize * threadsize; i++) {
	//	printf("%X", sa_temp[i]);
	//}
	//for (int i = 0; i < blocksize * threadsize * 8; i++) {
	//	temp[i] = rand() % 0x100;
	//}
	//for (int i = 0; i < blocksize * threadsize * 4; i++) {
	//	sa_temp[i] = rand() % 0x100;
	//}


	//printf("\nCAMP\n");
	//for (int i = 0; i < blocksize * threadsize; i++) {
	//	printf("%X", temp[i]);
	//}
	//getchar();

	state_transform(temp, blocksize, threadsize);
	salt_transform(sa_temp, blocksize, threadsize);

	uint8_t* gpu_pt = NULL;
	uint8_t* gpu_salt = NULL;
	uint64_t* gpu_dk = NULL;

	cudaMalloc((void**)&gpu_pt, blocksize * threadsize * 8);
	cudaMalloc((void**)&gpu_salt, blocksize * threadsize * 4);
	cudaMalloc((void**)&gpu_dk, blocksize * threadsize * sizeof(uint64_t) * 8);

	cudaMemcpy(gpu_pt, temp, blocksize * threadsize * 8, cudaMemcpyHostToDevice);
	cudaMemcpy(gpu_salt, sa_temp, blocksize * threadsize * 4, cudaMemcpyHostToDevice);
	cudaEventCreate(&start);
	cudaEventCreate(&stop);
	cudaEventRecord(start, 0);

	for (int i = 0; i < 1; i++) {
		PBKDF2_HMAC_SHA512_fixed_Coalseced_memory << <blocksize, threadsize >> > (gpu_pt, gpu_salt, gpu_dk, 129977);
	}
	cudaEventRecord(stop, 0);
	cudaDeviceSynchronize();
	cudaEventSynchronize(start);
	cudaEventSynchronize(stop);
	cudaEventElapsedTime(&elapsed_time_ms, start, stop);
	elapsed_time_ms /= 1;

	printf("Block_size = %d, Thread_size = %d\n", blocksize, threadsize);
	printf("Performance : %4.2f PBKDF2 time per second \n", blocksize * threadsize / ((elapsed_time_ms / 1000)));
	cudaMemcpy(dk_temp, gpu_dk, blocksize * threadsize * sizeof(uint64_t) * 8, cudaMemcpyDeviceToHost);
	dk_transform(dk_temp, blocksize, threadsize);
	//getchar();
	//printf("\n");
	//for (int i = 0; i < blocksize * threadsize * 8; i++) {
	//	printf("%016llx ", dk_temp[i]);
	//	if ((i + 1) % 8 == 0)
	//		printf("\n");
	//}
}

void GPU_PBKDF2_SHA512_performance_analysis(uint64_t Blocksize, uint64_t Threadsize) {

	//None Fix Len Version
#if 0
	cudaEvent_t start, stop;
	cudaError_t err;
	float elapsed_time_ms = 0.0f;

	uint64_t* GPU_out = NULL;
	uint64_t* CPU_out = NULL;
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

	CPU_out = (uint64_t*)malloc(sizeof(uint64_t) * (Blocksize * Threadsize) * 8);
	if (CPU_out == NULL)
		return;

	//GPU Phase
	err = cudaMalloc((void**)&GPU_pt, Blocksize * Threadsize * 8 * sizeof(uint8_t));
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA512_performance_analysis, GPU_pt : CUDA error : %s\n", cudaGetErrorString(err));
	}

	err = cudaMalloc((void**)&GPU_salt, Blocksize * Threadsize * 4 * sizeof(uint8_t));
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA512_performance_analysis, GPU_salt : CUDA error : %s\n", cudaGetErrorString(err));
	}
	err = cudaMalloc((void**)&GPU_pt_len, Blocksize * Threadsize * sizeof(uint64_t));
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA512_performance_analysis, GPU_pt_len : CUDA error : %s\n", cudaGetErrorString(err));
	}

	err = cudaMalloc((void**)&GPU_salt_len, Blocksize * Threadsize * sizeof(uint64_t));
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA512_performance_analysis, GPU_salt_len : CUDA error : %s\n", cudaGetErrorString(err));
	}

	err = cudaMalloc((void**)&GPU_out, Blocksize * Threadsize * 8 * sizeof(uint64_t));
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA512_performance_analysis, GPU_out : CUDA error : %s\n", cudaGetErrorString(err));
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
		printf("GPU_PBKDF2_SHA512_performance_analysis, GPU_pt : CUDA error : %s\n", cudaGetErrorString(err));
	}
	err = cudaMemcpy(GPU_salt, salt, sizeof(uint8_t) * Threadsize * Blocksize * 4, cudaMemcpyHostToDevice);
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA512_performance_analysis, GPU_salt : CUDA error : %s\n", cudaGetErrorString(err));
	}
	err = cudaMemcpy(GPU_pt_len, pt_len, sizeof(uint64_t) * Threadsize * Blocksize, cudaMemcpyHostToDevice);
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA512_performance_analysis, GPU_pt_len : CUDA error : %s\n", cudaGetErrorString(err));
	}
	err = cudaMemcpy(GPU_salt_len, salt_len, sizeof(uint64_t) * Threadsize * Blocksize, cudaMemcpyHostToDevice);
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA512_performance_analysis, GPU_salt_len : CUDA error : %s\n", cudaGetErrorString(err));
	}


	err = cudaMemcpy(GPU_pt, pt, sizeof(uint8_t) * Threadsize * Blocksize * 8, cudaMemcpyHostToDevice);
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA512_performance_analysis, GPU_pt : CUDA error : %s\n", cudaGetErrorString(err));
	}
	err = cudaMemcpy(GPU_salt, salt, sizeof(uint8_t) * Threadsize * Blocksize * 4, cudaMemcpyHostToDevice);
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA512_performance_analysis, GPU_salt : CUDA error : %s\n", cudaGetErrorString(err));
	}

	cudaEventCreate(&start);
	cudaEventCreate(&stop);
	cudaEventRecord(start, 0);
	for (int i = 0; i < 1; i++) {
		//state_Transform(CPU_in, Blocksize, Threadsize);
		PBKDF2_HMAC_SHA512_testVector_Check_Function << <Blocksize, Threadsize >> > (GPU_pt, GPU_pt_len, GPU_salt, GPU_salt_len, GPU_out);
	}
	cudaEventRecord(stop, 0);
	cudaDeviceSynchronize();
	cudaEventSynchronize(start);
	cudaEventSynchronize(stop);
	cudaEventElapsedTime(&elapsed_time_ms, start, stop);
	elapsed_time_ms /= 1;
	printf("Performance : %4.2f PBKDF2 time per second \n", Blocksize * Threadsize / ((elapsed_time_ms / 1000)));
	err = cudaMemcpy(CPU_out, GPU_out, sizeof(uint64_t) * Threadsize * Blocksize * 8, cudaMemcpyDeviceToHost);
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA512_performance_analysis, CPU_out : CUDA error : %s\n", cudaGetErrorString(err));
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
		printf("%016llx", CPU_out[i]);
		if ((i + 1) % 8 == 0)
			printf("\n");
	}
	free(CPU_out);
#endif
	//Fixed Len Version

	cudaEvent_t start, stop;
	cudaError_t err;
	float elapsed_time_ms = 0.0f;

	uint8_t test_pt[8] = { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64 };
	uint8_t test_sa[4] = { 0x73, 0x61, 0x6c, 0x74 };

	uint8_t* fixed_pt = (uint8_t*)malloc(sizeof(uint8_t) * FIX_PTLEN * Blocksize * Threadsize);
	uint8_t* fixed_salt = (uint8_t*)malloc(sizeof(uint8_t) * FIX_SALTLEN * Blocksize * Threadsize);
	uint64_t* fixed_dk = (uint64_t*)malloc(sizeof(uint64_t) * (FIX_DKLEN >> 3) * Blocksize * Threadsize);

	for (int i = 0; i < Blocksize * Threadsize; i++)
		memcpy(fixed_pt + (i * FIX_PTLEN), test_pt, FIX_PTLEN);

	for (int i = 0; i < Blocksize * Threadsize; i++)
		memcpy(fixed_salt + (i * FIX_SALTLEN), test_sa, FIX_SALTLEN);


	uint8_t* gpu_fixed_pt = NULL;
	uint8_t* gpu_fixed_salt = NULL;
	uint64_t* gpu_fixed_dk = NULL;

	err = cudaMalloc((void**)&gpu_fixed_pt, Blocksize * Threadsize * FIX_PTLEN * sizeof(uint8_t));
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA512_performance_analysis, gpu_fixed_pt : CUDA error : %s\n", cudaGetErrorString(err));
	}
	err = cudaMalloc((void**)&gpu_fixed_salt, Blocksize * Threadsize * FIX_SALTLEN * sizeof(uint8_t));
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA512_performance_analysis, gpu_fixed_salt : CUDA error : %s\n", cudaGetErrorString(err));
	}
	err = cudaMalloc((void**)&gpu_fixed_dk, Blocksize * Threadsize * (FIX_DKLEN >> 3) * sizeof(uint64_t));
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA512_performance_analysis, gpu_fixed_dk : CUDA error : %s\n", cudaGetErrorString(err));
	}


	err = cudaMemcpy(gpu_fixed_pt, fixed_pt, sizeof(uint8_t) * Threadsize * Blocksize * FIX_PTLEN, cudaMemcpyHostToDevice);
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA512_performance_analysis, gpu_fixed_pt : CUDA error : %s\n", cudaGetErrorString(err));
	}
	err = cudaMemcpy(gpu_fixed_salt, fixed_salt, sizeof(uint8_t) * Threadsize * Blocksize * FIX_SALTLEN, cudaMemcpyHostToDevice);
	if (err != cudaSuccess) {
		printf("GPU_PBKDF2_SHA512_performance_analysis, gpu_fixed_salt : CUDA error : %s\n", cudaGetErrorString(err));
	}


	cudaEventCreate(&start);
	cudaEventCreate(&stop);
	cudaEventRecord(start, 0);
	for (int i = 0; i < 100; i++) {
		PBKDF2_HMAC_SHA512_fixed_Len << <Blocksize, Threadsize >> > (gpu_fixed_pt, gpu_fixed_salt, gpu_fixed_dk, 999);
		cudaMemcpy(fixed_dk, gpu_fixed_dk, Blocksize * Threadsize * (FIX_DKLEN >> 3) * sizeof(uint64_t), cudaMemcpyDeviceToHost);
	}
	cudaEventRecord(stop, 0);
	cudaDeviceSynchronize();
	cudaEventSynchronize(start);
	cudaEventSynchronize(stop);
	cudaEventElapsedTime(&elapsed_time_ms, start, stop);
	elapsed_time_ms /= 100;
	printf("Performance : %4.2f ms\n", elapsed_time_ms);

	for (int i = 0; i < Blocksize * Threadsize * 8; i++) {
		printf("%016llx", fixed_dk[i]);
		if ((i + 1) % 8 == 0)
			printf("\n");
	}
}