#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include "type.cuh"
#include "sha160.cuh"
#include "sha256.cuh"
#include "sha512.cuh"
#include <stdio.h>
#include <time.h>

int main() {
	srand(time(NULL));
	//PBKDF2_HMAC_SHA160_coalesed_test(64, 64);
	//PBKDF2_HMAC_SHA160_coalesed_test(128, 128);
	//PBKDF2_HMAC_SHA160_coalesed_test(256, 256);
	//PBKDF2_HMAC_SHA160_coalesed_test(384, 384);
	//PBKDF2_HMAC_SHA160_coalesed_test(512, 256);


	//!PBKDF2_HMAC_SHA512 performance test
	//GPU_PBKDF2_SHA512_performance_analysis(2, 2);
	//GPU_PBKDF2_SHA512_performance_analysis(64, 64);
	//GPU_PBKDF2_SHA512_performance_analysis(128, 128);

	//GPU_PBKDF2_SHA512_performance_analysis(352, 352);
	//GPU_PBKDF2_SHA512_performance_analysis(384, 384);
	//GPU_PBKDF2_SHA512_performance_analysis(416, 416);

	//GPU_PBKDF2_SHA512_performance_analysis(448, 448);
	//GPU_PBKDF2_SHA512_performance_analysis(480, 480);

	//PBKDF2_HMAC_SHA512_coalesed_test(4, 4);
	//PBKDF2_HMAC_SHA512_coalesed_test(128, 128);
	//PBKDF2_HMAC_SHA512_coalesed_test(256, 256);
	//printf("\n");
	PBKDF2_HMAC_SHA512_coalesed_test(BLOCK_SIZE, THREAD_SIZE);

	//printf("\n");
	//PBKDF2_HMAC_SHA512_coalesed_test(416, 416);
	//printf("\n");
	//PBKDF2_HMAC_SHA512_coalesed_test(448, 448);

	//!PBKDF2_HMAC_SHA256 performance test
	//GPU_PBKDF2_SHA256_performance_analysis(64, 64);
	//GPU_PBKDF2_SHA256_performance_analysis(128, 128);
	//GPU_PBKDF2_SHA256_performance_analysis(192, 192);
	//GPU_PBKDF2_SHA256_performance_analysis(448, 448);
	//GPU_PBKDF2_SHA512_performance_analysis(256, 256);
	//PBKDF2_HMAC_SHA256_coalesed_test();
	return 0;
}