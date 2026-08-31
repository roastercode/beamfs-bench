// SPDX-License-Identifier: GPL-2.0-only
//
// Native cost of the same Reed-Solomon codec beamfs uses, with the
// emulator taken out of the picture.
//
// The in-kernel micro-benchmark reports 7.2 MB/s, but that is measured
// inside a TCG-emulated aarch64 guest, where every instruction is
// translated. Quoting it as the cost of the codec would overstate it
// by whatever the emulator costs, and nothing so far says by how much.
//
// This runs the identical arithmetic on the host, natively. The ratio
// between the two is the emulation factor, and it is the number that
// lets every other figure in the campaign be read as a property of
// beamfs rather than of the lab.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#define SYMSIZE   8
#define NROOTS    16
#define DATA_LEN  239
#define SUBBLOCKS 16
#define BLOCK_BYTES (DATA_LEN * SUBBLOCKS)

/* GF(2^8) with the primitive polynomial rslib uses: x^8+x^4+x^3+x^2+1. */
#define GFPOLY 0x11d
static uint8_t alpha_to[256], index_of[256];

static void gf_init(void)
{
	int i, x = 1;

	for (i = 0; i < 255; i++) {
		alpha_to[i] = (uint8_t)x;
		index_of[x] = (uint8_t)i;
		x <<= 1;
		if (x & 0x100)
			x ^= GFPOLY;
	}
	alpha_to[255] = 0;
	index_of[0] = 0;
}

static uint8_t gf_mul(uint8_t a, uint8_t b)
{
	if (!a || !b)
		return 0;
	return alpha_to[(index_of[a] + index_of[b]) % 255];
}

/* Generator polynomial for NROOTS parity symbols. */
static uint8_t genpoly[NROOTS + 1];

static void gen_init(void)
{
	int i, j;

	memset(genpoly, 0, sizeof(genpoly));
	genpoly[0] = 1;
	for (i = 0; i < NROOTS; i++) {
		for (j = i + 1; j > 0; j--)
			genpoly[j] = genpoly[j - 1] ^ gf_mul(genpoly[j], alpha_to[i]);
		genpoly[0] = gf_mul(genpoly[0], alpha_to[i]);
	}
}

/* Systematic encode of one shortened codeword. */
static void encode_one(const uint8_t *data, uint8_t *par)
{
	int i, j;

	memset(par, 0, NROOTS);
	for (i = 0; i < DATA_LEN; i++) {
		uint8_t fb = data[i] ^ par[0];

		for (j = 0; j < NROOTS - 1; j++)
			par[j] = par[j + 1] ^ gf_mul(fb, genpoly[NROOTS - 1 - j]);
		par[NROOTS - 1] = gf_mul(fb, genpoly[0]);
	}
}

/* Syndrome computation: what a decode pays on undamaged data, which is
 * the case every read pays whether or not anything is wrong.
 */
static int syndromes(const uint8_t *data, const uint8_t *par, uint8_t *syn)
{
	int i, j, nonzero = 0;

	for (i = 0; i < NROOTS; i++) {
		uint8_t s = 0;

		for (j = 0; j < DATA_LEN; j++)
			s = data[j] ^ gf_mul(s, alpha_to[i]);
		for (j = 0; j < NROOTS; j++)
			s = par[j] ^ gf_mul(s, alpha_to[i]);
		syn[i] = s;
		if (s)
			nonzero = 1;
	}
	return nonzero;
}

static double now_s(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
	long iters = argc > 1 ? atol(argv[1]) : 1000;
	uint8_t *data = malloc(BLOCK_BYTES);
	uint8_t par[SUBBLOCKS][NROOTS];
	uint8_t syn[NROOTS];
	double t0, enc, dec;
	volatile long sink;
	long i;
	int s;

	gf_init();
	gen_init();
	for (i = 0; i < BLOCK_BYTES; i++)
		data[i] = (uint8_t)(rand() & 0xff);

	t0 = now_s();
	for (i = 0; i < iters; i++)
		for (s = 0; s < SUBBLOCKS; s++)
			encode_one(data + s * DATA_LEN, par[s]);
	enc = now_s() - t0;

	/*
	 * sink consumes the result. Without it the optimiser sees a pure
	 * function whose value is discarded and deletes the loop: the
	 * first run of this reported 3 ns per block and 1.1 TB/s, which
	 * is what measuring nothing looks like.
	 */
	sink = 0;
	t0 = now_s();
	for (i = 0; i < iters; i++)
		for (s = 0; s < SUBBLOCKS; s++)
			sink += syndromes(data + s * DATA_LEN, par[s], syn) + syn[0];
	dec = now_s() - t0;

	printf("ITERS=%ld\n", iters);
	printf("BLOCK_BYTES=%d\n", BLOCK_BYTES);
	printf("ENCODE_NS_PER_BLOCK=%.0f\n", enc / (double)iters * 1e9);
	printf("DECODE_NS_PER_BLOCK=%.0f\n", dec / (double)iters * 1e9);
	printf("ENCODE_MB_PER_SEC=%.1f\n",
	       (double)iters * BLOCK_BYTES / enc / 1e6);
	printf("DECODE_MB_PER_SEC=%.1f\n",
	       (double)iters * BLOCK_BYTES / dec / 1e6);
	if (sink == 0x7fffffff)
		printf("unreachable\n");
	free(data);
	return 0;
}
