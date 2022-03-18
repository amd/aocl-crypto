#pragma once

#include "alc_base.hh"
#include "base.hh"
#include "string.h"
#include <alcp/alcp.h>
#include <benchmark/benchmark.h>
#include <iostream>

void CipherAes(benchmark::State &state, uint64_t blockSize, bool enc,
               alc_aes_mode_t alcpMode, size_t keylen) {
  // alc_error_t error = ALC_ERROR_NONE;
  uint8_t in[blockSize];
  uint8_t out[blockSize];
  uint8_t key[keylen / 8];
  uint8_t iv[16];
  alcp::testing::CipherBase *cb =
      new alcp::testing::AlcpCipherBase(alcpMode, iv, key, keylen);
  // CBC ENC thing
  for (auto _ : state) {
    if (enc)
      cb->encrypt(in, blockSize, out);
    else
      cb->decrypt(in, blockSize, out);
  }
  state.counters["Speed(Bytes/s)"] = benchmark::Counter(
      state.iterations() * blockSize, benchmark::Counter::kIsRate);
  state.counters["BlockSize(Bytes)"] = blockSize;
}
static void BENCH_AES_CBC_128_16K(benchmark::State &state) {
  CipherAes(state, 16384, true, ALC_AES_MODE_CBC, 128);
}
BENCHMARK(BENCH_AES_CBC_128_16K);

// void Digest_SHA2_256(benchmark::State &state, uint64_t block_size) {
//   alc_error_t error;
//   uint8_t message[16384] = {0};
//   uint8_t digest[512] = {0};
//   for (auto _ : state) {
//     AlcpDigestBase DigestBase(ALC_SHA2_256, ALC_DIGEST_TYPE_SHA2,
//                               ALC_DIGEST_LEN_256);
//     error =
//         DigestBase.digest_function(message, block_size, digest,
//         sizeof(digest));
//     if (alcp_is_error(error)) {
//       printf("Error in running benchmark");
//       return;
//     }
//   }
//   state.counters["Speed(Bytes/s)"] = benchmark::Counter(
//       state.iterations() * block_size, benchmark::Counter::kIsRate);
//   state.counters["BlockSize(Bytes)"] = block_size;
//   return;
// }

// void Digest_SHA2_384(benchmark::State &state, uint64_t block_size) {
//   alc_error_t error;
//   uint8_t message[16384] = {0};
//   uint8_t digest[512] = {0};
//   for (auto _ : state) {
//     AlcpDigestBase DigestBase(ALC_SHA2_384, ALC_DIGEST_TYPE_SHA2,
//                               ALC_DIGEST_LEN_384);
//     error =
//         DigestBase.digest_function(message, block_size, digest,
//         sizeof(digest));
//     if (alcp_is_error(error)) {
//       printf("Error in running benchmark");
//       return;
//     }
//   }
//   state.counters["Speed(Bytes/s)"] = benchmark::Counter(
//       state.iterations() * block_size, benchmark::Counter::kIsRate);
//   state.counters["BlockSize(Bytes)"] = block_size;
//   return;
// }

// void Digest_SHA2_512(benchmark::State &state, uint64_t block_size) {
//   alc_error_t error;
//   uint8_t message[16384] = {0};
//   uint8_t digest[512] = {0};
//   for (auto _ : state) {
//     AlcpDigestBase DigestBase(ALC_SHA2_512, ALC_DIGEST_TYPE_SHA2,
//                               ALC_DIGEST_LEN_512);
//     error =
//         DigestBase.digest_function(message, block_size, digest,
//         sizeof(digest));
//     if (alcp_is_error(error)) {
//       printf("Error in running benchmark");
//       return;
//     }
//   }
//   state.counters["Speed(Bytes/s)"] = benchmark::Counter(
//       state.iterations() * block_size, benchmark::Counter::kIsRate);
//   state.counters["BlockSize(Bytes)"] = block_size;
//   return;
// }

// /* add all your new benchmarks here */
// static void BENCH_SHA2_224_16(benchmark::State &state) {
//   Digest_SHA2_224(state, 16);
// }
// BENCHMARK(BENCH_SHA2_224_16);

// static void BENCH_SHA2_224_64(benchmark::State &state) {
//   Digest_SHA2_224(state, 64);
// }
// BENCHMARK(BENCH_SHA2_224_64);

// static void BENCH_SHA2_224_256(benchmark::State &state) {
//   Digest_SHA2_224(state, 256);
// }
// BENCHMARK(BENCH_SHA2_224_256);

// static void BENCH_SHA2_224_1024(benchmark::State &state) {
//   Digest_SHA2_224(state, 1024);
// }
// BENCHMARK(BENCH_SHA2_224_1024);

// static void BENCH_SHA2_224_8192(benchmark::State &state) {
//   Digest_SHA2_224(state, 8192);
// }
// BENCHMARK(BENCH_SHA2_224_8192);

// static void BENCH_SHA2_224_16384(benchmark::State &state) {
//   Digest_SHA2_224(state, 16384);
// }
// BENCHMARK(BENCH_SHA2_224_16384);

// /*256*/
// /* add all your new benchmarks here */
// static void BENCH_SHA2_256_16(benchmark::State &state) {
//   Digest_SHA2_256(state, 16);
// }
// BENCHMARK(BENCH_SHA2_256_16);

// static void BENCH_SHA2_256_64(benchmark::State &state) {
//   Digest_SHA2_256(state, 64);
// }
// BENCHMARK(BENCH_SHA2_256_64);

// static void BENCH_SHA2_256_256(benchmark::State &state) {
//   Digest_SHA2_256(state, 256);
// }
// BENCHMARK(BENCH_SHA2_256_256);

// static void BENCH_SHA2_256_1024(benchmark::State &state) {
//   Digest_SHA2_256(state, 1024);
// }
// BENCHMARK(BENCH_SHA2_256_1024);

// static void BENCH_SHA2_256_8192(benchmark::State &state) {
//   Digest_SHA2_256(state, 8192);
// }
// BENCHMARK(BENCH_SHA2_256_8192);

// static void BENCH_SHA2_256_16384(benchmark::State &state) {
//   Digest_SHA2_256(state, 16384);
// }
// BENCHMARK(BENCH_SHA2_256_16384);

// /*384*/
// static void BENCH_SHA2_384_16(benchmark::State &state) {
//   Digest_SHA2_384(state, 16);
// }
// BENCHMARK(BENCH_SHA2_384_16);

// static void BENCH_SHA2_384_64(benchmark::State &state) {
//   Digest_SHA2_384(state, 64);
// }
// BENCHMARK(BENCH_SHA2_384_64);

// static void BENCH_SHA2_384_256(benchmark::State &state) {
//   Digest_SHA2_384(state, 256);
// }
// BENCHMARK(BENCH_SHA2_384_256);

// static void BENCH_SHA2_384_1024(benchmark::State &state) {
//   Digest_SHA2_384(state, 1024);
// }
// BENCHMARK(BENCH_SHA2_384_1024);

// static void BENCH_SHA2_384_8192(benchmark::State &state) {
//   Digest_SHA2_384(state, 8192);
// }
// BENCHMARK(BENCH_SHA2_384_8192);

// static void BENCH_SHA2_384_16384(benchmark::State &state) {
//   Digest_SHA2_384(state, 16384);
// }
// BENCHMARK(BENCH_SHA2_384_16384);

// /*SHA512*/
// static void BENCH_SHA2_512_16(benchmark::State &state) {
//   Digest_SHA2_512(state, 16);
// }
// BENCHMARK(BENCH_SHA2_512_16);

// static void BENCH_SHA2_512_64(benchmark::State &state) {
//   Digest_SHA2_512(state, 64);
// }
// BENCHMARK(BENCH_SHA2_512_64);

// static void BENCH_SHA2_512_256(benchmark::State &state) {
//   Digest_SHA2_512(state, 256);
// }
// BENCHMARK(BENCH_SHA2_512_256);

// static void BENCH_SHA2_512_1024(benchmark::State &state) {
//   Digest_SHA2_512(state, 1024);
// }
// BENCHMARK(BENCH_SHA2_512_1024);

// static void BENCH_SHA2_512_8192(benchmark::State &state) {
//   Digest_SHA2_512(state, 8192);
// }
// BENCHMARK(BENCH_SHA2_512_8192);

// static void BENCH_SHA2_512_16384(benchmark::State &state) {
//   Digest_SHA2_512(state, 16384);
// }
// BENCHMARK(BENCH_SHA2_512_16384);