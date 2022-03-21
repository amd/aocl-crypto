#include <benchmarks.hh>
#include <gbench_base.hh>

// Test blocksizes, append more if needed, size is in bytes
std::vector<int64_t> blocksizes = { 16, 64, 256, 1024, 8192, 16384 };

int
CipherAes(benchmark::State& state,
          uint64_t          blockSize,
          encrypt_t         enc,
          alc_aes_mode_t    alcpMode,
          size_t            keylen)
{
    // Dynamic allocation better for larger sizes
    std::vector<uint8_t>       vec_in(blockSize, 1);
    std::vector<uint8_t>       vec_out(blockSize, 10);
    uint8_t                    key[keylen / 8];
    uint8_t                    iv[16];
    alcp::testing::CipherBase* cb;
#ifdef USE_IPP
    alcp::testing::IPPCipherBase icb =
        alcp::testing::IPPCipherBase(alcpMode, iv, key, keylen);
    alcp::testing::AlcpCipherBase acb =
        alcp::testing::AlcpCipherBase(alcpMode, iv, key, keylen);
    if (useipp) {
        cb = &icb;
    } else {
        cb = &acb;
    }
#else
    alcp::testing::AlcpCipherBase acb =
        alcp::testing::AlcpCipherBase(alcpMode, iv, key, keylen);
    cb = &acb;
#endif
    for (auto _ : state) {
        if (enc) {
            if (cb->encrypt(&(vec_in[0]), blockSize, &(vec_out[0])) == false) {
                std::cout << "BENCH_ENC_FAILURE" << std::endl;
            }
        } else if (cb->decrypt(&(vec_in[0]), blockSize, &(vec_out[0]))
                   == false) {
            std::cout << "BENCH_DEC_FAILURE" << std::endl;
        }
    }
    state.counters["Speed(Bytes/s)"] = benchmark::Counter(
        state.iterations() * blockSize, benchmark::Counter::kIsRate);
    state.counters["BlockSize(Bytes)"] = blockSize;

    return 0;
}

// TODO: Implement for 192,256 bit keysizes

/**
 * @brief Encrypt
 *
 * @param state Google Bench state
 */

static void
BENCH_AES_ENCRYPT_CBC_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CBC, 128));
}
BENCHMARK(BENCH_AES_ENCRYPT_CBC_128)->ArgsProduct({ blocksizes });

static void
BENCH_AES_ENCRYPT_CTR_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CTR, 128));
}
BENCHMARK(BENCH_AES_ENCRYPT_CTR_128)->ArgsProduct({ blocksizes });

static void
BENCH_AES_ENCRYPT_OFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_OFB, 128));
}
BENCHMARK(BENCH_AES_ENCRYPT_OFB_128)->ArgsProduct({ blocksizes });

static void
BENCH_AES_ENCRYPT_CFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 128));
}
BENCHMARK(BENCH_AES_ENCRYPT_CFB_128)->ArgsProduct({ blocksizes });

/**
 * @brief Decrypt
 *
 * @param state Google Bench state
 */

static void
BENCH_AES_DECRYPT_CBC_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CBC, 128));
}
BENCHMARK(BENCH_AES_DECRYPT_CBC_128)->ArgsProduct({ blocksizes });

static void
BENCH_AES_DECRYPT_CTR_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CTR, 128));
}
BENCHMARK(BENCH_AES_DECRYPT_CTR_128)->ArgsProduct({ blocksizes });

static void
BENCH_AES_DECRYPT_OFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_OFB, 128));
}
BENCHMARK(BENCH_AES_DECRYPT_OFB_128)->ArgsProduct({ blocksizes });

static void
BENCH_AES_DECRYPT_CFB_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CFB, 128));
}
BENCHMARK(BENCH_AES_DECRYPT_CFB_128)->ArgsProduct({ blocksizes });

int
main(int argc, char** argv)
{
    parseArgs(&argc, argv);
#ifndef USE_IPP
    if (useipp) {
        std::cout << "Error IPP not found defaulting to ALCP" << std::endl;
    }
#endif
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    ::benchmark::RunSpecifiedBenchmarks();

    return 0;
}