#include <benchmarks.hh>

int
CipherAes(benchmark::State& state,
          uint64_t          blockSize,
          encypt_t          enc,
          alc_aes_mode_t    alcpMode,
          size_t            keylen)
{
    // alc_error_t error = ALC_ERROR_NONE;
    // Dynamic allocation better for larger sizes
    uint8_t* in  = new uint8_t[blockSize];
    uint8_t* out = new uint8_t[blockSize];
    uint8_t  key[keylen / 8];
    uint8_t  iv[16];

    alcp::testing::AlcpCipherBase acb =
        alcp::testing::AlcpCipherBase(alcpMode, iv, key, keylen);

    alcp::testing::CipherBase* cb = &acb;

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

    delete[] in;
    delete[] out;
    return 0;
}

static void
BENCH_AES_ENCRYPT_CBC_128(benchmark::State& state)
{
    benchmark::DoNotOptimize(
        CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CBC, 128));
}
BENCHMARK(BENCH_AES_ENCRYPT_CBC_128)
    ->ArgsProduct({ { 16, 64, 1024, 8192, 16384 } });

static void
BENCH_AES_ENCRYPT_CTR_128(benchmark::State& state)
{
    CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CTR, 128);
}
BENCHMARK(BENCH_AES_ENCRYPT_CTR_128)
    ->ArgsProduct({ { 16, 64, 1024, 8192, 16384 } });

static void
BENCH_AES_ENCRYPT_OFB_128(benchmark::State& state)
{
    CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_OFB, 128);
}
BENCHMARK(BENCH_AES_ENCRYPT_OFB_128)
    ->ArgsProduct({ { 16, 64, 1024, 8192, 16384 } });

static void
BENCH_AES_ENCRYPT_CFB_128(benchmark::State& state)
{
    CipherAes(state, state.range(0), ENCRYPT, ALC_AES_MODE_CFB, 128);
}
BENCHMARK(BENCH_AES_ENCRYPT_CFB_128)
    ->ArgsProduct({ { 16, 64, 1024, 8192, 16384 } });

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
BENCHMARK(BENCH_AES_DECRYPT_CBC_128)
    ->ArgsProduct({ { 16, 64, 1024, 8192, 16384 } });

static void
BENCH_AES_DECRYPT_CTR_128(benchmark::State& state)
{
    CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CTR, 128);
}
BENCHMARK(BENCH_AES_DECRYPT_CTR_128)
    ->ArgsProduct({ { 16, 64, 1024, 8192, 16384 } });

static void
BENCH_AES_DECRYPT_OFB_128(benchmark::State& state)
{
    CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_OFB, 128);
}
BENCHMARK(BENCH_AES_DECRYPT_OFB_128)
    ->ArgsProduct({ { 16, 64, 1024, 8192, 16384 } });

static void
BENCH_AES_DECRYPT_CFB_128(benchmark::State& state)
{
    CipherAes(state, state.range(0), DECRYPT, ALC_AES_MODE_CFB, 128);
}
BENCHMARK(BENCH_AES_DECRYPT_CFB_128)
    ->ArgsProduct({ { 16, 64, 1024, 8192, 16384 } });

int
main(int argc, char** argv)
{
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    ::benchmark::RunSpecifiedBenchmarks();
    return 0;
}