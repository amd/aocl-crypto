/*
 * Copyright (C) 2026, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#pragma once

#include "colors.hh"
#include <cstdint>
#include <iostream>
#include <string>

namespace alcp::bench::args {

/* Holds every custom flag recognised by the AOCL-Crypto arg parsers. */
struct ParsedArgs
{
    bool     use_ipp        = false;
    bool     use_ossl       = false;
    bool     use_alcp       = false;
    bool     override_alcp  = false;
    bool     help_requested = false;
    int      block_size     = 0;
    /* test-only flags (bench parsers leave these at defaults) */
    int      verbose        = 0;
    bool     replay_blackbox = false;
    bool     seed_set       = false;
    uint64_t seed           = 0;
};

/* Compacts argv[] in-place, consuming all recognised custom flags and their
 * values.  Unrecognised args are preserved so google benchmark / gtest can
 * handle them.  --help/-h is normalised to --help so downstream handlers
 * (benchmark::Initialize / testing::InitGoogleTest) exit cleanly. */
inline void
strip_custom_args(int* argc, char** argv, ParsedArgs& out)
{
    static char kHelpFlag[] = "--help";
    int         newArgc     = 1;
    int         i           = 1;

    while (i < *argc) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            out.help_requested = true;
            argv[newArgc++]    = (arg == "--help") ? argv[i] : kHelpFlag;
            i++;
        } else if (arg == "--use-ipp" || arg == "-i") {
            out.use_ipp = true;
            i++;
        } else if (arg == "--use-ossl" || arg == "-o") {
            out.use_ossl = true;
            i++;
        } else if (arg == "--use-alcp" || arg == "-a") {
            out.use_alcp = true;
            i++;
        } else if (arg == "--override-alcp" || arg == "-oa") {
            out.override_alcp = true;
            i++;
        } else if (arg == "--blocksize" || arg == "-b") {
            if (i + 1 < *argc) {
                try {
                    out.block_size = std::stoi(argv[i + 1]);
                } catch (const std::invalid_argument&) {
                    std::cerr << RED << argv[i + 1]
                              << " is not an integer or invalid block size."
                              << RESET << std::endl;
                }
                i += 2;
            } else {
                std::cerr << RED << "No block size provided" << RESET
                          << std::endl;
                i++;
            }
        } else if (arg == "--verbose" || arg == "-v") {
            if (i + 1 < *argc) {
                std::string level = argv[i + 1];
                if (level == "0" || level == "1" || level == "2") {
                    out.verbose = std::stoi(level);
                } else {
                    std::cerr << RED << "Invalid verbosity level \"" << level
                              << "\" (expected 0, 1, or 2)" << RESET
                              << std::endl;
                }
                i += 2;
            } else {
                std::cerr << RED << "No verbosity level provided" << RESET
                          << std::endl;
                i++;
            }
        } else if (arg == "--replay-blackbox" || arg == "-r") {
            out.replay_blackbox = true;
            i++;
        } else if (arg == "--seed" || arg == "-s") {
            if (i + 1 < *argc) {
                try {
                    out.seed     = std::stoull(argv[i + 1], nullptr, 0);
                    out.seed_set = true;
                } catch (const std::exception&) {
                    std::cerr << RED << "Invalid seed value \"" << argv[i + 1]
                              << "\"" << RESET << std::endl;
                }
                i += 2;
            } else {
                std::cerr << RED << "No seed value provided" << RESET
                          << std::endl;
                i++;
            }
        } else {
            argv[newArgc++] = argv[i++];
        }
    }
    argv[newArgc] = nullptr;
    *argc         = newArgc;
}

/* Prints the AOCL-Crypto custom options section.  Call before
 * benchmark::Initialize() so google benchmark's own help follows. */
inline void
print_bench_help()
{
    std::cout << "\nAOCL-Crypto Benchmark Options:\n"
              << "  -i, --use-ipp        Benchmark against IPPCP\n"
              << "  -o, --use-ossl       Benchmark against OpenSSL\n"
              << "  -a, --use-alcp       Benchmark against ALCP explicitly\n"
              << "  -b, --blocksize <n>  Use custom input block size "
                 "(bytes)\n\n"
              << "Google Benchmark Options (forwarded):\n";
}

/* Prints the AOCL-Crypto custom options section for test executables.
 * Call before testing::InitGoogleTest() so gtest's own help follows. */
inline void
print_test_help()
{
    std::cout << "\nAOCL-Crypto Test Options:\n"
              << "  -i, --use-ipp              Test against IPPCP\n"
              << "  -o, --use-ossl             Test against OpenSSL\n"
              << "  -a, --use-alcp             Test against ALCP explicitly\n"
              << "  -oa, --override-alcp       Override ALCP with reference\n"
              << "  -b, --blocksize <n>        Custom input block size (bytes)\n"
              << "  -v, --verbose <0|1|2>      Verbosity level (default 0)\n"
              << "  -r, --replay-blackbox      Replay blackbox with log file\n"
              << "  -s, --seed <N>             Fix RNG seed (decimal or 0x hex) "
                 "to reproduce a prior run\n\n"
              << "GTest Options (forwarded):\n";
}

} // namespace alcp::bench::args
