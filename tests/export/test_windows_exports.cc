/*
 * Copyright (C) 2022-2026, Advanced Micro Devices. All rights reserved.
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

#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <windows.h>

namespace {

std::vector<std::string>
loadManifest(const char* path)
{
    std::ifstream            input(path);
    std::vector<std::string> symbols;
    std::string              line;
    while (std::getline(input, line)) {
        if (!line.empty() && line[0] != '#') {
            symbols.push_back(line);
        }
    }
    return symbols;
}

void
expectExports(const char* library_path, const std::vector<std::string>& symbols)
{
    HMODULE library = LoadLibraryA(library_path);
    ASSERT_NE(library, nullptr) << library_path << ": " << GetLastError();
    ASSERT_FALSE(symbols.empty());
    for (const auto& symbol : symbols) {
        EXPECT_NE(GetProcAddress(library, symbol.c_str()), nullptr) << symbol;
    }
    FreeLibrary(library);
}

} // namespace

TEST(WindowsExports, AlcpPublicApiIsExported)
{
    expectExports(ALCP_EXPORT_LIBRARY,
                  loadManifest(ALCP_EXPORT_SYMBOLS_MANIFEST));
}

#ifdef OPENSSL_COMPAT_LIB_PATH
TEST(WindowsExports, OpenSslProviderEntryIsExported)
{
    expectExports(OPENSSL_COMPAT_LIB_PATH, { "OSSL_provider_init" });
}
#endif

#ifdef IPP_COMPAT_LIB_PATH
TEST(WindowsExports, IppManifestIsExported)
{
    expectExports(IPP_COMPAT_LIB_PATH,
                  loadManifest(IPP_COMPAT_SYMBOLS_MANIFEST));
}
#endif

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
