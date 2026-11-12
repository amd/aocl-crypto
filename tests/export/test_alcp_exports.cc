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
 *
 */

#include <cstdlib>
#include <dlfcn.h>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace {

void*
openAlcpLibrary()
{
    void* handle = dlopen(ALCP_EXPORT_LIBRARY, RTLD_LAZY);
    if (handle == nullptr) {
        ADD_FAILURE() << "dlopen failed: " << dlerror();
    }
    return handle;
}

std::vector<std::string>
loadManifest(const char* path)
{
    std::ifstream in(path);
    EXPECT_TRUE(in.good()) << "Cannot read manifest: " << path;
    std::vector<std::string> symbols;
    std::string              line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        symbols.push_back(line);
    }
    return symbols;
}

std::vector<std::string>
loadExpectedSymbols()
{
    return loadManifest(ALCP_EXPORT_SYMBOLS_MANIFEST);
}

} // namespace

TEST(AlcpExports, AllDocumentedSymbolsAreExported)
{
    void* handle = openAlcpLibrary();
    ASSERT_NE(handle, nullptr);

    const auto symbols = loadExpectedSymbols();
    ASSERT_FALSE(symbols.empty());

    for (const auto& sym : symbols) {
        dlerror();
        void*       addr = dlsym(handle, sym.c_str());
        const char* err  = dlerror();
        EXPECT_NE(addr, nullptr) << sym << ": " << (err ? err : "unknown");
    }

    dlclose(handle);
}

TEST(AlcpExports, NoInternalSymbolsLeaked)
{
#if !ALCP_HIDDEN_VISIBILITY_ENABLED
    GTEST_SKIP() << "hidden visibility disabled";
#else
    const std::string command =
        std::string("\"") + ALCP_EXPORT_CHECKER + "\" --library \"" +
        ALCP_EXPORT_LIBRARY + "\" --c-manifest \"" +
        ALCP_EXPORT_SYMBOLS_MANIFEST + "\" --cpp-manifest \"" +
        ALCP_EXPORT_CPP_EXCEPTIONS_MANIFEST + "\"";
    EXPECT_EQ(std::system(command.c_str()), 0);
#endif
}

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
