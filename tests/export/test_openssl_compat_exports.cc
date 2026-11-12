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

#include <dlfcn.h>
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <vector>

#ifndef OPENSSL_COMPAT_LIB_PATH
#error "OPENSSL_COMPAT_LIB_PATH must be defined"
#endif

namespace {

void*
openCompatLibrary()
{
    void* handle = dlopen(OPENSSL_COMPAT_LIB_PATH, RTLD_LAZY);
    if (handle == nullptr) {
        ADD_FAILURE() << "dlopen failed: " << dlerror();
    }
    return handle;
}

#if ALCP_HIDDEN_VISIBILITY_ENABLED
std::string
runCommand(const std::string& cmd)
{
    std::string output;
    FILE*       pipe = popen(cmd.c_str(), "r");
    if (pipe == nullptr) {
        return output;
    }
    char buffer[512];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    pclose(pipe);
    return output;
}
#endif

} // namespace

TEST(OpensslCompatExports, ProviderEntryIsExported)
{
    void* handle = openCompatLibrary();
    ASSERT_NE(handle, nullptr);

    dlerror();
    void* addr = dlsym(handle, "OSSL_provider_init");
    const char* err = dlerror();
    EXPECT_NE(addr, nullptr) << (err ? err : "unknown");

    dlclose(handle);
}

TEST(OpensslCompatExports, NoInternalProviderSymbolsLeaked)
{
#if !ALCP_HIDDEN_VISIBILITY_ENABLED
    GTEST_SKIP() << "hidden visibility disabled";
#else
    const std::string nm_cmd =
        std::string("nm -D --defined-only \"") + OPENSSL_COMPAT_LIB_PATH +
        "\" 2>/dev/null";
    const std::string nm_out = runCommand(nm_cmd);
    ASSERT_FALSE(nm_out.empty());

    std::istringstream stream(nm_out);
    std::string        line;
    while (std::getline(stream, line)) {
        std::istringstream fields(line);
        std::string        field;
        std::string        symbol;
        while (fields >> field) {
            symbol = field;
        }
        ASSERT_FALSE(symbol.empty()) << line;
        EXPECT_EQ(symbol, "OSSL_provider_init")
            << "unexpected provider export: " << line;
    }
#endif
}

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
