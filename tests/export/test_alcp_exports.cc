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

#include "config.h"

#include <dlfcn.h>
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <vector>

namespace {

void*
openAlcpLibrary()
{
    void* handle = dlopen(ALCP_LIB_OUTPUT_FILE_NAME_STRING, RTLD_LAZY);
    if (handle == nullptr) {
        ADD_FAILURE() << "dlopen failed: " << dlerror();
    }
    return handle;
}

std::vector<std::string>
loadExpectedSymbols()
{
    std::ifstream in(ALCP_EXPORT_SYMBOLS_MANIFEST);
    EXPECT_TRUE(in.good()) << "Cannot read manifest: "
                           << ALCP_EXPORT_SYMBOLS_MANIFEST;
    std::vector<std::string> symbols;
    std::string              line;
    while (std::getline(in, line)) {
        if (!line.empty()) {
            symbols.push_back(line);
        }
    }
    return symbols;
}

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

} // namespace

TEST(AlcpExports, AllDocumentedSymbolsAreExported)
{
    void* handle = openAlcpLibrary();
    ASSERT_NE(handle, nullptr);

    const auto symbols = loadExpectedSymbols();
    ASSERT_FALSE(symbols.empty());

    for (const auto& sym : symbols) {
        dlerror();
        void* addr = dlsym(handle, sym.c_str());
        const char* err = dlerror();
        EXPECT_NE(addr, nullptr) << sym << ": " << (err ? err : "unknown");
    }

    dlclose(handle);
}

TEST(AlcpExports, NoInternalSymbolsLeaked)
{
    const std::string nm_cmd = std::string("nm -D --defined-only \"") +
                               ALCP_LIB_OUTPUT_FILE_NAME_STRING + "\" 2>/dev/null";
    const std::string nm_out = runCommand(nm_cmd);
    ASSERT_FALSE(nm_out.empty()) << "nm produced no output";

    std::istringstream stream(nm_out);
    std::string        line;
    while (std::getline(stream, line)) {
        if (line.find(" T ") == std::string::npos) {
            continue;
        }
        EXPECT_EQ(line.find("_Z"), std::string::npos)
            << "mangled C++ symbol exported: " << line;
        EXPECT_EQ(line.find("EncryptCbc"), std::string::npos)
            << "internal arch symbol exported: " << line;
        EXPECT_EQ(line.find("TweakBlockCalculate"), std::string::npos)
            << "internal arch symbol exported: " << line;
        EXPECT_EQ(line.find("InitializeTweakBlock"), std::string::npos)
            << "internal arch symbol exported: " << line;
        EXPECT_EQ(line.find("ExpandTweakKeys"), std::string::npos)
            << "internal arch symbol exported: " << line;
        EXPECT_EQ(line.find("xor_a_b"), std::string::npos)
            << "internal arch symbol exported: " << line;
    }
}

int
main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
