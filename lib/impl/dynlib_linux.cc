/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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
#include "alcp/dynlib.hh"

#include <dlfcn.h>

#include <mutex>

namespace alcp {
class DynamicLibrary::Impl
{
  public:
    Impl(const std::string& path)
        : m_path{ path }
    {}
    Impl(const std::string& path, int flags)
        : m_path{ path }
    {}
    ~Impl();

    void               load(const std::string& path, int flags);
    void               unload();
    bool               isLoaded() const;
    void*              getSymbol(const std::string& name);
    static std::string suffix();

  private:
    std::string m_path{};
    void*       m_handle = nullptr;
    std::mutex  m_mutex{};
};

DynamicLibrary::Impl::~Impl()
{
    if (m_handle) {
        dlclose(m_handle);
    }
}

void
DynamicLibrary::Impl::load(const std::string& path, int flags)
{
    m_mutex.lock();
    if (m_handle) {
        // already loaded
    }

    int load_flags = RTLD_LAZY;

    m_handle = dlopen(path.c_str(), load_flags);

    if (!m_handle) {
        // throw some exception
    }

    m_mutex.unlock();
}

void
DynamicLibrary::Impl::unload()
{
    if (m_handle) {
        dlclose(m_handle);
        m_handle = nullptr;
    }
}

bool
DynamicLibrary::Impl::isLoaded() const
{
    return m_handle != nullptr;
}

void*
DynamicLibrary::Impl::getSymbol(const std::string& name)
{
    m_mutex.lock();

    void* result = nullptr;
    if (m_handle) {
        result = dlsym(m_handle, name.c_str());
    }

    return result;
}

std::string
DynamicLibrary::Impl::suffix()
{
    std::string s;

    s += ".so";

    return s;
}
} // namespace alcp
