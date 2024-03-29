/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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
#include "alcp/types.hh"

enum DynLoadError : alcp::Uint32 {
  Success = 0,
  None = Success,

  LibNotFound,
  SymNotFound,
  Other,
};

#ifdef ALCP_BUILD_OS_LINUX
#include "impl/dynlib_linux.cc"
#else
#include "impl/dynlib_win.cc"
#endif

namespace alcp {

DynamicLibrary::DynamicLibrary(const std::string &path)
    : m_pimpl{std::make_unique<DynamicLibrary::Impl>(path)} {}

DynamicLibrary::DynamicLibrary(const std::string &path, int flags)
    : m_pimpl{std::make_unique<DynamicLibrary::Impl>(path, flags)} {}

bool DynamicLibrary::isLoaded() const { return m_pimpl->isLoaded(); }

void DynamicLibrary::load(const std::string &path) { m_pimpl->load(path, 0); }

void DynamicLibrary::load(const std::string &path, int flags) {
  m_pimpl->load(path, flags);
}

DynamicLibrary::~DynamicLibrary() {}

} // namespace alcp
