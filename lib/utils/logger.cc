/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

#include <map>
#include <string>

#include "utils/logger.hh"

//#include "utils/color.hh"

namespace alcp::utils {
/* g_s_logger: default logger */
static log::Logger* g_s_logger;

/* Any other logger created by individual modules are held here */
using logger_map = std::map<std::string, log::Logger*>;
static logger_map g_s_loggers_map;

namespace log {

    LogLevel   Logger::s_default_level = LogLevel::eInfo;
    LoggerType Logger::s_default_type  = LoggerType::eDummyLogger;

    void Logger::initialize()
    {

#ifdef DEBUG
        static log::Logger* g_s_logger = new log::ConsoleLogger;
#else
        g_s_logger = new log::DummyLogger();
#endif
    }

    Logger& Logger::getDefaultLogger() { return *g_s_logger; }

    class ConsoleLogger::Impl
    {};

    bool ConsoleLogger::debug(const std::string& msg)
    {
        // impl->print(Color::gray(m_level);)
        return false;
    }

    Logger& Logger::getLogger(const std::string& name)
    {
        if (name.empty()) {
            return getDefaultLogger();
        }

        logger_map::iterator it = g_s_loggers_map.find(name);

        if (it != g_s_loggers_map.end()) {
            /* found */
            return *(it)->second;
        }

        /* not found, create one */
        Logger* lg = createLogger(name);

        g_s_loggers_map[name] = lg;

        return *lg;
    }

    Logger* Logger::createLogger(const std::string& name,
                                 LoggerType         ltype,
                                 LogLevel           lvl)
    {
        return g_s_logger;
    }

    LoggerInterface::~LoggerInterface() {}
} // namespace log
} // namespace alcp::utils
