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

#include "alcp/utils/logger.hh"

namespace alcp::utils {

class Color
{
  public:
    enum Name
    {
        eDefault, // Default color that console is configured with
        eWhite,
        eBlack,
        eRed,
        eGreen,
        eBlue,
        eYellow,
        eBrown,
        eMagenta,
        eAqua,
        eGray,
    };
};

class Console
{
  public:
    enum Ground
    {
        eForeground,
        eBackground,
    };
    enum class Attribute : Uint32
    {
        eDefault   = 0,
        eBold      = 1,
        eDim       = 2,
        eItalics   = 3,
        eUnderline = 4,
        eBlink     = 5,
        eReverse   = 6,
        eHidden    = 7,
    };
    enum class ResetAttribute : Uint32
    {
        eAll       = 0,
        eBold      = 21,
        eDim       = 22,
        eItalics   = 23,
        eUnderline = 24,
        eBlink     = 25,
        eReverse   = 27,
        eHidden    = 28,
    };

    /* Regular Text */
    const std::map<Color::Name, std::string> m_ascii_str = {
        { Color::eDefault, "\\e[0;37m" }, { Color::eWhite, "\\e[0;37m" },
        { Color::eBlack, "\\e[0;30m" },   { Color::eRed, "\\e[0;31m" },
        { Color::eGreen, "\\e[0;32m" },   { Color::eBlue, "\\e[0;34m" },
        { Color::eYellow, "\\e[0;33m" },  { Color::eBrown, "\\e[0;33m" },
        { Color::eMagenta, "\\e[0;35m" }, { Color::eAqua, "\\e[0;36m" },
        { Color::eGray, "\\e[0;30m" },
    };

    /* Regular Bold */
    const std::map<Color::Name, std::string> m_ascii_bold_str = {
        { Color::eDefault, "\\e[1;37m" }, { Color::eWhite, "\\e[1;37m" },
        { Color::eBlack, "\\e[1;30m" },   { Color::eRed, "\\e[1;31m" },
        { Color::eGreen, "\\e[1;32m" },   { Color::eBlue, "\\e[1;34m" },
        { Color::eYellow, "\\e[1;33m" },  { Color::eBrown, "\\e[1;33m" },
        { Color::eMagenta, "\\e[1;35m" }, { Color::eAqua, "\\e[1;36m" },
        { Color::eGray, "\\e[1;30m" },
    };

    const std::map<Color::Name, std::string> m_ascii_bolder_str = {
        { Color::eDefault, "\\e[1;97m" }, { Color::eWhite, "\\e[1;97m" },
        { Color::eBlack, "\\e[1;90m" },   { Color::eRed, "\\e[1;91m" },
        { Color::eGreen, "\\e[1;92m" },   { Color::eBlue, "\\e[1;94m" },
        { Color::eYellow, "\\e[1;93m" },  { Color::eBrown, "\\e[1;93m" },
        { Color::eMagenta, "\\e[1;95m" }, { Color::eAqua, "\\e[1;96m" },
        { Color::eGray, "\\e[1;90m" },
    };

    void setColor(const Color::Name n) const;
    void reset() const;
    void setBgColor(Color::Name n) const;
    void setFgColor(Color::Name n) const;
    void setAttribute(Attribute e) const;
    void coloredWrite(Color::Name n, const std::string& msg) const;

  private:
    static const std::string s_reset_str;
};

const std::string Console::s_reset_str{ "\\e[0m" };

using Level = Priority::Level;

class ConsoleLogger::Impl
{
  public:
    bool debug(const Message& msg);
    void error(const Message& msg);
    void panic(const Message& msg);
    bool info(const Message& msg);
    bool notice(const Message& msg);
    bool trace(const Message& msg);

    void checkAndFlushQueue();
    void flushQueue()
    { // TODO : Implement this
        /*
         * m_console.setColor(s_levelmap.at(Level::eDebug));
         * m_console.setColor(s_levelmap.at(Level::eInfo));
         * m_console.setColor(s_levelmap.at(Level::ePanic));
         * m_console.setColor(s_levelmap.at(Level::eError));
         * m_console.setColor(s_levelmap.at(Level::eTrace));
         */
        std::scoped_lock lock(m_mutex);
        for (auto msg = m_msgs.begin(); msg != m_msgs.end();) {
            std::cout << msg->c_str() << std::endl;
            m_msgs.erase(msg);
        }
    }

  private:
    static const std::map<Level, Color::Name> s_levelmap;
    std::mutex                                m_mutex;
    Console                                   m_console;
    Uint32 m_threashold_size = 10; /* Number of messages to keep in vector */
    std::vector<Message> m_msgs;
};

const std::map<Level, Color::Name> ConsoleLogger::Impl::s_levelmap = {
    { Level::eFatal, Color::eRed },       { Level::eError, Color::eRed },
    { Level::eWarning, Color::eMagenta }, { Level::eNotice, Color::eYellow },
    { Level::eInfo, Color::eGreen },      { Level::eDebug, Color::eBlue },
    { Level::eTrace, Color::eBrown },
};

bool
ConsoleLogger::Impl::debug(const Message& msg)
{
    m_msgs.push_back(msg);
    checkAndFlushQueue();

    return true;
}

void
ConsoleLogger::Impl::error(const Message& msg)
{
    flushQueue();

    std::abort();
}

void
ConsoleLogger::Impl::panic(const Message& msg)
{
    m_msgs.push_back(msg);
    flushQueue();

    std::abort();
}

void
ConsoleLogger::Impl::checkAndFlushQueue()
{
    if (m_msgs.size() > m_threashold_size)
        flushQueue();
}

bool
ConsoleLogger::Impl::info(const Message& msg)
{
    m_msgs.push_back(msg);

    checkAndFlushQueue();

    return true;
}

bool
ConsoleLogger::Impl::notice(const Message& msg)
{
    m_msgs.push_back(msg);
    checkAndFlushQueue();
    return true;
}

bool
ConsoleLogger::Impl::trace(const Message& msg)
{
    m_msgs.push_back(msg);
    checkAndFlushQueue();
    return true;
}

ConsoleLogger::ConsoleLogger()
    : Logger{ std::string("Default Logger") }
{
}

ConsoleLogger::ConsoleLogger(const std::string& name)
    : Logger{ std::string(name) }
{
}

ConsoleLogger::ConsoleLogger(const std::string& name, Priority::Level lvl)
    : Logger{ std::string(name) }
{
    m_allowed_priority = lvl;
    m_pimpl            = std::make_unique<ConsoleLogger::Impl>();
}

ConsoleLogger::~ConsoleLogger() {}

bool
ConsoleLogger::debug(const Message& msg)
{
    return pImpl()->debug(msg);
}

bool
ConsoleLogger::error(const Message& msg)
{
    m_pimpl->error(msg);
    return false; // though this never returns
}

void
ConsoleLogger::panic(const Message& msg)
{
    m_pimpl->panic(msg);
}

bool
ConsoleLogger::info(const Message& msg)
{
    return m_pimpl->info(msg);
}

bool
ConsoleLogger::notice(const Message& msg)
{
    return m_pimpl->notice(msg);
}

bool
ConsoleLogger::trace(const Message& msg)
{
    return m_pimpl->trace(msg);
}

} // namespace alcp::utils
