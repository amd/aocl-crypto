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

#pragma once

#include "types.hh"

#include <chrono>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace alcp::utils {

class Priority
{
  public:
    enum Level
    {
        eFatal   = (1 << 0), /* Highest, Application will terminate (mostly) */
        ePanic   = (1 << 1), /* Application might not work as expected */
        eError   = (1 << 2), /* API wont complete, but app will continue */
        eWarning = (1 << 3), /* API completes (with error), app will continue */
        eNotice  = (1 << 4), /* Just like INFO but higher priority */
        eInfo    = (1 << 5), /* usually denoting successful completion  */
        eDebug   = (1 << 6), /* For debugging purpose only */
        eTrace   = (1 << 7), /* Lowest priority */
    };

  public:
    Priority() = default;
    ~Priority() {}

    Priority(const Level c)
        : m_level{ c }
    {}

    inline static const std::string& name(const Level& c)
    {
        static std::map<Level, std::string> str_map{
            { eFatal, "Fatal" },     { ePanic, "Panic" }, { eError, "Error" },
            { eWarning, "Warning" }, { eInfo, "Info" },   { eNotice, "Notice" },
            { eDebug, "Debug" }

        };

        return str_map[c];
    }

    inline bool operator==(const Priority& r)
    {
        return (int)m_level == r.m_level;
    }

    inline bool operator<(const Priority& r)
    {
        return (int)m_level < r.m_level;
    }

    inline bool operator<=(const Priority& r)
    {
        return (int)m_level == r.m_level;
    }

    inline bool operator>(const Priority& r)
    {
        return !((int)m_level <= r.m_level);
    }

    inline bool operator>=(const Priority& r)
    {
        return !((int)m_level < r.m_level);
    }

  private:
    Level m_level;
};

#include "types.hh"
class Time
{
    using clock = std::chrono::system_clock;

  public:
    using Stamp = Uint64;

  public:
    Time(Uint64 t) {}

    static Stamp now()
    {
        /*
        const std::time_t t = clock::to_time_t(now());
        return std::put_time(std::localtime(&t), "%F %T");
        */
        return 0x0000000;
    }

    Uint64 getHour(Stamp st) const;
    Uint64 getMinute(Stamp st) const;
    Uint64 getSeconds(Stamp st) const;
    Uint64 getMilliSeconds(Stamp st) const;
    Uint64 getMicroSeconds(Stamp st) const;
    Uint64 getNanoSeconds(Stamp st) const;
};

class Message
{
  public:
    Message(Priority prt, const std::string& s)
    {
        m_time = Time::now();
        m_text = s;
        m_prio = prt;
    }

    Message(const std::string s)
        : Message{ Priority::Level::eInfo, s }
    {}

    Message(const std::string& s)
        : Message{ Priority::Level::eInfo, s }
    {}

    Message(const std::string&& s)
        : Message{ Priority::Level::eInfo, s }
    {}

    /**
     * \brief    Construct Message with default priority
     * \notes     A Logger uses operates on message
     *
     * \param   rSrc    Message source such as subsystem, thread etc
     * \param   pText   Actual message
     * \param   level   Message priority
     */
    Message(const std::string& rSrc,
            const std::string& rText,
            Priority           prty = Priority::Level::eInfo)
        : Message{ prty, rText }
    {
        m_text = rSrc + m_text;
    }

  public:
    void               setPriority();
    const Priority&    getPriority() { return m_prio; }
    const std::string& c_str() { return m_text; }

  private:
    Priority    m_prio;
    std::string m_text;
    Time::Stamp m_time;
    // Uint32 m_tid; // Thread ID
};

class ILogger
{
  public:
    virtual bool info(const Message& msg)   = 0;
    virtual bool debug(const Message& msg)  = 0;
    virtual bool error(const Message& msg)  = 0;
    virtual void panic(const Message& msg)  = 0;
    virtual bool trace(const Message& msg)  = 0;
    virtual bool notice(const Message& msg) = 0;

  protected:
    ILogger() {}
    virtual ~ILogger();
};

enum class LoggerType
{
    eConsoleLogger, /* Logs to console, presumably ANSI compliant */
    eDummyLogger,   /* Discards all messages, regardless of priority */
    eFileLogger,    /* Logs to a file, provided via builder */
};

/**
 * class Logger:
 *
 *
 */
class Logger : public ILogger
{
  public:
    Logger(const std::string& name)
        : m_name{ name }
        , m_allowed_priority{ Priority::eWarning }
    {}

    Logger(const std::string&& name)
        : m_name{ name }
        , m_allowed_priority{ Priority::eWarning }
    {}

    Logger(const char* name)
        : Logger(std::string(name))
    {}

    ~Logger() {}

    void setPriority(Priority ll) { m_allowed_priority = ll; }
    void setThreshold(Uint32 t);

    ALCP_API_EXPORT static ILogger* getDefaultLogger();
    static ILogger* getLogger(const std::string& name);
    Priority        getPriority() { return m_allowed_priority; }

  public:
    class Stream
    {
      public:
        Stream() {}
        ~Stream() {}

        template<typename T>
        Stream& operator<<(const T& val)
        {
            m_ostream << val;
            return *this;
        }

      private:
        std::shared_ptr<std::ostringstream> m_ostream;
    };

  public:
    // ostream based implementations
    // Logger.warn() << "This is a warning"
    // Stream& warn(void) { return m_stream; }

  protected:
    ILogger*    m_p_ilogger;
    std::string m_name;
    Priority    m_allowed_priority;
    Stream      m_stream;
};

class LoggerFactory
{
  public:
    static Logger* createLogger(const std::string& name,
                                LoggerType         ltype,
                                Priority::Level    lvl);
};

class DummyLogger final : public Logger
{
  public:
    DummyLogger()
        : Logger("dummy")
    {}
    ~DummyLogger() {}

  public:
    virtual bool debug(const Message& msg) override { return true; }
    virtual bool error(const Message& msg) override { return true; }
    virtual void panic(const Message& msg) override {}
    virtual bool info(const Message& msg) override { return true; }
    virtual bool notice(const Message& msg) override { return true; }
    virtual bool trace(const Message& msg) override { return true; }
};

class ConsoleLogger final : public Logger
{
  public:
    ConsoleLogger();
    ConsoleLogger(const std::string& name);
    ConsoleLogger(const std::string& name, Priority::Level lvl);
    ~ConsoleLogger();

  public:
    virtual bool debug(const Message& msg) override;
    virtual bool error(const Message& msg) override;
    virtual void panic(const Message& msg) override;
    virtual bool info(const Message& msg) override;
    virtual bool notice(const Message& msg) override;
    virtual bool trace(const Message& msg) override;

  private:
    class Impl;
    const Impl*           pImpl() const { return m_pimpl.get(); }
    Impl*                 pImpl() { return m_pimpl.get(); }
    std::unique_ptr<Impl> m_pimpl;
};

class FileLogger : public Logger
{};

} // namespace alcp::utils

#include "alcp/macros.h"

EXTERN_C_BEGIN

#define MAKE_MSG(prio, str) alcp::utils::Message(prio, str)
#define LOG(str)            TRACE(str)

static inline bool
TRACE(const char* str)
{
    using namespace alcp::utils;
    auto lgr = Logger::getDefaultLogger();
    return lgr->trace(MAKE_MSG(Priority::Level::eInfo, std::string(str)));
}

#define WARN(str)   Logger::getDefaultLogger()->warn(str)
#define INFO(str)   Logger::getDefaultLogger()->info(str)
#define PANIC(str)  Logger::getDefaultLogger()->panic(str)
#define NOTICE(str) Logger::getDefaultLogger()->notice(str)
#define DEBUG(str)  Logger::getDefaultLogger()->debug(str)

EXTERN_C_END
