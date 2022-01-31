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

#include <memory>
#include <string>

namespace alcp::util::log {

class Message;

class LogWriter
{
  public:
    LogWriter();

    virtual void open() {}
    virtual void close() {}
    virtual void log(const Message& msg) = 0;

    void setProperty(const std::string& name, const std::string& value) {}

    std::string& getProperty(const std::string& name) const {}

  protected:
    virtual ~LogWriter();

  private:
    // Disable copy constructor and assignment operator
    LogWriter(const LogWriter&);
    LogWriter& operator=(const LogWriter&);
};

class LogLevel
{
  public:
    enum Category
    {
        /* FATAL, Highest, Application will terminate (mostly) */
        eFatal = (1 << 0),

        /* CRITICAL/PANIC, Application might not work as expected */
        ePanic = (1 << 1),

        /* Operation will not complete, but application will continue */
        eError = (1 << 2),

        /* Operation will complete with an error code, appl will continue */
        eWarning = (1 << 3),

        /* A NOTICE, just like INFO but higher priority */
        eNotice = (1 << 4),

        /* An INFO usually denoting successful completion  */
        eInfo = (1 << 5),

        /* A DEBUG message, for debugging purpose only */
        eDebug = (1 << 6),

        /* A TRACE, lowest priority */
        eTrace = (1 << 7),
    };

  private:
    LogLevel() = delete;

  public:
    LogLevel(const Category c)
        : m_category{ c }
    {}

    ~LogLevel();

    inline const std::string& name(Category& c)
    {
        switch (c) {
            // clang-format off
            case eFatal: return "Fatal"; break;
            case ePanic: return "Panic"; break;
            case eError: return "Error"; break;
            case eWarning: return "Warning"; break;
            case eInfo: return "Info"; break;
            case eNotice: return "Notice"; break;
            case eDebug: return "Debug"; break;
            default: break;
                // clang-format on
        }
        return "";
    }

    inline bool operator==(const Category& r)
    {
        return (int)m_category == (int)r;
    }

    inline bool operator<(const Category& r)
    {
        return (int)m_category < (int)r;
    }

    inline bool operator<=(const Category& r)
    {
        return (int)m_category == (int)r;
    }

    inline bool operator>(const Category& r)
    {
        return !((int)m_category <= (int)r);
    }

    inline bool operator>=(const Category& r)
    {
        return !((int)m_category < (int)r);
    }

  private:
    Category m_category;
};

class Message
{
  public:
  private:
    LogLevel m_level;
};

#define LOG(msg) util::log::get_instance()->log(msg)

class LoggerInterface
{
  public:
    virtual bool debug(const std::string& msg)  = 0;
    virtual bool error(const std::string& msg)  = 0;
    virtual bool panic(const std::string& msg)  = 0;
    virtual bool info(const std::string& msg)   = 0;
    virtual bool notice(const std::string& msg) = 0;
    virtual bool log(const std::string& msg)    = 0;

  protected:
    LoggerInterface();
    virtual ~LoggerInterface();
};

enum class LoggerType
{
    eConsoleLogger,
    eDummyLogger,
    eFileLogger,
};

/**
 * class Logger:
 *
 *
 */
class Logger : LoggerInterface
{
  public:
    Logger(std::string& name)
        : m_level{ LogLevel::eWarning }
    {}

    static LogLevel   s_default_level;
    static LoggerType s_default_type;

    static void setDefaultType(LoggerType lt) { s_default_type = lt; }
    static void setDefaultLevel(LogLevel ll) { s_default_level = ll; }

    static Logger& getDefaultLogger();
    static Logger& getLogger(std::string& name);
    static Logger* createLogger(std::string name,
                                LoggerType  ltype = LoggerType::eDummyLogger,
                                LogLevel    lvl   = LogLevel::eInfo);

    LogLevel   getLevel() { return m_level; }
    LoggerType getType() { return m_logger_type; }

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

  protected:
    LogLevel   m_level;
    LoggerType m_logger_type;
    Stream     m_stream;
};

class DummyLogger final : public log::Logger
{
  public:
    static std::string s_m_name = "dummy";
    DummyLogger()
        : Logger(s_m_name)
    {}
    ~DummyLogger() {}

  public:
    virtual bool debug(const std::string& msg) override {}
    virtual bool error(const std::string& msg) override {}
    virtual bool panic(const std::string& msg) override {}
    virtual bool info(const std::string& msg) override {}
    virtual bool notice(const std::string& msg) override {}
    virtual bool log(const std::string& msg) override {}
};

class ConsoleLogger : public Logger
{
  public:
    ConsoleLogger();
    ~ConsoleLogger();

  public:
    virtual bool debug(const std::string& msg) override;
    virtual bool error(const std::string& msg) override;
    virtual bool panic(const std::string& msg) override;
    virtual bool info(const std::string& msg) override;
    virtual bool notice(const std::string& msg) override;
    virtual bool log(const std::string& msg) override;

  private:
    class Impl;
    Impl* m_impl;
};

class FileLogger : public LoggerInterface
{};

} // namespace alcp::util::log
