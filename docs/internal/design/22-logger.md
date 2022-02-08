# Logging System

Logger supports
 - Multiple loggers, accessible by name
        - a static class method `getLogger(const std::string&)`
 - C++ style logging with overloaded `<<` operator.
 - Custom formatted output useful for AOCL project, such as dumping memory
   location with width size as _byte_, _word_, _dword_, _qword_ etc.
 - Ability to control Log Level
 - Serialization of multiple calls to logger
 - Thread Safe Design

## Performance Implications
Logger to be available only in Debug build, hence having logger that can be
eliminated during build time is essential.

## Initializing the Logger
Default Logger is initialized at the very beginning when the library is loaded.
It would be through a static function to Logger class. Since the debug logger
module is slightly sophisticated than a pure macro based 'C' implementations.

```c++
#ifdef DEBUG
Logger::initialize();
#endif
``` 

This will create default logger like 'DummyLogger' where every message is
ignored, and any other requested Logger with default log level.

## Using the default Logger 
The default logger in Release mode is DummyLogger, a logger gets created, but
wont be usable. The default logger in Debug mode is ConsoleLogger, which throws
all the messages to the console (if it has one, via ostream).

## Creating new logger
During initialization a default logger is created by calling `Logger::initialize()`


## Design

Let us first differentiate between logger, backend, message, priority etc. A
Logger class is the overall logging system, connects to a backend (could be
anything, a console based logging, simple file-based, xml or json etc).

Logger gets a message (as in `Message` class), each message has a message
priority or level (`LogLevel` class). 

### Message class
Messages can be compared to see if the priority is less/greater or equal to the
other. Message class carries information such as 
 - module, there can be many modules trying to send message to a logger.
 - text, actual message that is to be sent
 - priority, level Message's priority or `LogLevel`
 - timestamp, optional
 - thread id, optional
 - thread name, optional
 - file name, at which the message has been kept (relative to project).
 - line num, Line number in file

### Log Level class
### Logger Type class

## Use Case

Named logger support:
A Named logger is just not the default logger, can be a module specific logger.

```c++
#define WARN  Logger::getDefaultLogger()->warn()

util::Logger &logger = Logger::getLogger("cipher");

WARN << "This path is not supposed to be reached\n";

```

## Use Case 2

A Default logger with macro.

```c++
#define LOG     Logger::getDefaultLogger()->log()
#define DEBUG   Logger::getDefaultLogger()->log()

LOG << "This is expected print" ;

DEBUG << "value of abcd %d\n" << bcd << "\n";

```


```
template<>
Logger::Stream& LOG(std::string& str)
{
        Logger::getDefaultLogger()->log() << str;
}

```

