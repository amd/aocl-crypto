#pragma once

static bool verbose = false;
static bool useipp  = false;
void
parseArgs(int* argc, char** argv)
{
    std::string currentArg;
    const int   _argc = *argc;
    if (*argc > 1) {
        for (int i = 1; i < _argc; i++) {
            currentArg = std::string(argv[i]);
            if ((currentArg == std::string("--help"))
                || (currentArg == std::string("-h"))) {
                std::cout << std::endl
                          << "Additional help for microbenches" << std::endl;
                std::cout << "Append these after gtest arguments only"
                          << std::endl;
                std::cout << "--verbose or -v per line status." << std::endl;
                std::cout << "--use-ipp or -i force IPP use in testing."
                          << std::endl;
            } else if ((currentArg == std::string("--verbose"))
                       || (currentArg == std::string("-v"))) {
                verbose = true;
                *argc -= 1;
            } else if ((currentArg == std::string("--use-ipp"))
                       || (currentArg == std::string("-i"))) {
                useipp = true;
                *argc -= 1;
            }
        }
    }
}