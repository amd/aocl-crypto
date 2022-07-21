#include <iostream>

#pragma once
// #define DEBUG

inline void
printErr(std::string error)
{
    std::cout << "IPP_wrpr_ERR:" << error << std::endl;
}
#ifdef DEBUG

inline void
printMsg(std::string error)
{
    std::cout << "IPP_wrpr_MSG:" << error << std::endl;
}

#else

inline void
printMsg(std::string error)
{}
#endif