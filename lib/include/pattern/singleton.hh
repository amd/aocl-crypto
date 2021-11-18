
#include "misc/disable_copy_move.hh"

template<class T>
class Singleton : public DisableCopyMove
{
public:
    static T& instance(void)
    {
        static T _impl;
        return _impl;
    }

protected:
    Singleton(void) = default;
};


