

class DisableCopy
{
protected:
    DisableCopy(void) = default;
    DisableCopy(const DisableCopy&) = delete;
    DisableCopy& operator=(const DisableCopy&) = delete;
};

class DisableMove
{
protected:
    DisableMove(void) = default;
    DisableMove(DisableMove&&) = delete;
    DisableMove& operator=(DisableMove&&) = delete;
};

class DisableCopyMove : public DisableCopy,
    public DisableMove
{
protected:
    DisableCopyMove(void) = default;
};

