# Instructions to Build/Use IPP-CP plugin
By preloading the IPP Compat library you will be able to run any applications using AOCL-Cryptography without changing the APIs to crypto from IPPCP. 

> <span style="color:red">__Note:__</span> IPP Compat Library is experimental and has currently only been verified on KAT and Cross tests.

## Building

```
git clone <repo url> aocl-crypto
mkdir aocl-crypto/build
cd aocl-crypto/build
cmake -DAOCL_COMPAT_LIBS=ipp ../
cmake --build .
```

After running all the above commands you should see a `libipp-compat.so` in build directory.

## Preloading

```
export LD_LIBRARY_PATH=/path/where/libalcp/is:$LD_LIBRARY_PATH
LD_PRELOAD=/path/to/libipp-compat.so ./program_to_run
```

* Export Path should be a directory.
* Preload Path should be the .so file itself.
* Any command can follow LD_PRELOAD.