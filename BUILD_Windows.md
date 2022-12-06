#Following software should be installed prior to build AOCL-CRYPTO 
=> MS Visual Studio (2019 or greater)
=> Git
=> Python 3.7 or greater
=> Cmake

# AOCL Crypto Library in Windows

1. After git checkout the latest Crypto_Lib for windows.
2. Open the powershell.exe as administrator.
3. cd to current working directory/cmake_source_directory

## Building

`you can enable EXAMPLES, TESTS & BENCH & generate the Project Files. Here you are specify cmake generator, by default 'Visual Studio': platform: 'x64' (by default): and for toolset current configuration use 'ClangCl'

```Powershell

> cmake -A x64 -B build -DALCP_ENABLE_EXAMPLES=ON -DALCP_ENABLE_TESTS=ON -DALCP_ENABLE_BENCH=ON -DCMAKE_BUILD_TYPE=RELEASE -T ClangCl
 
 ---Build binaries will be written to cmake_source_directory/build
 
 To build the cmake projects->
> cmake --build build/ --config=release
 

```
##Build after enabling compat libs, CPUID
```Enabling IPP , open ssl, IPP-crypto

> cmake -A x64 -B build -DCMAKE_BUILD_TYPE=RELEASE -DALCP_ENABLE_EXAMPLES=ON -DALCP_ENABLE_TESTS=ON -DALCP_ENABLE_BENCH=ON -DENABLE_AOCL_CPUID=ON -DAOCL_CPUID_INSTALL_DIR=path/to/libcpuid 
-DENABLE_TESTS_OPENSSL_API=ON -DOPENSSL_INSTALL_DIR=path/to/openssl -DENABLE_TESTS_IPP_API=ON -DIPP_INSTALL_DIR=path/to/ipp_crypto -T ClangCl
> cmake --build build/ --config=release
```

## Extra steps to found dll's by setting an environment variable
`Try to Run the tests, if alcp & gtests dll's are not found, run the batch file, this batch file set the environment path for tests & bench.

> Set_Env_Path.bat
And restart the powershell & set the path to current cmake source directory.

##For run the Cipher & Digest Tests
> cd build
> ctest -C release

##For run the Cipher & Digest bench
``` For running the benchmarking for cipher & digests, you can run the following batch files
.\bench\digest\release\bench_digest
.\bench\cipher\release\bench_cipher
```

#### Important Notes: ASAN is not configured for Windows yet. #### 


## Enabling features of AOCL-Crypto

1. [Enable Examples - To compile example/demo code.](##Enable Examples append)
2. [Enable CPUID - To dispatch correct kernel with CPU identification.](##To enable CPUID append this)

### Enable Examples append

```
$ cmake -DALCP_ENABLE_EXAMPLES=ON -B build
```

### Enable CPUID append

```
$ cmake -DAOCL_CPUID_INSTALL_DIR=path/to/aocl/cpuid/source ../
```

## For Debug build

```
$ cmake -DCMAKE_BUILD_TYPE=DEBUG -B build
```

## For compiling with Address Sanitizer support
```ASAN is not configured for windows yet````

## To build tests (using KAT vectors)
```
$ Append the argument '-DALCP_ENABLE_TESTS=ON'
 This will create test executable:
 .\tests\digest\release
```

 ## To run:
 ```  PS
 $ .\tests\digest\release\test_digest
 $ .\tests\cipher\release\test_cipher
 ```

## Building (Micro)Benchmarks

## To build  bench

```
$ Append the argument -DALCP_ENABLE_BENCH=ON
  This will create bench executable:
  .\bench\digest\ -B build
```
 ## To Run:
$ .\bench\digest\release\bench_digest

## Arguments can be provided as:
``` PS
$ .\bench\digest\release\bench_digest --benchmark_filter=SHA2_<SHA SCHEME>_<Block Size>
$ .\bench\digest\release\bench_digest --benchmark_filter=SHA2_512 (runs SHA256 schemes for 16 block size)
$ .\bench\digest\release\bench_digest --benchmark_filter=SHA2 (runs for all SHA2 schemes and block sizes)
```