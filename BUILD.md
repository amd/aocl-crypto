# AOCL Crypto Library Build

### Build Release Configuration

```shell
$ mkdir build
$ cd build
$ cmake ../
```

#### Extra steps for making STATIC library work
 To generate a single .a file from all the .a files
```shell
ar crsT libnew.a libalcp.a libarch_zen3.a libarch_avx2.a
mv libnew.a libalcp.a
```

#### Enabling Features of AOCL-Crypto

1. [Enable Examples - To compile example/demo code.](#example)
2. [Enable AOCL-UTILS - To dispatch correct kernel with CPU identification.](#aocl-utils)
3. [Enable DEBUG Build - To compile code in Debug Mode.](#debug)
4. [Enable Address Sanitizer Support ](#asan)
5. [Enable Bench - To compile bench code.](#bench)
6. [Enable Tests - To compile test code](#tests)

<div id = "example"> </div>

#### Enable Examples

To enable examples, append `-DALCP_ENABLE_EXAMPLES=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_ENABLE_EXAMPLES=ON ../
```

<div id = "aocl-utils"> </div>

#### Enable AOCL-UTILS

To enable aocl utils checks, append `-DAOCL_UTILS_INSTALL_DIR=path/to/aocl/utils/source` and `-DENABLE_AOCL_UTILS=ON` to the cmake configuration command.
```bash
$ cmake -DENABLE_AOCL_UTILS=ON -DAOCL_UTILS_INSTALL_DIR=path/to/aocl/utils/source ../
```

<div id = "debug"> </div>

#### Build Debug Configuration

To build in debug mode, append `-DCMAKE_BUILD_TYPE=DEBUG` to the cmake configuration command.
```sh
$ cmake -DCMAKE_BUILD_TYPE=DEBUG ../
```
<div id = "asan"> </div>

#### For Compiling with Address Sanitizer Support

To enable sanitizers (asan, tsan etc), append `-DALCP_SANITIZE=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_SANITIZE=ON ../
```
<div id = "bench"> </div>

#### Build Benches

To build benchmarking support with alcp library, append `-DALCP_ENABLE_BENCH=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_ENABLE_BENCH=ON ../
```
Benchmarks will be built into `bench/{algorithm_type}/`

Please look into **[ README.md ](md_bench_README.html)** from bench.

#### Execute Benchmarks
```
$ ./bench/{algorithm_type}/bench_{algorithm_type}
```
#### Arguments can be provided in above bench as
```
$ ./bench/digest/bench_digest --benchmark_filter=SHA2_<SHA SCHEME>_<Block Size>
$ ./bench/digest/bench_digest --benchmark_filter=SHA2_512_16 (runs SHA256 schemes for 16 block size)
$ ./bench/digest/bench_digest --benchmark_filter=SHA2 (runs for all SHA2 schemes and block sizes)
```
<div id = "tests"> </div>

#### Build Tests (using KAT vectors)
To enable tests, append `-DALCP_ENABLE_TESTS=ON` to the cmake configuration command.
```sh
$ cmake -DALCP_ENABLE_TESTS=ON ../
```
Test executables can be found inside `tests/{algorithm_type}` directory 

For more details see **[README.md](md_tests_README.html)** from tests.

#### Execute Tests
 ```  shell
 $ ./tests/{algorithm_type}/test_{algorithm_type}
 ```
