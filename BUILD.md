
# AOCL Crypto Library

## Building

```shell
$ mkdir build
$ cd build
$ cmake ../
```

## Enabling features of AOCL-Crypto

1. [Enable Examples - To compile example/demo code.](##Enable Examples append)
2. [Enable AOCL-SRNG - To enable AOCL-SRNG (RNG source ARCH).](##Enable AOCL-SRNG append this)
3. [Enable CPUID - To dispatch correct kernel with CPU identification.](##To enable CPUID append this)

### Enable Examples append

```sh
$ cmake -DALCP_ENABLE_EXAMPLES=1 ../
```

### Enable AOCL-SRNG append

```sh
$ cmake -DAOCL_INSTALL_DIR=path/to/aocl/root
```

### Enable CPUID append

```bash
$ cmake -DAOCL_CPUID_INSTALL_DIR=path/to/aocl/cpuid/source ../
```

## For Debug build

```sh
$ cmake -DCMAKE_BUILD_TYPE=DEBUG ../
```

## To build test bench

```sh
$ Append the argument -DALCP_ENABLE_BENCH=1
  This will create bench executable:
  ./bench/digest/

 ## To Run:
$ ./bench/digest/bench_digest

## Arguments can be provided as:
$ ./bench/digest/bench_digest --benchmark_filter=SHA2_<SHA SCHEME>_<Block Size>
$ ./bench/digest/bench_digest --benchmark_filter=SHA2_512_16 (runs SHA256 schemes for 16 block size)
$ ./bench/digest/bench_digest --benchmark_filter=SHA2 (runs for all SHA2 schemes and block sizes)
```

## To build tests (using KAT vectors)
$ Append the argument '-DALCP_ENABLE_TESTS=1'
 This will create test executable:
 ./tests/digest/

For more details see [README.md](tests/README.md) from tests.

## Building (Micro)Benchmarks

Please look into [README.md](bench/README.md) from bench.

 ## To run:
 ```  shell
 $ ./tests/digest/test_digest
 $ ./tests/cipher/test_cipher
 ```


## To build examples
Append any other necessary configuration needed for build such as 
`ALCP_ENABLE_EXAMPLES=1` for building examples

