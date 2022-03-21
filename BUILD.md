
# AOCL Crypto Library

## Building

$ mkdir build
$ cd build
$ cmake ../


## To enable examples append this
```sh
$ cmake -DALCP_ENABLE_EXAMPLES=1 ../
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
$ ./bench/digest/bench_digest;

## Arguments can be provided as:
$ --benchmark_filter=SHA2_<SHA SCHEME>_<Block Size>
$ --benchmark_filter=SHA2_512_16 (runs SHA256 schemes for 16 block size)
$ --benchmark_filter=SHA2 (runs for all SHA2 schemes and block sizes)
```

## To build tests (using KAT vectors)
$ Append the argument '-DALCP_ENABLE_TESTS=1'
 This will create test executable:
 ./tests/digest/
 ## To run:
   ./tests/digest/test_digest;


## To build examples
Append any other necessary configuration needed for build such as 
`ALCP_ENABLE_EXAMPLES=1` for building examples

