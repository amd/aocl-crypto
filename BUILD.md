
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
$ cmake -DTESTS=1 ../
  This will create bench executable:
  ./bench/digest/

## To Run:
$ ./bench/digest/bench_digest;

## Arguments can be provided as:
$ --benchmark_filter=HashPerformanceTest_SHA2_256
$ --benchmark_filter=HashConformanceTest_SHA2_512
$ --benchmark_filter=HashPerformanceTest (runs for all schemes)
```

Append any other necessary configuration needed for build such as 
`ALCP_ENABLE_EXAMPLES=1` for building examples

