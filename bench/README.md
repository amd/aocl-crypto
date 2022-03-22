# ALCP Micro Benchmarks

## Building

Skip to [Executing Benches](##Executing Benches) if already installed

### Installing GBench

1. <code>git clone https://github.com/google/benchmark.git</code>
2. <code>cd benchmark</code>
3. <code>mkdir build</code>
4. <code>cd build</code>
5. <code>cmake ../ -DCMAKE_INSTALL_PREFIX="$HOME/.local" -DBENCHMARK_DOWNLOAD_DEPENDENCIES=ON -DCMAKE_BUILD_TYPE="Release"</code> 
6. <code>make -j $(nproc --all)</code>
7. <code>make install</code>

### Setting Up Environment GBench

1. <code>export C_LIBRARY_PATH=$HOME/.local/include:$C_LIBRARY_PATH</code>
2. <code>export CPLUS_LIBRARY_PATH=$HOME/.local/include:$CPLUS_LIBRARY_PATH</code>
3. <code>export LD_LIBRARY_PATH=$HOME/.local/lib:$HOME/.local/lib64</code>

### Building ALCP with Testing framework

1. <code>git clone [alcp-crypto git url here]</code>
2. <code>cd alcp-crypto</code>
3. <code>cmake -B build -DALCP_ENABLE_EXAMPLES=ON -DALCP_BENCH=ON -DGBENCH_INSTALL_DIR=$HOME/.local</code> - <font color="red">Please replace <code>$HOME/.local</code> with GBench Prefix, if you have installed some other place</font>
4. <code>cmake --build build</code>

<font color="red">Note - To include IPP, please define <code>-DENABLE_TESTS_IPP_API=ON -DIPP_INSTALL_DIR=/path/to/ipp_prefix</code> in step 3.</font>

## AES

### Executing Benches

After building ALCP, there should be binary files with name bench_cipher in bench/cipher and bench_digest in bench/digest

To run tests with verbose mode (prints also success)

1. <code>cd aocl-crypto/build</code>
2. <code>./bench/cipher/bench_cipher</code>
3. <code>./tests/digest/bench_digest</code>

#### Selecting tests

Example for selecting only "CBC" benchmarks

​	 <code>./bench/cipher/bench_cipher --benchmark_filter="CBC"</code>

Example for selecting only "SHA256" benchmarks

​	<code>./bench/digest/bench_digest --benchmark_filter="SHA2_256"</code>

Always you can use <code>--help</code> to know all the command line arguments which can be given to the executable.

#### Using IPP

For using IPP just specify <code>-i</code> command line argument.

### Testing Datasets

Datasets are located in directory <code>alcp-crypto/tests/cipher/dataset/</code>. File name should be dataset_\<aes\_mode\>.csv. Order of elements are mentioned in line number 1. Line number 1 is always ignored, please forbid form deleting that line.

