# ALCP Micro Benchmarks

## Building

Skip to [Executing Benches](##Executing Benches) if already installed

### Building ALCP with Testing framework

1. <code>git clone [alcp-crypto git url here]</code>
2. <code>cd alcp-crypto</code>
3. <code>cmake -B build -DALCP_ENABLE_EXAMPLES=ON -DALCP_ENABLE_BENCH=ON  -DCMAKE_BUILD_TYPE=Release</code>
4. <code>cmake --build build</code>

<font color="red">Note - To include IPP, please define <code>-DENABLE_TESTS_IPP_API=ON -DIPP_INSTALL_DIR=/path/to/ipp_prefix</code> in step 3.</font><br>
<font color="red"> Note - To include OpenSSL, please define <code>-DOPENSSL_INSTALL_DIR=/path/to/openssl_prefix</code> in step 3.</font>

## AES

### Executing Benches

After building ALCP, there should be binary files with name bench_cipher in bench/cipher and bench_digest in bench/digest

To run tests with verbose mode (prints also success)

1. <code>cd aocl-crypto/build</code>
2. <code>./bench/cipher/bench_cipher</code>
3. <code>./tests/digest/bench_digest</code>

#### Selecting benchmarks

Example for selecting only "CBC" benchmarks

​	 <code>./bench/cipher/bench_cipher --benchmark_filter="CBC"</code>

Example for selecting only "SHA256" benchmarks

​	<code>./bench/digest/bench_digest --benchmark_filter="SHA2_256"</code>

Always you can use <code>--help</code> to know all the command line arguments which can be given to the executable.

#### Using IPP

For using IPP just specify <code>-i</code> command line argument.

#### Using OpenSSL

For using OpenSSL just specify <code>-o</code> command line argument.

### Testing Datasets

Datasets are located in directory <code>alcp-crypto/tests/cipher/dataset/</code>. File name should be dataset_\<aes\_mode\>.csv. Order of elements are mentioned in line number 1. Line number 1 is always ignored, please forbid form deleting that line.

