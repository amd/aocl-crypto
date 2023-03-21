# ALCP Micro Benchmarks 

## Building

Skip to [Executing Benches](#Executing_Benches) if already installed

### Building ALCP with Testing framework

1. $<code>git clone [alcp-crypto git url here]</code>
2. $<code>cd alcp-crypto</code>
3. $<code>cmake -B build -DALCP_ENABLE_EXAMPLES=ON -DALCP_ENABLE_BENCH=ON  -DCMAKE_BUILD_TYPE=Release</code>
4. $<code>cmake --build build</code>

<font color="red">Note - To include IPP, please define <code>-DENABLE_TESTS_IPP_API=ON -DIPP_INSTALL_DIR=/path/to/ipp_prefix</code> in step 3.</font><br>
<font color="red"> Note - To include OpenSSL, please define <code>-DOPENSSL_INSTALL_DIR=/path/to/openssl_prefix</code> in step 3.</font>

## AES

<a name = "Executing_Benches"></a>

### Executing Benches

After building ALCP, there should be binary files with name bench_cipher in bench/cipher and bench_digest in bench/digest

To run tests with verbose mode (prints also success)

1. $<code>cd aocl-crypto/build</code>
2. $<code>./bench/cipher/bench_cipher</code>
3. $<code>./bench/digest/bench_digest</code>

#### Selecting benchmarks

Example for selecting only "CBC" benchmarks

​	 $<code>./bench/cipher/bench_cipher --benchmark_filter="CBC"</code>

Example for selecting only "SHA256" benchmarks

​	$<code>./bench/digest/bench_digest --benchmark_filter="SHA2_256"</code>

Always you can use <code>--help</code> to know all the command line arguments which can be given to the executable.

##### Supported Benchmarks

###### Cipher

1. AES-CBC (128,192,256)
2. AES-CTR (128,192,256)
3. AES-CFB (128,192,256)
4. AES-OFB (128,192,256)
5. AES-GCM (128,192,256)

###### Digest

1. SHA2-224
2. SHA2-256
3. SHA2-384
4. SHA2-512

#### Using IPP

For using IPP just specify <code>-i</code> command line argument.

#### Using OpenSSL

For using OpenSSL just specify <code>-o</code> command line argument.

