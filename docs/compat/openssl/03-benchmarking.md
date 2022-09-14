# Benchmarking

## OpenSSL Speed

OpenSSL has an inbuilt benchmarking mechanism called `speed`. When you invoke openssl speed using command line (`openssl speed`), openssl benchmarks all the supported algorithms. After the benchmark you will be given a summary, in the summary it will say how much bytes was encrypted/decrypted in a second.

### OpenSSL Speed Arguments

Important Arguments

1) -evp - Use EVP API.
2) -decrypt - Do a decrypt benchmark.
3) -seconds - Edit the benchmark time default 3 seconds.
4) -provider - File name of provider without extension.
5) -provider-path - Path where to look for provider binary file.
6) algorithm - Which algorithm to benchmark.

example -

1. EVP API is used with cipher AES mode CBC with 128bit keysize in encrypt setting.

```bash
openssl speed -evp aes-128-cbc
```

## Benchmarking with OpenSSL Speed.

In this section we will discuss how to use provider without configuration files. OpenSSL binary can be given arguments to load provider from a custom directory. If openssl.cnf is already configured to use the custom directory and the provider, then specifying provider in argument is not necessary.

To load the OpenSSL provider for AOCL Crypto, we have to provide the path of the provider and the name of the .so file.

 ```bash
 openssl speed -provider-path /path/to/alcp/lib -provider libopenssl-compat
 ```

Now we can combine this command with EVP API and provide an algorithm to run the encrypt benchmark

```bash
openssl speed -provider-path /path/to/alcp/lib -provider libopenssl-compat \
-evp aes-128-cbc
```

### All supported possible commands for OpenSSL speed
#### AES-CBC
```bash
openssl speed -provider-path /path/to/alcp/lib -provider libopenssl-compat \
-evp aes-128-cbc

openssl speed -provider-path /path/to/alcp/lib -provider libopenssl-compat \
-evp aes-192-cbc

openssl speed -provider-path /path/to/alcp/lib -provider libopenssl-compat \
-evp aes-256-cbc
```
#### AES-CTR
```bash
openssl speed -provider-path /path/to/alcp/lib -provider libopenssl-compat \
-evp aes-128-ctr

openssl speed -provider-path /path/to/alcp/lib -provider libopenssl-compat \
-evp aes-192-ctr

openssl speed -provider-path /path/to/alcp/lib -provider libopenssl-compat \
-evp aes-256-ctr
```
#### AES-CFB
```bash
openssl speed -provider-path /path/to/alcp/lib -provider libopenssl-compat \
-evp aes-128-cfb

openssl speed -provider-path /path/to/alcp/lib -provider libopenssl-compat \
-evp aes-192-cfb

openssl speed -provider-path /path/to/alcp/lib -provider libopenssl-compat \
-evp aes-256-cfb
```
#### AES-OFB
```bash
openssl speed -provider-path /path/to/alcp/lib -provider libopenssl-compat \
-evp aes-128-ofb

openssl speed -provider-path /path/to/alcp/lib -provider libopenssl-compat \
-evp aes-192-ofb

openssl speed -provider-path /path/to/alcp/lib -provider libopenssl-compat \
-evp aes-256-ofb
```
#### AES-GCM
```bash
openssl speed -provider-path /path/to/alcp/lib -provider libopenssl-compat \
-evp aes-128-gcm

openssl speed -provider-path /path/to/alcp/lib -provider libopenssl-compat \
-evp aes-192-gcm

openssl speed -provider-path /path/to/alcp/lib -provider libopenssl-compat \
-evp aes-256-gcm
```
<!-- XTS Mode should come here once implemented -->

