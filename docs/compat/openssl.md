---
title: AOCL Crypto OpenSSL Provider Documentation
subtitle: OpenSSL Plugin Documentation
subject: "markdown"
keywords: [books,programming]
language: en-US
#cover-image: img/example-book-cover.png
lof: true
lof-own-page: true
toc-own-page: true
titlepage: true
#;titlepage-background: backgrounds/background10.pdf
#titlepage-text-color: "333333"
#titlepage-rule-color: "00737C"
papersize: a4
#prepend-titlepage: img/example-book-cover.pdf
colorlinks: true
---

# Key Terminologies

* SSL- Secure Socket Layer

* SSH - Secure Shell Host

* Cipher Suite - A set of algorithms which can be used to exchange keys, verify integrity, and provide authenticity.

* Kernel - Piece of code which performs/executes all the core tasks and takes most amount of time in the library.
* Plugin - A foreign piece of code which can be used to extend a program/library.
* Provider - Another name for plugin used by OpenSSL.
* Benchmarking - Performance analysis of a program.





# Introduction

## About OpenSSL

OpenSSL is an opensource SSL library which supports various encryption decryption standards as well as cipher suites. OpenSSL is used in well known programs such as Nginx, SSH etc. Most of the OpenSSL kernels have a hardware optimized version inside it. 
Sometimes users of OpenSSL might require more optimized versions of the kernels, for this particular purpose OpenSSL has a plugin infrastructure which will allow anyone to write plugins called as providers. This is the interface which is used by ALCP to communicate with the OpenSSL infrastructure. 

### Using OpenSSL-Compat Lib

​	ALCP support for OpenSSL is provided by a provider. Provider lib name is ```libopenssl-compat.so```.  Please configure openssl to use provider by default or setup provider loading inside application itself.

​	To bench with the provider, use the following example assuming you are executing command from the root of the package (extracted tarball) directory.

​	```openssl speed -provider-path $PWD/lib  -provider libopenssl-compat -evp aes-128-gcm```
