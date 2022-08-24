# Configuring OpenSSL

For more information please take a look at [this](https://www.openssl.org/docs/manmaster/man5/config.html).

```sh
openssl_conf = openssl_init

[openssl_init]
providers = alcp_sect

[alcp_sect]
dynamic_path = /path/to/libopenssl-compat.so
activate = 1
```