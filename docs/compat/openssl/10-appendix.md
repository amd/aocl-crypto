# Appendix

## Compiling OpenSSL from the source.

```bash
git clone https://github.com/openssl/openssl.git -b openssl-3.0.5
cd openssl
./Configure --prefix=/usr/local
make -j $(nproc --all)
sudo make install
```

