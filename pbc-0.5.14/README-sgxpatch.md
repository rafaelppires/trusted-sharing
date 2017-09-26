
Assuming `../gmp-6.1.2/` contains the extracted content of [https://gmplib.org/download/gmp/gmp-6.1.2.tar.lz](https://gmplib.org/download/gmp/gmp-6.1.2.tar.lz).

## NO SGX

To configure:
```
rm -rf build-ntv && mkdir build-ntv && cd build-ntv && LDFLAGS="-L$(realpath ../../gmp-6.1.2/build-ntv/.libs/)" CPPFLAGS="-I$(realpath ../include) -I$(realpath ../../gmp-6.1.2/build-ntv)" ../configure && make
```

## SGX

To configure:
```
rm -rf build-sgx && mkdir build-sgx && cd build-sgx && LDFLAGS="-L$(realpath ../../gmp-6.1.2/build-sgx/.libs/) -static" CPPFLAGS="-I$(realpath ../include) -I$(realpath ../../gmp-6.1.2/build-sgx)" ../configure --enable-sgx && make
```

