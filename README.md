# cpp-httplib-mbedtls
This library makes a bridge between [cpp-httplib](https://github.com/yhirose/cpp-httplib) and [mbedtls](https://github.com/Mbed-TLS/mbedtls) by emulating OpenSSL API.

In order to use it, define CPPHTTPLIB_OPENSSL_SUPPORT and add the [openssl](openssl) folder to includes. Tested with cpp-httplib v0.15.3 and mbtdtls 3.5.2, should work with later versions.

*httplib::Client* seem to work fine with https, however *httplib::SSLServer* fails in the *SSL_accept function. It can be observed in the sample app by opening https://127.0.0.1:8081/hi in a browser, however it works when using wget, see the sample app for details. Maybe I'll fix when I have time time or you can fix it now :wink:.

Looking forward to any PR with fixes & improvements.

### TODO

- Fix httplib::SSLServer 

- Test and tune for more platforms (not only Windows)

### Disclaimer

- It's only proof of concept at the moment, by no means it can be used in a production environment.
