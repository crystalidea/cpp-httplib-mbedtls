// this test app can be compiled 
// with openssl include directory on the include path
// OR
// with cpp-httplib-mbedtls root repository directory on the include path

#include <iostream>
#include "httplib.h"

#ifdef OPENSSL_SSL_H // when compiling against openssl 
    #pragma comment(lib, "libcrypto.lib")
    #pragma comment(lib, "libssl.lib")
#elif 1
    // mbedtls is compiled statically in this example
#endif

void test_client();
void test_server();

int main()
{
    // you can define MBEDTLS_DEBUG_OUTPUT_LEVEL=3 or 4 for verbose output

    test_client();

    test_server();

    system("pause");
}

void request_test(const char* url, const char* request, bool bPost = false, bool bVerify = true)
{
    std::cout << "--> Testing " << url << std::endl;

    try
    {
        // HTTPS
        httplib::Client cli(url);

        cli.enable_server_certificate_verification(bVerify);

        httplib::Result res = (bPost == false) ? cli.Get(request) : cli.Post(request);

        if (res)
        {
            std::cout << "Status " << res->status << std::endl;

            std::cout << "Body size is " << res->body.size() << std::endl;

            if (res->body.size())
            {
                //std::cout << res->body;
            }
        }
        else
        {
            std::cout << httplib::to_string(res.error()) << std::endl;

            if (res.error() == httplib::Error::SSLServerVerification)
            {
                std::cout << "openssl_verify_result is " << cli.get_openssl_verify_result() << std::endl;
            }
        }
    }
    catch (std::exception& exc)
    {
        std::cerr << exc.what() << std::endl;
    }
}

void test_client()
{
    request_test("https://expired.badssl.com", "/");
    request_test("https://self-signed.badssl.com", "/");
    request_test("https://self-signed.badssl.com", "/", false, false);

    request_test("https://download.qt.io", "/official_releases/qt/");

    request_test("https://httpbin.org", "/post", true);
}

// not yet working correctly when using a browser - see SSL_accept function (MBEDTLS_ERR_RSA_VERIFY_FAILED error)
// however when not checking a certificate with wget works fine
// wget -qO- --no-check-certificate https://127.0.0.1:8081/hi 

void test_server() 
{
    std::string private_cert = "sample_server_cert.pem";
    std::string private_key = "sample_server_cert_pk.pem";

    httplib::SSLServer svr(private_cert.c_str(), private_key.c_str());

    if (svr.is_valid())
    {
        std::cout << "--> Starting server..." << std::endl;

        svr.Get("/hi", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("Hello World!", "text/plain");
            });

        if (!svr.listen("127.0.0.1", 8081))
        {
            std::cerr << "Failed to bind to port" << std::endl;
        }
    }
    else
    {
        std::cerr << "Error loading certificate and/or private key" << std::endl;
    }
}