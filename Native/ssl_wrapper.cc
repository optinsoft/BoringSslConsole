#include "ssl_wrapper.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <string>

struct PmsSslConnection
{
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    std::string hostname;
};

static thread_local std::string g_last_error;

static void SetLastError(const char* message)
{
    g_last_error = message ? message : "Unknown error";
}

static void SetOpenSslError(const char* prefix)
{
    unsigned long error = ERR_get_error();

    if (error == 0)
    {
        g_last_error = prefix ? prefix : "OpenSSL error";
        return;
    }

    char error_string[256] = {};

    ERR_error_string_n(
        error,
        error_string,
        sizeof(error_string));

    g_last_error =
        std::string(prefix ? prefix : "OpenSSL error") +
        ": " +
        error_string;
}

static int TranslateSslError(
    SSL* ssl,
    int result)
{
    int error = SSL_get_error(ssl, result);

    switch (error)
    {
        case SSL_ERROR_NONE:
            return PMS_SSL_OK;

        case SSL_ERROR_ZERO_RETURN:
            return PMS_SSL_ZERO_RETURN;

        case SSL_ERROR_WANT_READ:
            return PMS_SSL_WANT_READ;

        case SSL_ERROR_WANT_WRITE:
            return PMS_SSL_WANT_WRITE;

        default:
            SetOpenSslError("SSL error");
            return PMS_SSL_ERROR;
    }
}

extern "C"
{

PMS_EXPORT void* PMS_CALL pms_ssl_create(
    const char* hostname)
{
    if (!hostname || !hostname[0])
    {
        SetLastError("Hostname is empty");
        return nullptr;
    }

    auto* connection = new PmsSslConnection();

    connection->hostname = hostname;

    connection->ctx = SSL_CTX_new(TLS_client_method());

    if (!connection->ctx)
    {
        SetOpenSslError("SSL_CTX_new failed");
        delete connection;
        return nullptr;
    }

    // POC only.
    // Certificate verification should be enabled later.
    SSL_CTX_set_verify(
        connection->ctx,
        SSL_VERIFY_NONE,
        nullptr);

    connection->ssl = SSL_new(connection->ctx);

    if (!connection->ssl)
    {
        SetOpenSslError("SSL_new failed");
        SSL_CTX_free(connection->ctx);
        delete connection;
        return nullptr;
    }

    BIO* read_bio = BIO_new(BIO_s_mem());
    BIO* write_bio = BIO_new(BIO_s_mem());

    if (!read_bio || !write_bio)
    {
        if (read_bio)
            BIO_free(read_bio);

        if (write_bio)
            BIO_free(write_bio);

        SetOpenSslError("BIO_new failed");

        SSL_free(connection->ssl);
        SSL_CTX_free(connection->ctx);
        delete connection;

        return nullptr;
    }

    // SSL now owns both BIOs.
    SSL_set_bio(
        connection->ssl,
        read_bio,
        write_bio);

    if (SSL_set_tlsext_host_name(
            connection->ssl,
            connection->hostname.c_str()) != 1)
    {
        SetOpenSslError(
            "SSL_set_tlsext_host_name failed");

        SSL_free(connection->ssl);
        SSL_CTX_free(connection->ctx);
        delete connection;

        return nullptr;
    }

    SSL_set_connect_state(connection->ssl);

    return connection;
}

PMS_EXPORT int PMS_CALL pms_ssl_connect(
    void* connection_ptr)
{
    if (!connection_ptr)
    {
        SetLastError("Connection is null");
        return PMS_SSL_ERROR;
    }

    auto* connection =
        static_cast<PmsSslConnection*>(connection_ptr);

    int result = SSL_connect(connection->ssl);

    if (result == 1)
        return PMS_SSL_OK;

    return TranslateSslError(
        connection->ssl,
        result);
}

PMS_EXPORT int PMS_CALL pms_ssl_feed_read(
    void* connection_ptr,
    const uint8_t* buffer,
    int length)
{
    if (!connection_ptr)
    {
        SetLastError("Connection is null");
        return PMS_SSL_ERROR;
    }

    if (!buffer && length > 0)
    {
        SetLastError("Buffer is null");
        return PMS_SSL_ERROR;
    }

    if (length == 0)
        return 0;

    auto* connection =
        static_cast<PmsSslConnection*>(connection_ptr);

    BIO* bio = SSL_get_rbio(connection->ssl);

    if (!bio)
    {
        SetLastError("Read BIO is null");
        return PMS_SSL_ERROR;
    }

    int result = BIO_write(
        bio,
        buffer,
        length);

    if (result <= 0)
    {
        SetOpenSslError("BIO_write failed");
        return PMS_SSL_ERROR;
    }

    return result;
}

PMS_EXPORT int PMS_CALL pms_ssl_take_write(
    void* connection_ptr,
    uint8_t* buffer,
    int length)
{
    if (!connection_ptr)
    {
        SetLastError("Connection is null");
        return PMS_SSL_ERROR;
    }

    if (!buffer && length > 0)
    {
        SetLastError("Buffer is null");
        return PMS_SSL_ERROR;
    }

    if (length == 0)
        return 0;

    auto* connection =
        static_cast<PmsSslConnection*>(connection_ptr);

    BIO* bio = SSL_get_wbio(connection->ssl);

    if (!bio)
    {
        SetLastError("Write BIO is null");
        return PMS_SSL_ERROR;
    }

    int result = BIO_read(
        bio,
        buffer,
        length);

    if (result < 0)
    {
        SetOpenSslError("BIO_read failed");
        return PMS_SSL_ERROR;
    }

    return result;
}

PMS_EXPORT int PMS_CALL pms_ssl_pending_write(
    void* connection_ptr)
{
    if (!connection_ptr)
    {
        SetLastError("Connection is null");
        return PMS_SSL_ERROR;
    }

    auto* connection =
        static_cast<PmsSslConnection*>(connection_ptr);

    BIO* bio = SSL_get_wbio(connection->ssl);

    if (!bio)
    {
        SetLastError("Write BIO is null");
        return PMS_SSL_ERROR;
    }

    return static_cast<int>(
        BIO_ctrl_pending(bio));
}

PMS_EXPORT int PMS_CALL pms_ssl_read(
    void* connection_ptr,
    uint8_t* buffer,
    int length)
{
    if (!connection_ptr)
    {
        SetLastError("Connection is null");
        return PMS_SSL_ERROR;
    }

    if (!buffer && length > 0)
    {
        SetLastError("Buffer is null");
        return PMS_SSL_ERROR;
    }

    auto* connection =
        static_cast<PmsSslConnection*>(connection_ptr);

    int result = SSL_read(
        connection->ssl,
        buffer,
        length);

    if (result > 0)
        return result;

    return TranslateSslError(
        connection->ssl,
        result);
}

PMS_EXPORT int PMS_CALL pms_ssl_write(
    void* connection_ptr,
    const uint8_t* buffer,
    int length)
{
    if (!connection_ptr)
    {
        SetLastError("Connection is null");
        return PMS_SSL_ERROR;
    }

    if (!buffer && length > 0)
    {
        SetLastError("Buffer is null");
        return PMS_SSL_ERROR;
    }

    auto* connection =
        static_cast<PmsSslConnection*>(connection_ptr);

    int result = SSL_write(
        connection->ssl,
        buffer,
        length);

    if (result > 0)
        return result;

    return TranslateSslError(
        connection->ssl,
        result);
}

PMS_EXPORT const char* PMS_CALL
pms_ssl_get_protocol_version(
    void* connection_ptr)
{
    if (!connection_ptr)
        return "";

    auto* connection =
        static_cast<PmsSslConnection*>(connection_ptr);

    return SSL_get_version(connection->ssl);
}

PMS_EXPORT const char* PMS_CALL
pms_ssl_get_cipher_name(
    void* connection_ptr)
{
    if (!connection_ptr)
        return "";

    auto* connection =
        static_cast<PmsSslConnection*>(connection_ptr);

    const SSL_CIPHER* cipher =
        SSL_get_current_cipher(connection->ssl);

    if (!cipher)
        return "";

    return SSL_CIPHER_get_name(cipher);
}

PMS_EXPORT const char* PMS_CALL
pms_ssl_get_last_error()
{
    return g_last_error.c_str();
}

PMS_EXPORT void PMS_CALL pms_ssl_free(
    void* connection_ptr)
{
    if (!connection_ptr)
        return;

    auto* connection =
        static_cast<PmsSslConnection*>(connection_ptr);

    if (connection->ssl)
        SSL_free(connection->ssl);

    if (connection->ctx)
        SSL_CTX_free(connection->ctx);

    delete connection;
}

PMS_EXPORT int PMS_CALL pms_ssl_get_peer_certificate(
    void* connection_ptr,
    uint8_t* buffer,
    int max_length)
{
    if (!connection_ptr)
    {
        SetLastError("Connection is null");
        return PMS_SSL_ERROR;
    }

    auto* connection =
        static_cast<PmsSslConnection*>(connection_ptr);

    X509* cert = SSL_get_peer_certificate(connection->ssl);
    if (!cert)
    {
        SetLastError("No peer certificate found");
        return 0;
    }

    int cert_len = i2d_X509(cert, nullptr);
    if (cert_len <= 0)
    {
        SetOpenSslError("Failed to calculate certificate length");
        X509_free(cert);
        return PMS_SSL_ERROR;
    }

    if (!buffer)
    {
        X509_free(cert);
        return cert_len;
    }

    if (max_length < cert_len)
    {
        SetLastError("Buffer is too small for certificate");
        X509_free(cert);
        return PMS_SSL_ERROR;
    }

    uint8_t* out_ptr = buffer;
    if (i2d_X509(cert, &out_ptr) < 0)
    {
        SetOpenSslError("Failed to serialize certificate");
        X509_free(cert);
        return PMS_SSL_ERROR;
    }

    X509_free(cert);
    return cert_len;
}

}