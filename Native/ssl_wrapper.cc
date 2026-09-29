#include "ssl_wrapper.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cstdio>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#endif


struct PmsConnection {
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    BIO* bio = nullptr;
    BIO_METHOD* bio_method = nullptr;
    void* user_data = nullptr;
    pms_read_callback read_callback = nullptr;
    pms_write_callback write_callback = nullptr;
};

static thread_local std::string g_last_error;

static void SetLastError(const char* message) {
    g_last_error = message ? message : "unknown error";
}

static void SetOpenSslError(const char* prefix) 
{
    unsigned long error = ERR_get_error();
    if (error == 0) {
        SetLastError(prefix);
        return;
    }

    char error_string[256] = {};
    ERR_error_string_n(error, error_string, sizeof(error_string));
    g_last_error = std::string(prefix) + ": " + error_string;
}

static int BioRead(BIO* bio, char* out, int out_len) 
{
    auto* connection = static_cast<PmsConnection*>(BIO_get_data(bio));
    if (!connection || !connection->read_callback) {
        SetLastError("Invalid read callback");
        return -1;
    }

    return connection->read_callback(
        connection->user_data,
        reinterpret_cast<uint8_t*>(out),
        out_len);
}

static int BioWrite(BIO* bio, const char* in, int in_len) 
{
    auto* connection = static_cast<PmsConnection*>(BIO_get_data(bio));
    if (!connection || !connection->write_callback) {
        SetLastError("Invalid write callback");
        return -1;
    }

    return connection->write_callback(
        connection->user_data,
        reinterpret_cast<const uint8_t*>(in),
        in_len);
}

static long BioCtrl(BIO*, int cmd, long, void*) 
{
    switch (cmd) {
    case BIO_CTRL_FLUSH:
        return 1;
    case BIO_CTRL_PENDING:
    case BIO_CTRL_WPENDING:
        return 0;
    default:
        return 1;
    }
}

static int BioCreate(BIO* bio) 
{
    BIO_set_init(bio, 1);
    BIO_set_data(bio, nullptr);
    BIO_set_flags(bio, 0);
    return 1;
}

static int BioDestroy(BIO* bio) 
{
    if (!bio)
        return 0;

    BIO_set_data(bio, nullptr);
    BIO_set_init(bio, 0);
    return 1;
}

static BIO_METHOD* CreateBioMethod() 
{
    BIO_METHOD* method = BIO_meth_new(
        BIO_TYPE_SOURCE_SINK,
        "ProxyMap managed Stream BIO");

    if (!method)
        return nullptr;

    BIO_meth_set_write(method, BioWrite);
    BIO_meth_set_read(method, BioRead);
    BIO_meth_set_ctrl(method, BioCtrl);
    BIO_meth_set_create(method, BioCreate);
    BIO_meth_set_destroy(method, BioDestroy);
    return method;
}

void* PMS_CALL pms_ssl_create(
    void* user_data,
    pms_read_callback read_callback,
    pms_write_callback write_callback,
    const char* hostname) 
{

    auto* connection = new PmsConnection();
    connection->user_data = user_data;
    connection->read_callback = read_callback;
    connection->write_callback = write_callback;

    connection->ctx = SSL_CTX_new(TLS_client_method());
    if (!connection->ctx) {
        SetOpenSslError("SSL_CTX_new failed");
        delete connection;
        return nullptr;
    }

    // Proof of concept only. Certificate verification will be added later.
    SSL_CTX_set_verify(connection->ctx, SSL_VERIFY_NONE, nullptr);

    connection->ssl = SSL_new(connection->ctx);    
    if (!connection->ssl) {
        SetOpenSslError("SSL_new failed");
        SSL_CTX_free(connection->ctx);
        delete connection;
        return nullptr;
    }

    if (hostname && hostname[0] != '\0' &&
        !SSL_set_tlsext_host_name(connection->ssl, hostname)) {
        SetOpenSslError("SSL_set_tlsext_host_name failed");
        SSL_free(connection->ssl);
        SSL_CTX_free(connection->ctx);
        delete connection;
        return nullptr;
    }

    connection->bio_method = CreateBioMethod();
    if (!connection->bio_method) {
        SetOpenSslError("BIO_meth_new failed");
        SSL_free(connection->ssl);
        SSL_CTX_free(connection->ctx);
        delete connection;
        return nullptr;
    }

    connection->bio = BIO_new(connection->bio_method);
    if (!connection->bio) {
        SetOpenSslError("BIO_new failed");
        BIO_meth_free(connection->bio_method);
        SSL_free(connection->ssl);
        SSL_CTX_free(connection->ctx);
        delete connection;
        return nullptr;
    }

    BIO_set_data(connection->bio, connection);
    SSL_set_bio(connection->ssl, connection->bio, connection->bio);
    return connection;
}

int PMS_CALL pms_ssl_connect(void* ptr) {
    auto* connection = static_cast<PmsConnection*>(ptr);
    if (!connection || !connection->ssl) {
        SetLastError("Invalid SSL connection");
        return 0;
    }

    int result = SSL_connect(connection->ssl);
    if (result == 1)
        return 1;

    int error = SSL_get_error(connection->ssl, result);
    char message[128] = {};
    std::snprintf(message, sizeof(message), "SSL_connect failed, error=%d", error);
    SetOpenSslError(message);
    return 0;
}

int PMS_CALL pms_ssl_read(void* ptr, uint8_t* buffer, int offset, int length) {
    auto* connection = static_cast<PmsConnection*>(ptr);
    if (!connection || !connection->ssl || !buffer || offset < 0 || length <= 0) {
        SetLastError("Invalid SSL_read arguments");
        return -1;
    }

    int result = SSL_read(connection->ssl, buffer + offset, length);
    if (result > 0)
        return result;

    int error = SSL_get_error(connection->ssl, result);
    if (error == SSL_ERROR_ZERO_RETURN)
        return 0;

    if (error == SSL_ERROR_SYSCALL) {
#ifdef _WIN32        
        int sys_error = WSAGetLastError();
#else
        int sys_error = errno; 
#endif        
        unsigned long ossl_error = ERR_get_error();
        if (sys_error == 0 && ossl_error == 0) {
            return 0;
        }
    }

    char message[128] = {};
    std::snprintf(message, sizeof(message), "SSL_read failed, error=%d", error);
    SetOpenSslError(message);
    return -1;
}

int PMS_CALL pms_ssl_write(void* ptr, const uint8_t* buffer, int offset, int length) {
    auto* connection = static_cast<PmsConnection*>(ptr);
    if (!connection || !connection->ssl || !buffer || offset < 0 || length <= 0) {
        SetLastError("Invalid SSL_write arguments");
        return -1;
    }

    int result = SSL_write(connection->ssl, buffer + offset, length);
    if (result > 0)
        return result;

    int error = SSL_get_error(connection->ssl, result);
    char message[128] = {};
    std::snprintf(message, sizeof(message), "SSL_write failed, error=%d", error);
    SetOpenSslError(message);
    return -1;
}

const char* PMS_CALL pms_ssl_get_protocol_version(void* ptr) {
    auto* connection = static_cast<PmsConnection*>(ptr);
    return connection && connection->ssl ? SSL_get_version(connection->ssl) : "";
}

const char* PMS_CALL pms_ssl_get_cipher_name(void* ptr) {
    auto* connection = static_cast<PmsConnection*>(ptr);
    if (!connection || !connection->ssl)
        return "";

    const SSL_CIPHER* cipher = SSL_get_current_cipher(connection->ssl);
    return cipher ? SSL_CIPHER_get_name(cipher) : "";
}

const char* PMS_CALL pms_ssl_get_last_error(void) {
    return g_last_error.c_str();
}

void PMS_CALL pms_ssl_free(void* ptr) {
    auto* connection = static_cast<PmsConnection*>(ptr);
    if (!connection)
        return;

    BIO_METHOD* method = connection->bio_method;

    if (connection->ssl) {
        // SSL_free owns and frees the BIO installed with SSL_set_bio().
        SSL_free(connection->ssl);
        connection->ssl = nullptr;
        connection->bio = nullptr;
    }

    // BIO_free does not own/free the BIO_METHOD.
    if (method)
        BIO_meth_free(method);

    if (connection->ctx)
        SSL_CTX_free(connection->ctx);

    delete connection;
}
