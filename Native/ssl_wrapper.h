#pragma once
#include <stdint.h>

#ifdef _WIN32
#define PMS_EXPORT __declspec(dllexport)
#define PMS_CALL __cdecl
#else
#define PMS_EXPORT
#define PMS_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef int (PMS_CALL *pms_read_callback)(void* user_data, uint8_t* buffer, int length);
typedef int (PMS_CALL *pms_write_callback)(void* user_data, const uint8_t* buffer, int length);

PMS_EXPORT void* PMS_CALL pms_ssl_create(void* user_data, pms_read_callback read_callback,
    pms_write_callback write_callback, const char* hostname);
PMS_EXPORT int PMS_CALL pms_ssl_connect(void* connection);
PMS_EXPORT int PMS_CALL pms_ssl_read(void* connection, uint8_t* buffer, int offset, int length);
PMS_EXPORT int PMS_CALL pms_ssl_write(void* connection, const uint8_t* buffer, int offset, int length);
PMS_EXPORT const char* PMS_CALL pms_ssl_get_protocol_version(void* connection);
PMS_EXPORT const char* PMS_CALL pms_ssl_get_cipher_name(void* connection);
PMS_EXPORT const char* PMS_CALL pms_ssl_get_last_error(void);
PMS_EXPORT void PMS_CALL pms_ssl_free(void* connection);

#ifdef __cplusplus
}
#endif
