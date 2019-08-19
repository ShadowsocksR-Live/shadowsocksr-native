#ifndef __SSR_QR_CODE__
#define __SSR_QR_CODE__

#include <stddef.h>

struct server_config;

//
// Encode SSR QR code text from server config.
// Note: caller must release the text buffer using free().
//
char * ssr_qr_code_encode(const struct server_config *config, void*(*alloc_fn)(size_t size));

//
// Decode SSR base64 text to server config.
// Note: caller must release server_config data with config_release().
//
struct server_config * ssr_qr_code_decode(const char *text);

#endif
