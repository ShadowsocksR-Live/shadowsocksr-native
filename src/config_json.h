#if !defined(__config_json_h__)
#define __config_json_h__ 1

#include <stdbool.h>

struct server_config;

struct server_config* parse_config_file(bool is_server, const char* file);

#endif // !defined(__config_json_h__)
