#if !defined(__config_json_h__)
#define __config_json_h__ 1

#include <stdbool.h>

struct server_config;

bool parse_config_file(bool is_server, const char *file, struct server_config *config);

#endif // !defined(__config_json_h__)
