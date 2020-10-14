
#include <json-c/json.h>
#include "config_json.h"
#include "ssr_executive.h"

bool json_iter_extract_object(const char *key, const struct json_object_iter *iter, const struct json_object **value) {
    bool result = false;
    do {
        struct json_object *val;
        if (key == NULL || iter == NULL || value == NULL) {
            break;
        }
        *value = NULL;
        if (strcmp(iter->key, key) != 0) {
            break;
        }
        val = iter->val;
        if (json_type_object != json_object_get_type(val)) {
            break;
        }
        *value = val; // json_object_get(val);
        result = true;
    } while (0);
    return result;
}

bool json_iter_extract_string(const char *key, const struct json_object_iter *iter, const char **value) {
    bool result = false;
    do {
        struct json_object *val;
        if (key == NULL || iter == NULL || value == NULL) {
            break;
        }
        *value = NULL;
        if (strcmp(iter->key, key) != 0) {
            break;
        }
        val = iter->val;
        if (json_type_string != json_object_get_type(val)) {
            break;
        }
        *value = json_object_get_string(val);
        result = true;
    } while (0);
    return result;
}

bool json_iter_extract_int(const char *key, const struct json_object_iter *iter, int *value) {
    bool result = false;
    do {
        struct json_object *val;

        if (key == NULL || iter == NULL || value == NULL) {
            break;
        }
        *value = 0;
        if (strcmp(iter->key, key) != 0) {
            break;
        }
        val = iter->val;
        if (json_type_int != json_object_get_type(val)) {
            break;
        }
        *value = json_object_get_int(val);
        result = true;
    } while (0);
    return result;
}

bool json_iter_extract_bool(const char *key, const struct json_object_iter *iter, bool *value) {
    bool result = false;
    do {
        struct json_object *val;
        if (key == NULL || iter == NULL || value == NULL) {
            break;
        }
        *value = false;
        if (strcmp(iter->key, key) != 0) {
            break;
        }
        val = iter->val;
        if (json_type_boolean != json_object_get_type(val)) {
            break;
        }
        *value = (bool)json_object_get_boolean(val);
        result = true;
    } while (0);
    return result;
}

struct server_config* parse_config_file(bool is_server, const char* file)
{
    bool result = false;
    json_object *jso = NULL;
    struct server_config* config = config_create();
    do {
        struct json_object_iter iter = { NULL };

        jso = json_object_from_file(file);
        if (jso == NULL) {
            break;
        }
        json_object_object_foreachC(jso, iter) {
            int obj_int = 0;
            bool obj_bool = false;
            const char *obj_str = NULL;
            const struct json_object *obj_obj = NULL;

            if (json_iter_extract_string("password", &iter, &obj_str)) {
                string_safe_assign(&config->password, obj_str);
                continue;
            }
            if (json_iter_extract_string("method", &iter, &obj_str)) {
                string_safe_assign(&config->method, obj_str);
                continue;
            }
            if (json_iter_extract_string("protocol", &iter, &obj_str)) {
                if (obj_str && strcmp(obj_str, "verify_sha1") == 0) {
                    // LOGI("The verify_sha1 protocol is deprecate! Fallback to origin protocol.");
                    obj_str = NULL;
                }
                string_safe_assign(&config->protocol, obj_str);
                continue;
            }
            if (json_iter_extract_string("protocol_param", &iter, &obj_str)) {
                string_safe_assign(&config->protocol_param, obj_str);
                continue;
            }
            if (json_iter_extract_string("obfs", &iter, &obj_str)) {
                string_safe_assign(&config->obfs, obj_str);
                continue;
            }
            if (json_iter_extract_string("obfs_param", &iter, &obj_str)) {
                string_safe_assign(&config->obfs_param, obj_str);
                continue;
            }

            if (json_iter_extract_bool("udp", &iter, &obj_bool)) {
                config->udp = obj_bool;
                continue;
            }
            if (json_iter_extract_int("idle_timeout", &iter, &obj_int)) {
                config->idle_timeout = obj_int * MILLISECONDS_PER_SECOND;
                continue;
            }
            if (json_iter_extract_int("connect_timeout", &iter, &obj_int)) {
                config->connect_timeout_ms = ((uint64_t)obj_int) * MILLISECONDS_PER_SECOND;
                continue;
            }
            if (json_iter_extract_int("udp_timeout", &iter, &obj_int)) {
                config->udp_timeout = ((uint64_t)obj_int) * MILLISECONDS_PER_SECOND;
                continue;
            }

            // Backward compatibility with old client configure file format.
            if (is_server == false) {
                if (json_iter_extract_string("server", &iter, &obj_str)) {
                    string_safe_assign(&config->remote_host, obj_str);
                    continue;
                }
                if (json_iter_extract_int("server_port", &iter, &obj_int)) {
                    config->remote_port = obj_int;
                    continue;
                }
                if (json_iter_extract_string("local_address", &iter, &obj_str)) {
                    string_safe_assign(&config->listen_host, obj_str);
                    continue;
                }
                if (json_iter_extract_int("local_port", &iter, &obj_int)) {
                    config->listen_port = obj_int;
                    continue;
                }
            }

            if (json_iter_extract_object("server_settings", &iter, &obj_obj)) {
                struct json_object_iter iter2 = { NULL };
                if (is_server == false) {
                    continue;
                }
                json_object_object_foreachC(obj_obj, iter2) {
                    const char *obj_str2 = NULL;

                    if (json_iter_extract_string("listen_address", &iter2, &obj_str2)) {
                        string_safe_assign(&config->listen_host, obj_str2);
                        continue;
                    }
                    if (json_iter_extract_int("listen_port", &iter2, &obj_int)) {
                        config->listen_port = obj_int;
                        continue;
                    }
                }
                continue;
            }

            if (json_iter_extract_object("client_settings", &iter, &obj_obj)) {
                struct json_object_iter iter2 = {NULL};
                if (is_server) {
                    continue;
                }
                json_object_object_foreachC(obj_obj, iter2) {
                    const char *obj_str2 = NULL;

                    if (json_iter_extract_string("server", &iter2, &obj_str2)) {
                        string_safe_assign(&config->remote_host, obj_str2);
                        continue;
                    }
                    if (json_iter_extract_int("server_port", &iter2, &obj_int)) {
                        config->remote_port = obj_int;
                        continue;
                    }
                    if (json_iter_extract_string("listen_address", &iter2, &obj_str2)) {
                        string_safe_assign(&config->listen_host, obj_str2);
                        continue;
                    }
                    if (json_iter_extract_int("listen_port", &iter2, &obj_int)) {
                        config->listen_port = obj_int;
                        continue;
                    }
                }
                continue;
            }

            if (json_iter_extract_object("over_tls_settings", &iter, &obj_obj)) {
                struct json_object_iter iter2 = { NULL };
                json_object_object_foreachC(obj_obj, iter2) {
                    const char *obj_str2 = NULL;
                    obj_bool = false;

                    if (json_iter_extract_bool("enable", &iter2, &obj_bool)) {
                        config->over_tls_enable = obj_bool;
                        continue;
                    }
                    if (json_iter_extract_string("server_domain", &iter2, &obj_str2)) {
                        string_safe_assign(&config->over_tls_server_domain, obj_str2);
                        continue;
                    }
                    if (json_iter_extract_string("path", &iter2, &obj_str2)) {
                        string_safe_assign(&config->over_tls_path, obj_str2);
                        continue;
                    }
                    if (json_iter_extract_string("root_cert_file", &iter2, &obj_str2)) {
                        string_safe_assign(&config->over_tls_root_cert_file, obj_str2);
                        continue;
                    }
                }
                continue;
            }
        }
        result = true;
    } while (0);
    if (jso) {
        json_object_put(jso);
    }
    if (result == false) {
        config_release(config);
        config = NULL;
    }
    return config;
}
