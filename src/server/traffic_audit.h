#if !defined(__traffic_audit_h__)
#define __traffic_audit_h__

#define USER_TAG_LEN_MAX 32

struct user_traffic {
    char user_tag[USER_TAG_LEN_MAX];
    size_t upload;
    size_t download;
};

#endif // !defined(__traffic_audit_h__)
