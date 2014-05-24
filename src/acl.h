#ifndef _ACL_H
#define _ACL_H

int init_acl(const char *path);
void free_acl(void);

int acl_contains_ip(const char* ip);
int acl_contains_domain(const char* domain);

#endif // _ACL_H
