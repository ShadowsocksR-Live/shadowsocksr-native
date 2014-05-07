#ifndef _ACL_H
#define _ACL_H

int init_acl(const char *path);
void free_acl(void);
int is_bypass(const char* host);

#endif // _ACL_H
