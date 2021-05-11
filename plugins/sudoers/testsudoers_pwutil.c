/* Use custom passwd/group functions with the normal pwutil_impl.c */
#define sudo_make_pwitem	testsudoers_make_pwitem
#define sudo_make_gritem	testsudoers_make_gritem
#define sudo_make_gidlist_item	testsudoers_make_gidlist_item
#define sudo_make_grlist_item	testsudoers_make_grlist_item

#define getpwnam		testsudoers_getpwnam
#define getpwuid		testsudoers_getpwuid
#define getgrnam		testsudoers_getgrnam
#define getgrgid		testsudoers_getgrgid
#define sudo_getgrouplist2_v1	testsudoers_getgrouplist2_v1

#include "tsgetgrpw.h"
#include "pwutil_impl.c"
