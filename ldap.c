/*
 * Copyright (c) 1996, 1998-2002 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * 4. Products derived from this software may not be called "Sudo" nor
 *    may "Sudo" appear in their names without specific prior written
 *    permission from the author.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#ifdef HAVE_STRING_H
# include <string.h>
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif /* HAVE_STRING_H */
#if defined(HAVE_MALLOC_H) && !defined(STDC_HEADERS)
# include <malloc.h>
#endif /* HAVE_MALLOC_H && !STDC_HEADERS */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#include "sudo.h"
#include "parse.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

/* LDAP code below */


#ifdef HAVE_LDAP
#include <ldap.h>

#ifndef LDAP_CONFIG
#define LDAP_CONFIG "/etc/ldap.conf"
#endif

#define BUF_SIZ 1024

/* ldap configuration structure */
struct ldap_config {
  char *host;
  int  port;
  char *uri;
  char *binddn;
  char *bindpw;
  char *base;
  int debug;
} ldap_conf;

/*
 * Walks through search result and returns true if we have a
 * netgroup that matches our user
 */


int
sudo_ldap_check_user_netgroup(ld,entry)
  LDAP *ld;
  LDAPMessage *entry;
{
  char **v=NULL;
  char **p=NULL;

  int  ret=0;

  if (!entry) return ret;

  /* get the values from the entry */
  v=ldap_get_values(ld,entry,"sudoUser");

  /* walk through values */
  for (p=v; p && *p && !ret;p++)
  {
    if (ldap_conf.debug>1) printf("ldap sudoUser netgroup '%s' ...",*p);

    /* match any */
    if (netgr_matches(*p,NULL,NULL,user_name)) ret=1;

    if (ldap_conf.debug>1) printf(" %s\n",ret ? "MATCH!" : "not");
  }

  /* cleanup */
  if (v) ldap_value_free(v);

  /* all done */
  return ret;
}


/*
 * Walks through search result and returns true if we have a
 * host match
 */
int
sudo_ldap_check_host(ld,entry)
  LDAP *ld;
  LDAPMessage *entry;
{
  char **v=NULL;
  char **p=NULL;

  int  ret=0;

  if (!entry) return ret;

  /* get the values from the entry */
  v=ldap_get_values(ld,entry,"sudoHost");

  /* walk through values */
  for (p=v; p && *p && !ret;p++)
  {
    if (ldap_conf.debug>1) printf("ldap sudoHost '%s' ...",*p);

    /* match any or address or netgroup or hostname */
    if (
         !strcasecmp(*p,"ALL") ||
         addr_matches(*p) ||
         netgr_matches(*p,user_host,user_shost,NULL) ||
         !hostname_matches(user_shost,user_host,*p)
       )
    {
       ret=1;
    }


    if (ldap_conf.debug>1) printf(" %s\n",ret ? "MATCH!" : "not");
  }

  /* cleanup */
  if (v) ldap_value_free(v);

  /* all done */
  return ret;
}

/*
 * Walks through search result and returns true if we have a
 * runas match.  Since the runas directive in /etc/sudoers is optional,
 * so is the sudoRunAs attribute.
 *
 */

int sudo_ldap_check_runas(ld,entry)
  LDAP *ld;
  LDAPMessage *entry;
{
  char **v=NULL;
  char **p=NULL;

  int  ret=0;

  if (!entry) return ret;

  /* get the values from the entry */
  v=ldap_get_values(ld,entry,"sudoRunAs");

  /* BUG:
   *
   * if runas is not specified on the command line, the only information as
   * to which user to run as is in the runas_default option.
   * We should check check to see if we have the local option present.
   * Unfortunately we don't parse these options until after this routine
   * says yes * or no.  The query has already returned, so we could peek at the
   * attribute values here though.
   *
   * For now just require users to always use -u option unless its set
   * in the global defaults. This behaviour is no different than the global
   * /etc/sudoers.
   *
   * Sigh - maybe add this feature later
   *
   */

  /* If there are no runas entries, then match the runas_default with
   * whats on the command line
   */
  if (!v)
  {
    ret=!strcasecmp(*user_runas,def_str(I_RUNAS_DEFAULT));
  }

  /* what about the case where exactly one runas is specified in
   * the config and the user forgets the -u option, should we
   * switch it?  - Probably not
   */

  /* walk through values returned, looking for a match*/
  for (p=v; p && *p && !ret;p++)
  {
    if (ldap_conf.debug>1) printf("ldap sudoRunAs '%s' ...",*p);

    if (
         !strcasecmp(*p,*user_runas) ||
         !strcasecmp(*p,"ALL")
       )
    {
       ret = 1;
    }

    if (ldap_conf.debug>1) printf(" %s\n",ret ? "MATCH!" : "not");
  }

  /* cleanup */
  if (v) ldap_value_free(v);

  /* all done */
  return ret;
}

/*
 * Walks through search result and returns true if we have a
 * command match
 */
int sudo_ldap_check_command(ld,entry)
  LDAP *ld;
  LDAPMessage *entry;
{
  char **v=NULL;
  char **p=NULL;
  char *allowed_cmnd;
  char *allowed_args;
  int  ret=0;

  if (!entry) return ret;

  v=ldap_get_values(ld,entry,"sudoCommand");

  /* get_first_entry */
  for (p=v; p && *p && !ret;p++){
    if (ldap_conf.debug>1) printf("ldap sudoCommand '%s' ...",*p);

    /* Match against ALL ? */
    if (!strcasecmp(*p,"ALL")) {
      ret=1;
      if (safe_cmnd) free (safe_cmnd);
      safe_cmnd=estrdup(user_cmnd);
    }

    /* split optional args away from command */
    allowed_cmnd=estrdup(*p);
    allowed_args=strchr(allowed_cmnd,' ');
    if (allowed_args) *allowed_args++='\0';

    /* check the command like normal */
    if (command_matches(user_cmnd, user_args,allowed_cmnd,allowed_args)) ret=1;

    /* cleanup */
    free(allowed_cmnd);
    if (ldap_conf.debug>1) printf(" %s\n",ret ? "MATCH!" : "not");
  }

  /* more cleanup */
  if (v) ldap_value_free(v);

  /* all done */
  return ret;
}

/*
 * Read sudoOption, modify the defaults as we go.
 * This is used once from the cn=defaults entry
 * and also once when a final sudoRole is matched.
 *
 */
void
sudo_ldap_parse_options(ld,entry)
  LDAP *ld;
  LDAPMessage *entry;
{
  /* used to parse attributes */
  char **v=NULL;
  char **p=NULL;
  char *var;
  char *val;
  char op;

  if (!entry) return;

  v=ldap_get_values(ld,entry,"sudoOption");

  /* walk through options */
  for (p=v; p && *p;p++){

    if (ldap_conf.debug>1) printf("ldap sudoOption: '%s'\n",*p);
    var=estrdup(*p);
    /* check for = char */
    val=strchr(var,'=');

    /* check for equals sign past first char */
    if (val>var){
      *val++='\0'; /* split on = and truncate var */
      op=*(val-2); /* peek for += or -= cases */
      if (op == '+' || op == '-') {
        *(val-2)='\0'; /* found, remove extra char */
        /* case var+=val or var-=val */
        set_default(var,val,(int)op);
      } else {
        /* case var=val */
        set_default(var,val,TRUE);
      }
    } else if (*var=='!'){
      /* case !var Boolean False */
      set_default(var+1,NULL,FALSE);
    }  else {
      /* case var Boolean True */
      set_default(var,NULL,TRUE);
    }
    free(var);

  }

  if (v) ldap_value_free(v);

}

/*
 * Like strcat, only prevents buffer overflows
 */
void
_scatn(buf,bufsize,src)
  char *buf;
  size_t bufsize;
  char *src;
{

  /* make sure we have enough space,plus null at end */
  /* or silently truncate the string */
  if (bufsize>strlen(buf)+strlen(src)+1)
    strcat(buf,src);
}

/* builds together a filte to check against ldap
 */
char *
sudo_ldap_build_pass1()
{
  static char b[1024];
  struct group *grp;
  gid_t *grplist=NULL;
  int ngrps;
  int i;

  b[0]='\0'; /* empty string */


  /* global OR */
  _scatn(b,sizeof(b),"(|");

  /* build filter sudoUser=user_name */
  _scatn(b,sizeof(b),"(sudoUser=");
  _scatn(b,sizeof(b),user_name);
  _scatn(b,sizeof(b),")");

  /* Append primary group */
  grp=getgrgid(getgid());
  if (grp!=NULL){
    _scatn(b,sizeof(b),"(sudoUser=%");
    _scatn(b,sizeof(b),grp->gr_name);
    _scatn(b,sizeof(b),")");
  }

  /* handle arbitrary number of groups */
  if (0<(ngrps=getgroups(0,NULL))){
    grplist=calloc(ngrps,sizeof(gid_t));
    if (grplist!=NULL && (0<getgroups(ngrps,grplist)))
      for(i=0;i<ngrps;i++){
     if((grp=getgrgid(grplist[i]))!=NULL){
          _scatn(b,sizeof(b),"(sudoUser=%");
          _scatn(b,sizeof(b),grp->gr_name);
          _scatn(b,sizeof(b),")");
     }
      }
  }


  /* Add ALL to list */
  _scatn(b,sizeof(b),"(sudoUser=ALL)");

  /* End of OR List */
  _scatn(b,sizeof(b),")");
  return b ;
}


int
sudo_ldap_read_config()
{
  FILE *f;
  char buf[BUF_SIZ];
  char *c;
  char *keyword;
  char *value;

  f=fopen(LDAP_CONFIG,"r");
  if (!f) return 0;
  while (f && fgets(buf,sizeof(buf)-1,f)){
    c=buf;
    if (*c == '#')  continue; /* ignore comment */
    if (*c == '\n') continue; /* skip newline */
    if (!*c)        continue; /* incomplete last line */

    /* skip whitespace before keyword */
    while (isspace(*c)) c++;
    keyword=c;

    /* properly terminate keyword string */
    while (*c && !isspace(*c)) c++;
    if (*c) {
      *c='\0'; /* terminate keyword */
      c++;
    }

    /* skip whitespace before value */
    while (isspace(*c)) c++;
    value=c;

    /* trim whitespace after value */
    while (*c) c++; /* wind to end */
    while (--c > value && isspace(*c)) *c='\0';

    /* The following macros make the code much more readable */

#define MATCH_S(x,y) if (!strcasecmp(keyword,x)) \
    { if (y) free(y); y=estrdup(value); }
#define MATCH_I(x,y) if (!strcasecmp(keyword,x)) { y=atoi(value); }



    /* parse values using a continues chain of
     * if else if else if else if else ... */
         MATCH_S("host",    ldap_conf.host)
    else MATCH_I("port",    ldap_conf.port)
    else MATCH_S("uri",     ldap_conf.uri)
    else MATCH_S("binddn",  ldap_conf.binddn)
    else MATCH_S("bindpw",  ldap_conf.bindpw)
    else MATCH_S("sudoers_base",    ldap_conf.base)
    else MATCH_I("sudoers_debug",   ldap_conf.debug)
    else {

    /* The keyword was unrecognized.  Since this config file is shared
     * by multiple programs, it is appropriate to silently ignore options this
     * program does not understand
     */
    }

  } /* parse next line */

  if (f) fclose(f);

  /* defaults */
  if (!ldap_conf.port) ldap_conf.port=389;
  if (!ldap_conf.host) ldap_conf.host=estrdup("localhost");


  if (ldap_conf.debug>1) {
    printf("LDAP Config Summary\n");
    printf("===================\n");
    printf("host         %s\n", ldap_conf.host ?
                 ldap_conf.host   : "(NONE)");
    printf("port         %d\n", ldap_conf.port);

    printf("uri          %s\n", ldap_conf.uri ?
                 ldap_conf.uri    : "(NONE)");
    printf("sudoers_base %s\n", ldap_conf.base ?
                 ldap_conf.base : "(NONE) <---Sudo will ignore ldap)");
    printf("binddn       %s\n", ldap_conf.binddn ?
                 ldap_conf.binddn : "(anonymous)");
    printf("bindpw       %s\n", ldap_conf.bindpw ?
                 ldap_conf.bindpw : "(anonymous)");
    printf("===================\n");
  }

  /* if no base is defined, ignore LDAP */
  if (!ldap_conf.base) return 0;
  /* All is good */
  return 1;
}

/*
 * like sudoers_lookup() - only LDAP style
 *
 */

int
sudo_ldap_check(pwflag)
int pwflag;
{

  LDAP *ld=NULL;

  /* Used for searches */
  LDAPMessage *result=NULL;
  LDAPMessage *entry=NULL;
  /* used to parse attributes */
  char *f;
  /* temp/final return values */
  int rc=0;
  int ret=0;
  int pass=0;
  /* flags */
  int ldap_user_matches=0;
  int ldap_host_matches=0;

  if (!sudo_ldap_read_config())  return VALIDATE_ERROR;


  /* attempt connect */
  if (ldap_conf.uri) {

    if (ldap_conf.debug>1) fprintf(stderr,
           "ldap_initialize(ld,%s)\n",ldap_conf.uri);

    rc=ldap_initialize(&ld,ldap_conf.uri);
    if(rc){
      fprintf(stderr, "ldap_initialize()=%d : %s\n",
           rc,ldap_err2string(rc));
      return VALIDATE_ERROR;
    }
  } else if (ldap_conf.host) {

    if (ldap_conf.debug>1) fprintf(stderr,
           "ldap_init(%s,%d)\n",ldap_conf.host,ldap_conf.port);

    ld=ldap_init(ldap_conf.host,ldap_conf.port);
    if (!ld) {
      fprintf(stderr, "ldap_init(): errno=%d : %s\n",
                 errno, strerror(errno));
      return VALIDATE_ERROR;
    }
  }

  /* Acutally connect */

  rc=ldap_simple_bind_s(ld,ldap_conf.binddn,ldap_conf.bindpw);
  if(rc){
    fprintf(stderr,"ldap_simple_bind_s()=%d : %s\n",
           rc, ldap_err2string(rc));
    return VALIDATE_ERROR ;
  }

  if (ldap_conf.debug) printf("ldap_bind() ok\n");


  /* Parse Default Options */

  rc=ldap_search_s(ld,ldap_conf.base,LDAP_SCOPE_ONELEVEL,
             "cn=defaults",NULL,0,&result);
  if (!rc) {
    entry=ldap_first_entry(ld,result);
    if (ldap_conf.debug) printf("found:%s\n",ldap_get_dn(ld,entry));
    sudo_ldap_parse_options(ld,entry);
  } else {
    if (ldap_conf.debug) printf("no options found\n");
  }

  if (result) ldap_msgfree(result);
  result=NULL;

  /*
   * Okay - time to search for anything that matches this user
   * Lets limit it to only two queries of the LDAP server
   *
   * The first pass will look by the username, groups, and
   * the keyword ALL.  We will then inspect the results that
   * came back from the query.  We don't need to inspect the
   * sudoUser in this pass since the LDAP server already scanned
   * it for us.
   *
   * The second pass will return all the entries that contain
   * user netgroups.  Then we take the netgroups returned and
   * try to match them against the username.
   *
   */

  for(pass=1;!ret && pass<=2;pass++){

    if (pass==1) {
      /* Want the entries that match our usernames or groups */
      f=sudo_ldap_build_pass1();
    } else { /* pass=2 */
      /* Want the entries that have user netgroups in them. */
      f="sudoUser=+*";
    }
    if (ldap_conf.debug) printf("ldap search '%s'\n",f);
    rc=ldap_search_s(ld,ldap_conf.base,LDAP_SCOPE_ONELEVEL,
               f,NULL,0,&result);
    if (rc) {
      if (ldap_conf.debug) printf("nothing found for '%s'\n",f);
    }
    /* parse each entry returned from this most recent search */
    for(
        entry=rc ? NULL : ldap_first_entry(ld,result);
        entry!=NULL;
        entry=ldap_next_entry(ld,entry))
    {
      if (ldap_conf.debug) printf("found:%s\n",ldap_get_dn(ld,entry));
      if (
          /* first verify user netgroup matches - only if in pass 2 */
          (pass!=2 || sudo_ldap_check_user_netgroup(ld,entry)) &&
       /* remember that user matched */
       (ldap_user_matches=-1) &&
          /* verify host match */
          sudo_ldap_check_host(ld,entry) &&
       /* remember that host matched */
       (ldap_host_matches=-1) &&
          /* verify command match */
          sudo_ldap_check_command(ld,entry) &&
          /* verify runas match */
          sudo_ldap_check_runas(ld,entry)
      )
      {
        /* We have a match! */
        if(ldap_conf.debug) printf("Perfect Matched!\n");
        /* pick up any options */
        sudo_ldap_parse_options(ld,entry);
        /* make sure we dont reenter loop */
        ret=VALIDATE_OK;
        /* break from inside for loop */
        break;
      }

    }
    if (result) ldap_msgfree(result);
    result=NULL;

  }

  /* shut down connection */
  if (ld) ldap_unbind_s(ld);


  if (ldap_conf.debug) printf("user_matches=%d\n",ldap_user_matches);
  if (ldap_conf.debug) printf("host_matches=%d\n",ldap_host_matches);

  /*  I am not sure of the rest of the logic from here down */
  if (ret==0) {
    ret=VALIDATE_NOT_OK;
    if (!ldap_user_matches) ret|=FLAG_NO_USER;
    if (!ldap_host_matches) ret|=FLAG_NO_HOST;
  }

  /* Fixme - is this the right logic? */
  if (pwflag || !def_flag(I_AUTHENTICATE)) {
    ret|=FLAG_NOPASS;
  }

  if (ldap_conf.debug) printf("sudo_ldap_check()=0x%02x\n",ret);

  return ret ;
}

/*
 * Explicityly denied
 * VALIDATE_NOT_OK
 * VALIDATE_NOT_OK | FLAG_NOPASS
 * Explicitly Granted
 * VALIDATE_OK
 * VALIDATE_OK | FLAG_NOPASS
 * VALIDATE_OK |  -1 if found
 *
 * remove FLAG_NO_HOST
 * VALIDATE_ERROR  if could not connect to LDAP server
 *
 * FLAG_NO_CHECK
 * FLAG_NO_HOST
 * FLAG_NO_USER
 *
 *
 * Checked against
 * |VALIDATE_ERROR - complains of parse and dies
 * |FLAG_NOPASS - dont ask for password
 * |VALIDATE_OK - life is good - may be used with |FLAG_NOPASS
 *
 * |FLAG_NO_USER or |FLAG_NO_HOST - logs and dies
 * |VALIDATE_NOT_OK (! FLAG_NO_USER && ! FLAG_NO_HOST)
 * - command not allowed?
 *
 *
 */

#endif /* HAVE_LDAP */

