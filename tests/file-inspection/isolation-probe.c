/* Synthetic Linux boundary probe. Replaces the parser only in a separate test image. */
#define _GNU_SOURCE
#include <sched.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/statfs.h>
#include <unistd.h>
int main(void) {
 if(unshare(CLONE_NEWUSER)==0)return 34;
 struct rlimit limit;
 if (getrlimit(RLIMIT_CORE,&limit) || limit.rlim_cur != 0) return 21;
 if (getrlimit(RLIMIT_AS,&limit) || limit.rlim_cur != 4294967296ULL) return 22;
 if (getrlimit(RLIMIT_NOFILE,&limit) || limit.rlim_cur != 128) return 23;
 int f=open("/bin/clamscan",O_WRONLY);
 if (f>=0 || errno!=EROFS) return 24;
 f=open("/signatures/forbidden-write",O_WRONLY|O_CREAT,0600);
 if (f>=0 || errno!=EROFS) return 25;
 if (access("/etc/passwd",F_OK)==0 || access("/proc/1/root/etc/passwd",F_OK)==0) return 26;
 struct statfs fs;
 if (statfs("/tmp",&fs) || fs.f_type!=0x01021994 || (unsigned long long)fs.f_blocks*fs.f_bsize>16777216ULL) return 27;
 FILE *status=fopen("/proc/self/status","r"); if(!status)return 28;
 char line[256];int caps=0;
 while(fgets(line,sizeof(line),status)) if(strncmp(line,"CapEff:",7)==0) caps=strtoull(line+7,NULL,16)==0;
 fclose(status);if(!caps)return 29;
 /* Namespace has only loopback. No route or host interface may be present. */
 FILE *route=fopen("/proc/net/route","r");if(!route)return 30;
 int routes=0;while(fgets(line,sizeof(line),route))routes++;fclose(route);if(routes!=1)return 31;
 int sock=socket(AF_INET,SOCK_STREAM,0);if(sock<0)return 32;
 struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons(9)};
 inet_pton(AF_INET,"192.0.2.1",&address.sin_addr);
 if(connect(sock,(struct sockaddr*)&address,sizeof(address))==0)return 33;
 close(sock);
 while(getchar()!=EOF){}
 puts("stdin: OK");return 0;
}
