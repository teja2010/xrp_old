#include <stdio.h>
#include <error.h>
#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <string.h>
#include <unistd.h>


/* included from deps/kernelsrc */
#include <bpf/bpf.h>
//#include <bpf/libbpf.h>
#include "bpf_load.h"

void load_simple_tcp()
{
	char file[] = "xrp_tcp_simple.o";
	int ifindex = 0;
	struct bpf_object *obj = NULL;
	//char dev_name[] = "wlp4s0";
	char dev_name[] = "enp3s0";
	
	int input = 1;

	if (load_bpf_file(file))
		error(1, errno, "cant load %s", file);

	if (!prog_fd[0]) {
		printf("load_bpf_file error: %s\n", strerror(errno));
		exit(1);
	}

	ifindex = if_nametoindex(dev_name);
	if (ifindex == 0)
		error(1, errno, "if_nametoindex(%s) failed", dev_name);

	if (set_link_xdp_fd(ifindex, prog_fd[0], 0) < 0) {
		printf("set_link_xdp_fd failed, %s\n", strerror(errno));
		exit(1);
	}

	while(input != 0 ) {
		printf("enter port to drop packets\n>");
		printf("enter 0 to cleanup & exit:\n>");
		scanf("%d",&input);
		if(input ==0)
			continue;

		if(bpf_map_update_elem(map_fd[0], &input, &input, 0)) {
			printf("map update failed, %s\n", strerror(errno));
			input = 0;
		}
	}

	/* final clean up, unlink bpf prog*/
	if (set_link_xdp_fd(ifindex, -1, 0) < 0) {
		printf("set_link_xdp_fd clean up failed, %s\n",strerror(errno));
		exit(1);
	}

}



int main()
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

	printf("****** X R P ******\n");
//	if(setrlimit(RLIMIT_MEMLOCK, &r)) {
//		perror("setrlimit(RLIMIT_MEMLOCK)");
//		exit(1);
//	}


	load_simple_tcp();

	return 0;
}
