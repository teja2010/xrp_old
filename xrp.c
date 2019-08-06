#include <stdio.h>
#include <error.h>
#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>


/* included from deps/kernelsrc */
#include <bpf/bpf.h>
//#include <bpf/libbpf.h>
#include "bpf_load.h"




void load_simple_tcp2()
{
	char file[] = "xrp_tcp_simple.o";
	int ifindex = 0;
	struct bpf_object *obj = NULL;
	//char dev_name[] = "wlp4s0";
	char dev_name[] = "enp3s0";
	
	int dport1 = 1, dport2 = 0;

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
	printf("enter ports dport1 dport2\n");
	printf("enter 0 to cleanup & exit\n");
	printf("for all TCP connections to dport1, dest port will be"
		"modified to dport2\n");

	while(dport1 != 0 ) {
		printf("mode 1 dport1> ");
		scanf("%d",&dport1);
		if(dport1 == 0)
			break;
		printf("mode 1 dport2> ");
		scanf("%d",&dport2);
		dport1 = htons(dport1);
		dport2 = htons(dport2);

		if(bpf_map_update_elem(map_fd[0], &dport1, &dport2, 0)) {
			printf("map update failed, %s\n", strerror(errno));
			dport1 = 0;
		}
	}

	/* final clean up, unlink bpf prog*/
	if (set_link_xdp_fd(ifindex, -1, 0) < 0) {
		printf("set_link_xdp_fd clean up failed, %s\n",strerror(errno));
		exit(1);
	}

}

void load_simple_tcp()
{
	char file[] = "xrp_tcp_simple.o";
	int ifindex = 0;
	struct bpf_object *obj = NULL;
	//char dev_name[] = "wlp4s0";
	char dev_name[] = "enp3s0";
	char tc_path[1000] = {};
	char tc_cmd[1000] = {};
	int map_fd = 0;
	int dport1 = 1, dport2 = 0;
	FILE *fp = NULL;

	snprintf(tc_cmd, 1000, "tc filter add dev %s ingress bpf da obj %s sec tc_act",
			dev_name, file);
	fp = popen(tc_cmd, "r");
	if(fp == NULL) {
		printf("popen failed");
		exit(1);
	}

	snprintf(tc_path, 1000, "/sys/fs/bpf/tc/globals/%s", dev_name);
	map_fd = bpf_obj_get(tc_path);
	if(map_fd < 0) {
		printf("bpf_obj_get failed %s, %d", strerror(errno), errno);
		exit(1);
	}

	ifindex = if_nametoindex(dev_name);
	if (ifindex == 0)
		error(1, errno, "if_nametoindex(%s) failed", dev_name);

	printf("enter ports dport1 dport2\n");
	printf("enter 0 to cleanup & exit\n");
	printf("for all TCP connections to dport1, dest port will be"
		"modified to dport2\n");

	while(dport1 != 0 ) {
		printf("mode 1 dport1> ");
		scanf("%d",&dport1);
		if(dport1 == 0)
			break;
		printf("mode 1 dport2> ");
		scanf("%d",&dport2);
		dport1 = htons(dport1);
		dport2 = htons(dport2);

		if(bpf_map_update_elem(map_fd, &dport1, &dport2, 0)) {
			printf("map update failed, %s\n", strerror(errno));
			dport1 = 0;
		}
	}


}

void print_help()
{
	printf("1. TCP simple port change: dport ? dport <-> dport\n");
	printf("2. HTTP port change:  URI: dport <-> dport\n");
}

int main()
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	int input = 0;

	printf("****** X R P ******\n");
//	if(setrlimit(RLIMIT_MEMLOCK, &r)) {
//		perror("setrlimit(RLIMIT_MEMLOCK)");
//		exit(1);
//	}


	printf("enter mode:\n");
	printf("> ");
	scanf("%d", &input);

	switch(input) {
	case 1:
		load_simple_tcp();
		break;
	default:
		print_help();
		break;
	}

	return 0;
}
