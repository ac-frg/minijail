#include <stdio.h>

#include "bpf.h"
#include "syscall_filter.h"
#include "util.h"

/* TODO(jorgelo): Use libseccomp disassembler here. */
int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <policy file>\n", argv[0]);
		return 1;
	}

	FILE *f = fopen(argv[1], "r");
	if (!f) {
		pdie("fopen(%s) failed", argv[1]);
	}

	struct sock_fprog fp;
	int res = compile_filter(f, &fp, 0);
	if (res != 0) {
		die("compile_filter failed");
	}
	dump_bpf_prog(&fp);

	free(fp.filter);
	fclose(f);
	return 0;
}
