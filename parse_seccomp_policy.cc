/* Copyright 2016 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <getopt.h>
#include <stdio.h>

#include <string>

#include "bpf.h"
#include "syscall_filter.h"
#include "util.h"

namespace {

void DumpOneFilter(size_t i, struct sock_filter* filter) {
  constexpr int kWidth = 40;
  int written;
  const char *opcode, *op_name;

  // Print the index followed by the hex dump of filter.
  printf("%5zu: | %04x %02x %02x %08x | ", i, filter->code, filter->jt,
         filter->jf, filter->k);
  switch (filter->code & 0x7) {
    case 0x00:
      switch (filter->code) {
        case 0x60:
          printf("LD M[%d]\n", filter->k);
          return;
        case 0x20:
          printf("LDABSW %d\n", filter->k);
          return;
      }
      break;
    case 0x02:
      switch (filter->code) {
        case 0x02:
          printf("ST M[%d]\n", filter->k);
          return;
      }
      break;
    case 0x05:
      if (filter->code == 0x05) {
        written = printf("JMP %d", filter->k);
        printf("%*s; goto %zu\n", kWidth - written, "", i + filter->k + 1);
        return;
      }
      switch (filter->code) {
        case 0x15:
          opcode = "JEQ";
          op_name= "==";
          break;
        case 0x25:
          opcode = "JNE";
          op_name= "!=";
          break;
        case 0x35:
          opcode = "JLT";
          op_name= "<";
          break;
        case 0x45:
          opcode = "JLE";
          op_name= "<=";
          break;
        case 0x55:
          opcode = "JGT";
          op_name= ">";
          break;
        case 0x65:
          opcode = "JGE";
          op_name= ">=";
          break;
        case 0x75:
          opcode = "JSET";
          op_name= "&";
          break;
        case 0x85:
          opcode = "JIN";
          op_name= "in";
          break;
      }
      written =
          printf("%s %d %d %#x", opcode, filter->jt, filter->jf, filter->k);
      printf("%*s; %s %#x, t: %zu f: %zu\n", kWidth - written, "", op_name,
             filter->k, i + filter->jt + 1, i + filter->jf + 1);
      return;
    case 0x06:
      if (filter->k == SECCOMP_RET_KILL) {
        printf("RET SECCOMP_RET_KILL\n");
      } else if (filter->k == SECCOMP_RET_TRAP) {
        printf("RET SECCOMP_RET_TRAP\n");
      } else if ((filter->k & SECCOMP_RET_ACTION) == SECCOMP_RET_ERRNO) {
        printf("%-*s; errno = %d\n", kWidth, "RET SECCOMP_RET_ERRNO",
               filter->k & SECCOMP_RET_DATA);
      } else if (filter->k == SECCOMP_RET_TRACE) {
        printf("RET SECCOMP_RET_TRACE\n");
      } else if (filter->k == SECCOMP_RET_ALLOW) {
        printf("RET SECCOMP_RET_ALLOW\n");
      } else {
        printf("RET #%x\n", filter->k);
      }
      return;
  }
  // If we could not find a better match, just print out the formatted raw
  // structure.
  printf("{ code=%#x, jt=%u, jf=%u, k=%#x }\n", filter->code, filter->jt,
         filter->jf, filter->k);
}

void DumpBpfProg(struct sock_fprog* fprog) {
  struct sock_filter* filter = fprog->filter;
  unsigned short len = fprog->len;

  printf("len == %d\n", len);
  printf("filter:\n");
  for (size_t i = 0; i < len; i++) {
    DumpOneFilter(i, &filter[i]);
  }
}

void Usage(const char* progn) {
  // clang-format off
  fprintf(stderr,
          "Usage: %s [--dump <output.bpf>] <policy file>\n"
          " --dump <output>:  Dump the BPF program into <output>. Useful\n"
          "     -d <output>:  if you want to inspect it with libseccomp's\n"
          "                   scmp_bpf_disasm.\n",
          progn);
  // clang-format on
}

}  // namespace

int main(int argc, char** argv) {
  init_logging(LOG_TO_FD, STDERR_FILENO, LOG_INFO);

  const char* optstring = "d:h";
  const struct option long_options[] = {
      {"help", no_argument, 0, 'h'},
      {"dump", required_argument, 0, 'd'},
      {0, 0, 0, 0},
  };

  std::string dump_path;
  int opt;
  while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
    switch (opt) {
      case 'h':
        Usage(argv[0]);
        return 0;
      case 'd':
        dump_path = optarg;
        break;
    }
  }

  // There should be at least one additional unparsed argument: the
  // policy script.
  if (argc == optind) {
    Usage(argv[0]);
    return 1;
  }

  FILE* f = fopen(argv[optind], "re");
  if (!f)
    pdie("fopen(%s) failed", argv[1]);

  struct sock_fprog fp;
  int res = compile_filter(argv[1], f, &fp, 0, 0);
  fclose(f);
  if (res != 0)
    die("compile_filter failed");

  if (dump_path.empty()) {
    DumpBpfProg(&fp);
  } else {
    FILE* out = fopen(dump_path.c_str(), "we");
    if (!out)
      die("fopen(%s) failed", dump_path.c_str());
    if (fwrite(fp.filter, sizeof(struct sock_filter), fp.len, out) != fp.len)
      die("fwrite(%s) failed", dump_path.c_str());
    fclose(out);
  }

  free(fp.filter);
  return 0;
}
