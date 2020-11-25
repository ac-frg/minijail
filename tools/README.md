# Minijail tools

## generate_seccomp_policy.py

This script lets you build a Minijail seccomp-bpf filter from strace output.
This is very useful if the process that is traced has a fairly tight working
domain, and it can be traced in a few scenarios that will exercise all of the
needed syscalls. In particular, you should always make sure that failure cases
are also exercised to account for calls to `abort(2)`.

If `libminijail` or `minijail0` are used with preloading (the default with
dynamically-linked executables), the first few system calls after the first call
to `execve(2)` might not be needed, since the seccomp-bpf filter is installed
after that point in a sandboxed process.

### Sample usage

```shell
strace -f -e raw=all -o strace.txt -- <program>
./tools/generate_seccomp_policy.py --traces=strace.txt > <program>.policy
```

### (Experimental) Using linux audit logs to generate policy

Linux kernel v4.14+ support `SECCOMP_RET_LOG`. This allows minijail to log
syscalls via the `audit` subsystem instead of blocking them. One caveat of this
approach is that `SECCOMP_RET_LOG` does not log syscall arguments for finer
grained filtering.
The `audit` subsystem itself has a mechanism to log all syscalls. Though a
`SYSCALL` event is more voluminous than a corresponding `SECCOMP` event.
We employ here a combination of both techniques. We rely on `SECCOMP` for all
except the syscalls for which we want finer grained filtering.

Note that this requires python3 bindings for `auparse` which are generally
available in distro packages named `python3-audit` or `python-audit`.

#### Per-boot setup of audit rules on DUT

Set up `audit` rules and an empty seccomp policy for later use. This can be
done in the `pre-start` section of your upstart conf.

`$UID` is the uid for your process. Using root will lead to logspam.

```shell
auditctl -D
auditctl -a never,exclude -F msgtype!=AVC -F msgtype!=SELINUX_ERR \
         -F msgtype!=SECCOMP -F msgtype!=SYSCALL
for arch in b32 b64; do
  auditctl -a exit,always -F uid=$UID -F arch=$arch -F uid=0 -F gid=0 -S ioctl \
           -S socket -S prctl -S mmap -S mprotect
done
# TODO(aashay): Fix for ARM
touch /tmp/empty.policy
```

#### Run your program under minijail with an empty policy

Again, this can be done via your upstart conf. Just be sure to stimulate all
corner cases, error conditions, etc for comprehensive coverage.

```shell
minijail0 -u $UID -g $GID -L -S /tmp/empty.policy -- <program>
```

#### Generate policy using audit.log

```shell
./tools/generate_seccomp_policy.py --audit_log=audit.log \
    --audit_comm=$PROGRAM_NAME > $PROGRAM_NAME.policy
```

## compile_seccomp_policy.py

An external seccomp-bpf compiler that is documented [here][1]. This uses a
slightly different syntax and generates highly-optimized BPF binaries that can
be provided to `minijail0`'s `--seccomp-bpf-binary` or `libminijail`'s
`minijail_set_secomp_filters()`. This requires the existence of an
architecture-specific `constants.json` file that contains the mapping of syscall
names to numbers, the values of any compile-time constants that could be used to
simplify the parameter declaration for filters (like `O_RDONLY` and any other
constant defined in typical headers in `/usr/include`).

Policy files can also include references to frequency files, which enable
profile-guided optimization of the generated BPF code.

The generated BPF code can be analyzed using
[libseccomp](https://github.com/seccomp/libseccomp)'s `tools/scmp_bpf_disasm`.

### Sample usage

```shell
make minijail0 constants.json

# Create the .policy file using the syntax described in the documentation.
cat > test/seccomp.policy <<EOF
read: allow
write: allow
rt_sigreturn: allow
exit: allow
EOF

# Compile the .policy file into a .bpf filter
./tools/compile_seccomp_policy.py test/seccomp.policy test/seccomp.bpf

# Load the filter to sandbox your program.
./minijail0 --seccomp-bpf-binary=test/seccomp.bpf -- <program>
```

## generate_constants_json.py

This script generates the `constants.json` file from LLVM IR assembly files.
This makes it easier to generate architecture-specific `constants.json` files at
build-time.

[1]: https://docs.google.com/document/d/e/2PACX-1vQOeYLWmJJrRWvglnMo5cynkUe0gZ9wVsndLLePkJg6dfUXSOUWoveBBeY3u5nQMlEU4dt_vRgj0ifR/pub
