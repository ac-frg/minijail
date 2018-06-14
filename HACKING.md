# Hacking on Minijail

*   Minijail uses kernel coding style:
    https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/process/coding-style.rst
*   Utility functions with no side-effects should go in `util.{h|c}`.
*   Functions with side effects or with dependencies on operating system
    details, but that don't take a `struct minijail` argument, should go
    in `system.{h|c}`.
