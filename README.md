# Minijail

Minijail is a sandboxing and containment tool used in Chrome OS, Brillo, and Android. It provides an executable that can be used to launch and sandbox other programs, and a library that can be used by code to sandbox itself.

# `libminijail`

`libminijail` is the sandboxing library provided by Minijail. The API and a description of each function follows.

* `void minijail_change_uid(struct minijail *j, uid_t uid)`

  Change user id to `uid`.

* `void minijail_change_gid(struct minijail *j, gid_t gid)`

* `void minijail_set_supplementary_gids(struct minijail *j, size_t size, const gid_t *list)`

* `int minijail_change_user(struct minijail *j, const char *user)`

* `int minijail_change_group(struct minijail *j, const char *group)`

* `void minijail_inherit_usergroups(struct minijail *j)`

* `void minijail_use_seccomp(struct minijail *j)`

* `void minijail_no_new_privs(struct minijail *j)`

* `void minijail_use_seccomp_filter(struct minijail *j)`

* `void minijail_set_seccomp_filter_tsync(struct minijail *j)`

* `void minijail_parse_seccomp_filters(struct minijail *j, const char *path)`

* `void minijail_parse_seccomp_filters_from_fd(struct minijail *j, int fd)`

* `void minijail_log_seccomp_filter_failures(struct minijail *j)`

* `void minijail_use_caps(struct minijail *j, uint64_t capmask)`

* `void minijail_capbset_drop(struct minijail *j, uint64_t capmask)`

* `void minijail_reset_signal_mask(struct minijail *j)`

* `void minijail_namespace_vfs(struct minijail *j)`

* `void minijail_namespace_enter_vfs(struct minijail *j, const char *ns_path)`

* `void minijail_skip_remount_private(struct minijail *j)`

* `void minijail_namespace_ipc(struct minijail *j)`

* `void minijail_namespace_net(struct minijail *j)`

* `void minijail_namespace_enter_net(struct minijail *j, const char *ns_path)`

* `void minijail_namespace_cgroups(struct minijail *j)`

* `void minijail_namespace_pids(struct minijail *j)`

* `void minijail_namespace_user(struct minijail *j)`

* `int minijail_uidmap(struct minijail *j, const char *uidmap)`

* `int minijail_gidmap(struct minijail *j, const char *gidmap)`

* `void minijail_remount_proc_readonly(struct minijail *j)`

* `void minijail_run_as_init(struct minijail *j)`

* `int minijail_write_pid_file(struct minijail *j, const char *path)`

* `int minijail_use_alt_syscall(struct minijail *j, const char *table)`

* `int minijail_add_to_cgroup(struct minijail *j, const char *path)`

* `int minijail_enter_chroot(struct minijail *j, const char *dir)`

* `int minijail_enter_pivot_root(struct minijail *j, const char *dir)`

* `char *minijail_get_original_path(struct minijail *j, const char *chroot_path)`

* `void minijail_mount_tmp(struct minijail *j)`

* `int minijail_mount_with_data(struct minijail *j, const char *src, const char *dest, const char *type, unsigned long flags, const char *data)`

* `int minijail_mount(struct minijail *j, const char *src, const char *dest, char *type, unsigned long flags)`

* `int minijail_bind(struct minijail *j, const char *src, const char *dest, writeable)`

* `void minijail_enter(const struct minijail *j)`

* `int minijail_run(struct minijail *j, const char *filename, *const argv[])`

* `int minijail_run_no_preload(struct minijail *j, const char *filename, *const argv[])`

* `int minijail_run_pid(struct minijail *j, const char *filename, *const argv[], pid_t *pchild_pid)`

* `int minijail_run_pipe(struct minijail *j, const char *filename, *const argv[], int *pstdin_fd)`

* `int minijail_run_pid_pipes(struct minijail *j, const char *filename,	*const argv[], pid_t *pchild_pid, int *pstdin_fd, int *pstdout_fd, int *pstderr_fd)`

* `int minijail_run_pid_pipes_no_preload(struct minijail *j, const char *filename, char *const argv[], pid_t *pchild_pid, int *pstdin_fd, int *pstdout_fd, int *pstderr_fd)`

* `int minijail_kill(struct minijail *j)`

* `int minijail_wait(struct minijail *j)`

* `void minijail_destroy(struct minijail *j)`
