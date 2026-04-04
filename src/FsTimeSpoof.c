#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/err.h>
#include <syscall.h>
#include <kputils.h>
#include <uapi/asm-generic/unistd.h>
#include <uapi/linux/stat.h>

KPM_NAME("FsTimeSpoof");
KPM_VERSION("0.1.0");
KPM_LICENSE("AGPLv3");
KPM_AUTHOR("时汐安");
KPM_DESCRIPTION("Spoof the modification dates of files and folders");

#define MAX_FAKE_ENTRIES 64
#define PATH_MAX_LEN 256

struct kstat_buf {
    uint64_t _pad0[9];
    int64_t  atime_sec;
    uint32_t atime_nsec;
    int64_t  mtime_sec;
    uint32_t mtime_nsec;
    int64_t  ctime_sec;
    uint32_t ctime_nsec;
};

struct fake_entry {
    char path[PATH_MAX_LEN];
    int64_t sec;
    uint32_t nsec;
    int valid;
};

static struct fake_entry entries[MAX_FAKE_ENTRIES];
static int entry_count;

static void (*do_kfree)(const void *) = 0;
static void *(*do_memdup_user)(const void __user *, size_t) = 0;

static int64_t parse_time(const char *s)
{
    int64_t sec = 0;
    int neg = 0;
    if (*s == '-') { neg = 1; s++; }
    while (*s >= '0' && *s <= '9') {
        sec = sec * 10 + (*s - '0');
        s++;
    }
    if (neg) sec = -sec;
    return sec;
}

static void clear_all_entries(void)
{
    for (int i = 0; i < entry_count; i++) entries[i].valid = 0;
    entry_count = 0;
}

static int add_entry(const char *path, int64_t sec)
{
    if (entry_count >= MAX_FAKE_ENTRIES) return -1;
    struct fake_entry *e = &entries[entry_count];
    strncpy(e->path, path, PATH_MAX_LEN - 1);
    e->path[PATH_MAX_LEN - 1] = '\0';
    e->sec = sec;
    e->nsec = 0;
    e->valid = 1;
    entry_count++;
    return 0;
}

static const struct fake_entry *find_entry(const char *path)
{
    const char *p = path[0] == '/' ? path + 1 : path;
    for (int i = 0; i < entry_count; i++) {
        if (!entries[i].valid) continue;
        if (!strcmp(entries[i].path, path)) return &entries[i];
        const char *e = entries[i].path;
        if (e[0] == '/') e++;
        if (!strcmp(e, p)) return &entries[i];
    }
    return NULL;
}

static void patch_stat(void *buf, const struct fake_entry *e)
{
    struct kstat_buf *st = (struct kstat_buf *)buf;
    st->atime_sec = e->sec;   st->atime_nsec = e->nsec;
    st->mtime_sec = e->sec;   st->mtime_nsec = e->nsec;
    st->ctime_sec = e->sec;   st->ctime_nsec = e->nsec;
}

static void patch_statx(void *buf, const struct fake_entry *e)
{
    struct statx *sx = (struct statx *)buf;
    sx->stx_atime.tv_sec = e->sec;   sx->stx_atime.tv_nsec = e->nsec;
    sx->stx_btime.tv_sec = e->sec;   sx->stx_btime.tv_nsec = e->nsec;
    sx->stx_ctime.tv_sec = e->sec;   sx->stx_ctime.tv_nsec = e->nsec;
    sx->stx_mtime.tv_sec = e->sec;   sx->stx_mtime.tv_nsec = e->nsec;
}

static const struct fake_entry *resolve_path_from_args(void *args, int path_arg_index)
{
    const char __user *ufilename = (typeof(ufilename))syscall_argn(args, path_arg_index);
    char path[PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(path, ufilename, sizeof(path));
    if (flen <= 0 || flen >= PATH_MAX_LEN) return NULL;
    path[flen] = '\0';
    return find_entry(path);
}

typedef void (*patch_fn)(void *, const struct fake_entry *);

static void after_generic(hook_fargs0_t *args, int buf_arg_index,
                          size_t bufsize, patch_fn patcher)
{
    if ((long)args->ret < 0) return;
    const struct fake_entry *e = (const struct fake_entry *)args->local.data0;
    if (!e) return;

    void __user *statbuf = (void __user *)syscall_argn(args, buf_arg_index);
    char *kbuf = do_memdup_user(statbuf, bufsize);
    if (IS_ERR(kbuf)) return;

    patcher(kbuf, e);
    compat_copy_to_user(statbuf, kbuf, bufsize);
    do_kfree(kbuf);
}

static void before_newfstatat(hook_fargs4_t *args, void *udata)
{
    (void)udata;
    args->local.data0 = (uint64_t)resolve_path_from_args(args, 1);
}

static void before_statx(hook_fargs5_t *args, void *udata)
{
    (void)udata;
    args->local.data0 = (uint64_t)resolve_path_from_args(args, 1);
}

static void after_newfstatat(hook_fargs4_t *args, void *udata)
{
    (void)udata;
    after_generic((hook_fargs0_t *)args, 2, sizeof(struct kstat_buf), patch_stat);
}

static void after_statx(hook_fargs5_t *args, void *udata)
{
    (void)udata;
    after_generic((hook_fargs0_t *)args, 4, sizeof(struct statx), patch_statx);
}

static int parse_and_add(const char *args)
{
    const char *p = args;
    int added = 0;
    while (*p) {
        if (*p == '\n') p++;
        if (*p == '\0') break;
        const char *ps = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
        int plen = p - ps;
        if (plen <= 0 || plen >= PATH_MAX_LEN) { while (*p && *p != '\n') p++; continue; }
        while (*p == ' ' || *p == '\t') p++;
        const char *ts = p;
        while (*p && *p != '\n') p++;
        int tlen = p - ts;
        if (tlen <= 0) continue;

        char pb[PATH_MAX_LEN], tb[32];
        memcpy(pb, ps, plen); pb[plen] = '\0';
        memcpy(tb, ts, tlen); tb[tlen] = '\0';
        if (add_entry(pb, parse_time(tb)) == 0) added++;
    }
    return added;
}

static int itoa(char *buf, int n)
{
    char tmp[12];
    int len = 0;
    if (n == 0) {
        buf[0] = '0';
        return 1;
    }
    while (n > 0) { tmp[len++] = '0' + (n % 10); n /= 10; }
    for (int i = 0; i < len; i++) buf[i] = tmp[len - 1 - i];
    return len;
}

static long faketime_init(const char *args, const char *event, void *__user reserved)
{
    (void)event;
    (void)reserved;

    do_kfree = (void *)kallsyms_lookup_name("kfree");
    do_memdup_user = (void *)kallsyms_lookup_name("memdup_user");
    if (!do_kfree || !do_memdup_user) return -1;

    if (args && args[0]) parse_and_add(args);

    hook_err_t err = hook_syscalln(__NR3264_fstatat, 4, before_newfstatat, after_newfstatat, 0);
    if (err) return err;

    err = hook_syscalln(__NR_statx, 5, before_statx, after_statx, 0);
    if (err) {
        unhook_syscalln(__NR3264_fstatat, before_newfstatat, after_newfstatat);
        return err;
    }

    return 0;
}

static long faketime_control0(const char *ctl_args, char *__user out_msg, int outlen)
{
    if (!ctl_args) return -EINVAL;
    if (!strcmp(ctl_args, "clear")) {
        clear_all_entries();
        if (out_msg && outlen > 0) compat_copy_to_user(out_msg, "cleared", sizeof("cleared"));
        return 0;
    }
    int added = parse_and_add(ctl_args);
    char resp[32];
    memcpy(resp, "added ", sizeof("added "));
    int pos = 6 + itoa(resp + 6, added);
    resp[pos] = '\0';
    if (out_msg && outlen > 0) compat_copy_to_user(out_msg, resp, pos + 1);
    return 0;
}

static long faketime_exit(void *__user reserved)
{
    (void)reserved;
    unhook_syscalln(__NR3264_fstatat, before_newfstatat, after_newfstatat);
    unhook_syscalln(__NR_statx, before_statx, after_statx);
    clear_all_entries();
    return 0;
}

KPM_INIT(faketime_init);
KPM_CTL0(faketime_control0);
KPM_EXIT(faketime_exit);
