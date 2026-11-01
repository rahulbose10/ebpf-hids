#ifndef EBPF_HIDS_PATH_H
#define EBPF_HIDS_PATH_H

#define AT_FDCWD_VAL -100
#define PATH_BUF 512
#define PATH_MASK (PATH_BUF - 1)
#define PATH_DEPTH 32
#define NAME_LIMIT 255

struct path_scratch {
	char buf[PATH_BUF * 2 + DETAIL_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct path_scratch);
} path_scratch SEC(".maps");

static __always_inline struct path_scratch *get_scratch(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&path_scratch, &key);
}

static __always_inline struct file *get_file(int fd)
{
	struct task_struct *task;
	struct file *f = 0;
	struct file **fds;
	unsigned int max_fds;

	task = (struct task_struct *)bpf_get_current_task();
	fds = BPF_CORE_READ(task, files, fdt, fd);
	max_fds = BPF_CORE_READ(task, files, fdt, max_fds);
	if (fd < 0 || (unsigned int)fd >= max_fds)
		return 0;
	bpf_probe_read_kernel(&f, sizeof(f), &fds[fd]);
	return f;
}

struct walk_ctx {
	struct path_scratch *s;
	struct dentry *dentry;
	struct dentry *mnt_root;
	struct mount *mnt;
	__u32 off;
};

static long walk_step(__u64 index, void *data)
{
	struct walk_ctx *w = data;
	struct dentry *dentry = w->dentry;
	struct mount *mnt = w->mnt;
	struct mount *mnt_parent;
	struct dentry *parent;
	const unsigned char *name;
	__u32 off = w->off & (PATH_BUF * 2 - 1);
	__u32 len;

	parent = BPF_CORE_READ(dentry, d_parent);
	if (dentry == w->mnt_root || dentry == parent) {
		mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
		if (mnt == mnt_parent)
			return 1;
		w->dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
		w->mnt = mnt_parent;
		w->mnt_root = BPF_CORE_READ(mnt_parent, mnt.mnt_root);
		return 0;
	}

	len = BPF_CORE_READ(dentry, d_name.len);
	name = BPF_CORE_READ(dentry, d_name.name);
	if (len > NAME_LIMIT)
		len = NAME_LIMIT;
	if (len == 0 || len + 1 > off)
		return 1;

	off = (off - len - 1) & PATH_MASK;
	w->s->buf[off] = '/';
	bpf_probe_read_kernel(&w->s->buf[off + 1], len & NAME_LIMIT, name);
	w->off = off;
	w->dentry = parent;
	return 0;
}

static __always_inline __u32 walk_dentries(struct path_scratch *s,
					   struct dentry *dentry,
					   struct vfsmount *vfsmnt)
{
	struct walk_ctx w = {};

	w.s = s;
	w.dentry = dentry;
	w.mnt = (void *)vfsmnt - bpf_core_field_offset(struct mount, mnt);
	w.mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);
	w.off = PATH_BUF;

	bpf_loop(PATH_DEPTH, walk_step, &w, 0);
	return w.off;
}

static __always_inline const char *abs_path(struct path_scratch *s, int dfd,
					    const char *upath)
{
	struct dentry *dentry;
	struct vfsmount *vfsmnt;
	struct task_struct *task;
	struct file *f;
	__u32 off;

	if (bpf_probe_read_user_str(&s->buf[PATH_BUF + 1], PATH_BUF - 1, upath) <= 0)
		return 0;
	if (s->buf[PATH_BUF + 1] == '/')
		return &s->buf[PATH_BUF + 1];

	if (dfd == AT_FDCWD_VAL) {
		task = (struct task_struct *)bpf_get_current_task();
		dentry = BPF_CORE_READ(task, fs, pwd.dentry);
		vfsmnt = BPF_CORE_READ(task, fs, pwd.mnt);
	} else {
		f = get_file(dfd);
		if (!f)
			return &s->buf[PATH_BUF + 1];
		dentry = BPF_CORE_READ(f, f_path.dentry);
		vfsmnt = BPF_CORE_READ(f, f_path.mnt);
	}
	if (!dentry || !vfsmnt)
		return &s->buf[PATH_BUF + 1];

	off = walk_dentries(s, dentry, vfsmnt);
	s->buf[PATH_BUF] = '/';
	if (off >= PATH_BUF)
		return &s->buf[PATH_BUF];
	return &s->buf[off & PATH_MASK];
}

static __always_inline const char *fd_path(struct path_scratch *s, int fd)
{
	struct dentry *dentry;
	struct vfsmount *vfsmnt;
	struct file *f;
	__u32 off;

	f = get_file(fd);
	if (!f)
		return 0;
	dentry = BPF_CORE_READ(f, f_path.dentry);
	vfsmnt = BPF_CORE_READ(f, f_path.mnt);
	if (!dentry || !vfsmnt)
		return 0;

	off = walk_dentries(s, dentry, vfsmnt);
	if (off >= PATH_BUF) {
		s->buf[PATH_BUF] = '/';
		s->buf[PATH_BUF + 1] = 0;
		return &s->buf[PATH_BUF];
	}
	s->buf[PATH_BUF] = 0;
	return &s->buf[off & PATH_MASK];
}

#endif
