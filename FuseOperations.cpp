/*
    This file is part of AuditedFS.
    Copyright (C) 2017-2018  ReimuNotMoe <reimuhatesfdt@gmail.com>

    AuditedFS is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    AuditedFS is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with AuditedFS.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "AuditedFS.hpp"

using AuditedFS::Audit;

void *AuditedFS::FuseOperations::xmp_init(struct fuse_conn_info *conn) {
	(void) conn;


	return NULL;
}


int AuditedFS::FuseOperations::xmp_getattr(const char *path, struct stat *stbuf) {
	int res;

	res = lstat(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

int AuditedFS::FuseOperations::xmp_access(const char *path, int mask) {
	int res;

	res = access(path, mask);
	if (res == -1)
		return -errno;

	return 0;
}

int AuditedFS::FuseOperations::xmp_readlink(const char *path, char *buf, size_t size) {
	int res;

	res = readlink(path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}

int AuditedFS::FuseOperations::xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
					   struct fuse_file_info *fi) {

	auto ctx_fuse = fuse_get_context();

	LogD("AuditedFS", "audit: UID=%u PID=%u: readdir(\"%s\")\n", ctx_fuse->uid, ctx_fuse->pid, path);



	DIR *dp;
	struct dirent *de;

//	open_by_handle_at()


	dp = opendir(path);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

int AuditedFS::FuseOperations::xmp_mknod(const char *path, mode_t mode, dev_t rdev) {
	int res;

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

int AuditedFS::FuseOperations::xmp_mkdir(const char *path, mode_t mode) {
	int res;

	res = mkdir(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

int AuditedFS::FuseOperations::xmp_unlink(const char *path) {
	int res;

	res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

int AuditedFS::FuseOperations::xmp_rmdir(const char *path) {
	int res;

	res = rmdir(path);
	if (res == -1)
		return -errno;

	return 0;
}

int AuditedFS::FuseOperations::xmp_symlink(const char *from, const char *to) {
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

int AuditedFS::FuseOperations::xmp_rename(const char *from, const char *to) {
	int res;


	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

int AuditedFS::FuseOperations::xmp_link(const char *from, const char *to) {
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

int AuditedFS::FuseOperations::xmp_chmod(const char *path, mode_t mode) {
	int res;

	res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

int AuditedFS::FuseOperations::xmp_chown(const char *path, uid_t uid, gid_t gid) {
	int res;

	res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

int AuditedFS::FuseOperations::xmp_truncate(const char *path, off_t size) {
	int res;

	res = truncate(path, size);
	if (res == -1)
		return -errno;

	return 0;
}

int AuditedFS::FuseOperations::xmp_utimens(const char *path, const timespec *ts) {

	int res;

	/* don't use utime/utimes since they follow symlinks */
	res = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		return -errno;

	return 0;
}

int AuditedFS::FuseOperations::xmp_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
	int res;

	res = open(path, fi->flags, mode);
	if (res == -1)
		return -errno;

	fi->fh = res;
	return 0;
}

int AuditedFS::FuseOperations::xmp_open(const char *path, struct fuse_file_info *fi) {
	auto ctx_fuse = fuse_get_context();

	std::string path_chroot_base;
	auto rc_getflags = AuditedFS::Audit::GetFlags(ctx_fuse->uid, 0x10, path, path_chroot_base);

	if (rc_getflags == 0) {
		LogW("AuditedFS", "audit: UID=%u PID=%u: open(\"%s\"): Ask\n", ctx_fuse->uid, ctx_fuse->pid, path);
		// TODO
	} else {
		if (rc_getflags == 3) {
			auto path_chrooted = path_chroot_base + "/" + path;
			LogI("AuditedFS", "audit: UID=%u PID=%u: open(\"%s\"): Remapped to %s\n", ctx_fuse->uid,
			     ctx_fuse->pid, path, path_chrooted.c_str());
			path = path_chrooted.c_str();
		} else if (rc_getflags == 2) {
			LogW("AuditedFS", "audit: UID=%u PID=%u: open(\"%s\"): Denied\n", ctx_fuse->uid, ctx_fuse->pid,
			     path);
			return -EIO;
		} else {
			LogI("AuditedFS", "audit: UID=%u PID=%u: open(\"%s\"): Allowed\n", ctx_fuse->uid, ctx_fuse->pid, path);
		}
	}



	int res;

	res = open(path, fi->flags);
	if (res == -1)
		return -errno;

	fi->fh = res;
	return 0;
}

int
AuditedFS::FuseOperations::xmp_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	int fd;
	int res;


	if (fi == NULL)
		fd = open(path, O_RDONLY);
	else
		fd = fi->fh;

	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	if (fi == NULL)
		close(fd);
	return res;
}

int AuditedFS::FuseOperations::xmp_write(const char *path, const char *buf, size_t size, off_t offset,
					 struct fuse_file_info *fi) {
	int fd;
	int res;

	(void) fi;
	if(fi == NULL)
		fd = open(path, O_WRONLY);
	else
		fd = fi->fh;

	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	if(fi == NULL)
		close(fd);
	return res;
}

int AuditedFS::FuseOperations::xmp_statfs(const char *path, struct statvfs *stbuf) {
	int res;

	res = statvfs(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

int AuditedFS::FuseOperations::xmp_release(const char *path, struct fuse_file_info *fi) {
	(void) path;
	close(fi->fh);
	return 0;
}

int AuditedFS::FuseOperations::xmp_fsync(const char *path, int isdatasync, struct fuse_file_info *fi) {
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

int AuditedFS::FuseOperations::xmp_fallocate(const char *path, int mode, off_t offset, off_t length,
					     struct fuse_file_info *fi) {
	int fd;
	int res;

	(void) fi;

	if (mode)
		return -EOPNOTSUPP;

	if(fi == NULL)
		fd = open(path, O_WRONLY);
	else
		fd = fi->fh;

	if (fd == -1)
		return -errno;

	res = -posix_fallocate(fd, offset, length);

	if(fi == NULL)
		close(fd);
	return res;
}

int
AuditedFS::FuseOperations::xmp_setxattr(const char *path, const char *name, const char *value, size_t size, int flags) {
	int res = lsetxattr(path, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

int AuditedFS::FuseOperations::xmp_getxattr(const char *path, const char *name, char *value, size_t size) {
	int res = lgetxattr(path, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

int AuditedFS::FuseOperations::xmp_listxattr(const char *path, char *list, size_t size) {
	int res = llistxattr(path, list, size);
	if (res == -1)
		return -errno;
	return res;
}

int AuditedFS::FuseOperations::xmp_removexattr(const char *path, const char *name) {
	int res = lremovexattr(path, name);
	if (res == -1)
		return -errno;
	return 0;
}

fuse_operations AuditedFS::FuseOperations::GetOperations() {
	struct fuse_operations ret = {0};

	ret.init = xmp_init;
	ret.getattr = xmp_getattr;
	ret.access = xmp_access;
	ret.readlink = xmp_readlink;
	ret.readdir = xmp_readdir;
	ret.mknod = xmp_mknod;
	ret.mkdir = xmp_mkdir;
	ret.symlink = xmp_symlink;
	ret.unlink = xmp_unlink;
	ret.rmdir = xmp_rmdir;
	ret.rename = xmp_rename;
	ret.link = xmp_link;
	ret.chmod = xmp_chmod;
	ret.chown = xmp_chown;
	ret.truncate = xmp_truncate;
	ret.utimens = xmp_utimens;
	ret.open = xmp_open;
	ret.create = xmp_create;
	ret.read = xmp_read;
	ret.write = xmp_write;
	ret.statfs = xmp_statfs;
	ret.release = xmp_release;
	ret.fsync = xmp_fsync;
	ret.fallocate = xmp_fallocate;
	ret.setxattr = xmp_setxattr;
	ret.getxattr = xmp_getxattr;
	ret.listxattr = xmp_listxattr;
	ret.removexattr = xmp_removexattr;

	return ret;
}


