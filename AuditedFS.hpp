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

#ifndef AUDITEDFS_AUDITEDFS_HPP
#define AUDITEDFS_AUDITEDFS_HPP

#define FUSE_USE_VERSION 26
#include <fuse.h>

#ifdef HAVE_LIBULOCKMGR
#include <ulockmgr.h>
#endif

#include <unordered_map>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cinttypes>
#include <cassert>

#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <sys/file.h>

#include <sqlite3.h>

#include <libReimu_System/libSystem.hpp>

extern char *Global_Path_SrcPath, *Global_Path_APISocket, *Global_Path_Database;
extern sqlite3 *Global_Ctx_Database;

namespace AuditedFS {
    class FuseOperations {

    public:
	static fuse_operations GetOperations();

    private:
	static void *xmp_init(struct fuse_conn_info *conn);
	static int xmp_getattr(const char *path, struct stat *stbuf);
	static int xmp_access(const char *path, int mask);
	static int xmp_readlink(const char *path, char *buf, size_t size);
	static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
	static int xmp_mknod(const char *path, mode_t mode, dev_t rdev);
	static int xmp_mkdir(const char *path, mode_t mode);
	static int xmp_unlink(const char *path);
	static int xmp_rmdir(const char *path);
	static int xmp_symlink(const char *from, const char *to);
	static int xmp_rename(const char *from, const char *to);
	static int xmp_link(const char *from, const char *to);
	static int xmp_chmod(const char *path, mode_t mode);
	static int xmp_chown(const char *path, uid_t uid, gid_t gid);
	static int xmp_truncate(const char *path, off_t size);
	static int xmp_utimens(const char *path, const struct timespec ts[2]);
	static int xmp_create(const char *path, mode_t mode, struct fuse_file_info *fi);
	static int xmp_open(const char *path, struct fuse_file_info *fi);
	static int xmp_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
	static int xmp_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
	static int xmp_statfs(const char *path, struct statvfs *stbuf);
	static int xmp_release(const char *path, struct fuse_file_info *fi);
	static int xmp_fsync(const char *path, int isdatasync, struct fuse_file_info *fi);
	static int xmp_fallocate(const char *path, int mode, off_t offset, off_t length, struct fuse_file_info *fi);
	static int xmp_setxattr(const char *path, const char *name, const char *value, size_t size, int flags);
	static int xmp_getxattr(const char *path, const char *name, char *value, size_t size);
	static int xmp_listxattr(const char *path, char *list, size_t size);
	static int xmp_removexattr(const char *path, const char *name);

    };


    class API {
    public:
	static void *Listener(void *userp);
    };

    class Audit {
    public:
	static int Init();
	// @return: 0: Ask, 1: Allow, 2: Deny, 3: ChRoot
	static int GetFlags(uint32_t __uid, int __flag, const char *__path, std::string &__chroot_path);
    };
}

#endif //AUDITEDFS_AUDITEDFS_HPP
