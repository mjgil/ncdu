/* ncdu - NCurses Disk Usage

  Copyright (c) Yorhel

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be included
  in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

#include "global.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>

#if HAVE_PTHREAD
#include <pthread.h>
#endif

#if HAVE_LINUX_MAGIC_H && HAVE_SYS_STATFS_H && HAVE_STATFS
#include <sys/statfs.h>
#include <linux/magic.h>
#endif

#if HAVE_URING
#include <liburing.h>
#ifdef __linux__
#include <sys/sysmacros.h>
#endif
#endif

#if defined(AT_NO_AUTOMOUNT)
#define NCDU_AT_NO_AUTOMOUNT AT_NO_AUTOMOUNT
#else
#define NCDU_AT_NO_AUTOMOUNT 0
#endif

#ifndef S_BLKSIZE
#define S_BLKSIZE 512
#endif

#define URING_QUEUE_DEPTH 64

struct scan_node {
  struct dir item;
  struct dir_ext ext;
  unsigned int nlink;
  char *name;
  char *full_path;
  struct scan_node **children;
  size_t child_count;
  size_t child_cap;
};

struct scan_entry {
  char *name;
  char *full_path;
  struct stat st;
  int st_ok;
  int st_errno;
#if HAVE_URING
  struct statx stx;
#endif
};

struct scan_ctx {
  int uring_enabled;
  int parallel_enabled;
  uint64_t rootdev;
  volatile int abort_requested;
};

static int scan_uring_enabled = 1;
static int scan_parallel_enabled = 1;

#if HAVE_PTHREAD
struct scan_job {
  struct scan_ctx *ctx;
  struct scan_node *node;
  int fd;
};

static pthread_mutex_t thread_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned active_threads;
static unsigned max_threads;
#endif

struct pending_subtree {
  struct scan_node *node;
  int fd;
#if HAVE_PTHREAD
  pthread_t tid;
  int async;
#endif
};


#if HAVE_LINUX_MAGIC_H && HAVE_SYS_STATFS_H && HAVE_STATFS
static int is_kernfs(unsigned long type) {
  if(
#ifdef BINFMTFS_MAGIC
     type == BINFMTFS_MAGIC ||
#endif
#ifdef BPF_FS_MAGIC
     type == BPF_FS_MAGIC ||
#endif
#ifdef CGROUP_SUPER_MAGIC
     type == CGROUP_SUPER_MAGIC ||
#endif
#ifdef CGROUP2_SUPER_MAGIC
     type == CGROUP2_SUPER_MAGIC ||
#endif
#ifdef DEBUGFS_MAGIC
     type == DEBUGFS_MAGIC ||
#endif
#ifdef DEVPTS_SUPER_MAGIC
     type == DEVPTS_SUPER_MAGIC ||
#endif
#ifdef PROC_SUPER_MAGIC
     type == PROC_SUPER_MAGIC ||
#endif
#ifdef PSTOREFS_MAGIC
     type == PSTOREFS_MAGIC ||
#endif
#ifdef SECURITYFS_MAGIC
     type == SECURITYFS_MAGIC ||
#endif
#ifdef SELINUX_MAGIC
     type == SELINUX_MAGIC ||
#endif
#ifdef SYSFS_MAGIC
     type == SYSFS_MAGIC ||
#endif
#ifdef TRACEFS_MAGIC
     type == TRACEFS_MAGIC ||
#endif
     0
    )
    return 1;
  return 0;
}
#endif


static void node_free(struct scan_node *node) {
  size_t i;

  if(!node)
    return;
  for(i=0; i<node->child_count; i++)
    node_free(node->children[i]);
  free(node->children);
  free(node->name);
  free(node->full_path);
  free(node);
}


static struct scan_node *node_create(const char *name, const char *full_path) {
  struct scan_node *node = xcalloc(1, sizeof(*node));
  node->name = xstrdup(name);
  node->full_path = xstrdup(full_path);
  return node;
}


static void node_add_child(struct scan_node *parent, struct scan_node *child) {
  if(parent->child_count == parent->child_cap) {
    parent->child_cap = parent->child_cap ? parent->child_cap * 2 : 16;
    parent->children = xrealloc(parent->children, parent->child_cap * sizeof(*parent->children));
  }
  parent->children[parent->child_count++] = child;
}


static char *join_path(const char *base, const char *name) {
  size_t bl = strlen(base);
  size_t nl = strlen(name);
  int slash = bl > 1 && base[bl-1] != '/';
  char *out = xmalloc(bl + nl + slash + 1);

  memcpy(out, base, bl);
  if(slash)
    out[bl++] = '/';
  memcpy(out + bl, name, nl + 1);
  return out;
}


static void node_from_stat(struct scan_node *node, const struct stat *st, uint64_t rootdev) {
  node->item.flags |= FF_EXT;
  node->item.ino = (uint64_t)st->st_ino;
  node->item.dev = (uint64_t)st->st_dev;

  if(S_ISREG(st->st_mode))
    node->item.flags |= FF_FILE;
  else if(S_ISDIR(st->st_mode))
    node->item.flags |= FF_DIR;

  if(!S_ISDIR(st->st_mode) && st->st_nlink > 1) {
    node->item.flags |= FF_HLNKC;
    node->nlink = st->st_nlink;
  } else
    node->nlink = 0;

  if(dir_scan_smfs && rootdev != (uint64_t)st->st_dev)
    node->item.flags |= FF_OTHFS;

  if(!(node->item.flags & (FF_OTHFS | FF_EXL | FF_KERNFS))) {
    node->item.size = st->st_blocks * S_BLKSIZE;
    node->item.asize = st->st_size;
  }

  node->ext.mode = st->st_mode;
  node->ext.mtime = st->st_mtime;
  node->ext.uid = (unsigned int)st->st_uid;
  node->ext.gid = (unsigned int)st->st_gid;
  node->ext.flags = FFE_MTIME | FFE_UID | FFE_GID | FFE_MODE;
}


static void scan_entry_sync(int dirfd, struct scan_entry *entry) {
  if(fstatat(dirfd, entry->name, &entry->st, AT_SYMLINK_NOFOLLOW) == 0)
    entry->st_ok = 1;
  else
    entry->st_errno = errno;
}


#if HAVE_URING
static void stat_from_statx(struct stat *st, const struct statx *stx) {
  memset(st, 0, sizeof(*st));
  st->st_mode = stx->stx_mode;
  st->st_nlink = stx->stx_nlink;
  st->st_uid = stx->stx_uid;
  st->st_gid = stx->stx_gid;
  st->st_ino = stx->stx_ino;
  st->st_size = stx->stx_size;
  st->st_blocks = stx->stx_blocks;
  st->st_mtime = stx->stx_mtime.tv_sec;
#ifdef __linux__
  st->st_dev = makedev(stx->stx_dev_major, stx->stx_dev_minor);
#endif
}


static void scan_entries_uring(struct scan_ctx *ctx, int dirfd, struct scan_entry *entries, size_t count) {
  struct io_uring ring;
  struct io_uring_probe *probe = NULL;
  size_t next = 0;
  size_t inflight = 0;
  int rc;

  if(!ctx->uring_enabled || !count)
    return;

  rc = io_uring_queue_init(count < URING_QUEUE_DEPTH ? (unsigned)count : URING_QUEUE_DEPTH, &ring, 0);
  if(rc < 0) {
    ctx->uring_enabled = 0;
    return;
  }

  probe = io_uring_get_probe_ring(&ring);
  if(!probe || !io_uring_opcode_supported(probe, IORING_OP_STATX)) {
    ctx->uring_enabled = 0;
    io_uring_free_probe(probe);
    io_uring_queue_exit(&ring);
    return;
  }
  io_uring_free_probe(probe);

  while((next < count || inflight) && !ctx->abort_requested) {
    while(next < count && inflight < URING_QUEUE_DEPTH) {
      struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
      if(!sqe)
        break;
      memset(&entries[next].stx, 0, sizeof(entries[next].stx));
      io_uring_prep_statx(sqe, dirfd, entries[next].name,
        AT_SYMLINK_NOFOLLOW | NCDU_AT_NO_AUTOMOUNT, STATX_BASIC_STATS, &entries[next].stx);
      io_uring_sqe_set_data64(sqe, next);
      next++;
      inflight++;
    }

    if(!inflight)
      break;

    rc = io_uring_submit_and_wait(&ring, 1);
    if(rc < 0) {
      ctx->uring_enabled = 0;
      break;
    }

    while(inflight) {
      struct io_uring_cqe *cqe;
      size_t idx;

      rc = io_uring_peek_cqe(&ring, &cqe);
      if(rc == -EAGAIN)
        break;
      if(rc < 0) {
        ctx->uring_enabled = 0;
        inflight = 0;
        break;
      }

      idx = (size_t)io_uring_cqe_get_data64(cqe);
      if(cqe->res >= 0) {
        stat_from_statx(&entries[idx].st, &entries[idx].stx);
        entries[idx].st_ok = 1;
      } else
        entries[idx].st_errno = -cqe->res;
      io_uring_cqe_seen(&ring, cqe);
      inflight--;
    }
  }

  io_uring_queue_exit(&ring);
}
#endif


static void scan_entries(int dirfd, struct scan_ctx *ctx, struct scan_entry *entries, size_t count) {
  size_t i;

#if HAVE_URING
  scan_entries_uring(ctx, dirfd, entries, count);
#endif

  for(i=0; i<count; i++)
    if(!entries[i].st_ok && !entries[i].st_errno)
      scan_entry_sync(dirfd, &entries[i]);
}


static int read_entries(int dirfd, struct scan_entry **entries, size_t *count, int *fail) {
  DIR *dir;
  struct dirent *de;
  struct scan_entry *list = NULL;
  size_t cap = 0, len = 0;
  int dupfd;

  *entries = NULL;
  *count = 0;
  *fail = 0;

  if((dupfd = dup(dirfd)) < 0) {
    *fail = 1;
    return 0;
  }

  if((dir = fdopendir(dupfd)) == NULL) {
    close(dupfd);
    *fail = 1;
    return 0;
  }

  while(1) {
    errno = 0;
    de = readdir(dir);
    if(!de) {
      if(errno)
        *fail = 1;
      break;
    }
    if(de->d_name[0] == '.' && (de->d_name[1] == 0 || (de->d_name[1] == '.' && de->d_name[2] == 0)))
      continue;

    if(len == cap) {
      cap = cap ? cap * 2 : 32;
      list = xrealloc(list, cap * sizeof(*list));
      memset(list + len, 0, (cap - len) * sizeof(*list));
    }

    memset(&list[len], 0, sizeof(*list));
    list[len].name = xstrdup(de->d_name);
    len++;
  }

  if(closedir(dir) < 0)
    *fail = 1;

  *entries = list;
  *count = len;
  return 1;
}


static void free_entries(struct scan_entry *entries, size_t count) {
  size_t i;

  for(i=0; i<count; i++) {
    free(entries[i].name);
    free(entries[i].full_path);
  }
  free(entries);
}


static int emit_open(struct scan_node *node) {
  if(node->item.flags & FF_ERR)
    dir_setlasterr(node->full_path);
  dir_curpath_set(node->full_path);

  if(dir_output.item(&node->item, node->name, &node->ext, node->nlink)) {
    dir_seterr("Output error: %s", strerror(errno));
    return 1;
  }
  if(input_handle(1))
    return 1;
  return 0;
}


static int emit_close(struct scan_node *node) {
  dir_curpath_set(node->full_path);
  if(dir_output.item(NULL, 0, NULL, 0)) {
    dir_seterr("Output error: %s", strerror(errno));
    return 1;
  }
  if(input_handle(1))
    return 1;
  return 0;
}


static int emit_node(struct scan_node *node) {
  size_t i;

  if(emit_open(node))
    return 1;

  if(node->item.flags & FF_DIR) {
    for(i=0; i<node->child_count; i++)
      if(emit_node(node->children[i]))
        return 1;

    if(emit_close(node))
      return 1;
  }

  return 0;
}


static int scan_directory_tree(struct scan_ctx *ctx, struct scan_node *node, int dirfd);
static int scan_directory_stream(struct scan_ctx *ctx, struct scan_node *node, int dirfd);


#if HAVE_PTHREAD
static int try_acquire_worker(void) {
  int ok = 0;

  pthread_mutex_lock(&thread_lock);
  if(active_threads < max_threads) {
    active_threads++;
    ok = 1;
  }
  pthread_mutex_unlock(&thread_lock);
  return ok;
}


static void release_worker(void) {
  pthread_mutex_lock(&thread_lock);
  if(active_threads)
    active_threads--;
  pthread_mutex_unlock(&thread_lock);
}


static void *scan_job_main(void *arg) {
  struct scan_job *job = arg;
  scan_directory_tree(job->ctx, job->node, job->fd);
  close(job->fd);
  release_worker();
  return arg;
}
#endif


static int should_recurse(struct scan_node *node) {
  return (node->item.flags & FF_DIR)
    && !(node->item.flags & (FF_ERR | FF_EXL | FF_OTHFS | FF_KERNFS | FF_FRMLNK));
}


static struct scan_node *scan_item(struct scan_ctx *ctx, int parentfd, struct scan_entry *entry, int *childfd_out) {
  struct scan_node *node = node_create(entry->name, entry->full_path);
  struct stat follow;
  int childfd = -1;

  *childfd_out = -1;

#ifdef __CYGWIN__
  if(strchr(entry->name, '/') || strchr(entry->name, '\\')) {
    node->item.flags |= FF_ERR;
    return node;
  }
#endif

  if(exclude_match(entry->full_path)) {
    node->item.flags |= FF_EXL;
    return node;
  }

  if(!entry->st_ok) {
    node->item.flags |= FF_ERR;
    return node;
  }

  if(follow_symlinks && S_ISLNK(entry->st.st_mode)
      && fstatat(parentfd, entry->name, &follow, 0) == 0
      && !S_ISDIR(follow.st_mode))
    node_from_stat(node, &follow, ctx->rootdev);
  else
    node_from_stat(node, &entry->st, ctx->rootdev);

  if(node->item.flags & FF_DIR) {
#if HAVE_LINUX_MAGIC_H && HAVE_SYS_STATFS_H && HAVE_STATFS
    if(exclude_kernfs) {
      struct statfs fst;
      childfd = openat(parentfd, entry->name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
      if(childfd < 0)
        node->item.flags |= FF_ERR;
      else if(fstatfs(childfd, &fst) != 0)
        node->item.flags |= FF_ERR;
      else if(is_kernfs(fst.f_type))
        node->item.flags |= FF_KERNFS;
    }
#endif

#if HAVE_SYS_ATTR_H && HAVE_GETATTRLIST && HAVE_DECL_ATTR_CMNEXT_NOFIRMLINKPATH
    if(!follow_firmlinks && !(node->item.flags & (FF_ERR | FF_KERNFS))) {
      struct attrlist list = {
        .bitmapcount = ATTR_BIT_MAP_COUNT,
        .forkattr = ATTR_CMNEXT_NOFIRMLINKPATH,
      };
      struct {
        uint32_t length;
        attrreference_t reference;
        char extra[PATH_MAX];
      } __attribute__((aligned(4), packed)) attributes;

      if(getattrlist(node->full_path, &list, &attributes, sizeof(attributes), FSOPT_ATTR_CMN_EXTENDED) == -1)
        node->item.flags |= FF_ERR;
      else if(strcmp(node->full_path, (char *)&attributes.reference + attributes.reference.attr_dataoffset))
        node->item.flags |= FF_FRMLNK;
    }
#endif

    if(cachedir_tags && should_recurse(node) && has_cachedir_tag(node->full_path)) {
      node->item.flags |= FF_EXL;
      node->item.size = 0;
      node->item.asize = 0;
    }

    if(should_recurse(node)) {
      if(childfd < 0) {
        childfd = openat(parentfd, entry->name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if(childfd < 0)
          node->item.flags |= FF_ERR;
      }
      if(should_recurse(node) && childfd >= 0) {
        *childfd_out = childfd;
        childfd = -1;
      }
    }
  }

  if(childfd >= 0)
    close(childfd);
  return node;
}


static int scan_directory_tree(struct scan_ctx *ctx, struct scan_node *node, int dirfd) {
  struct scan_entry *entries = NULL;
  struct pending_subtree *pending = NULL;
  size_t count = 0, i;
  int fail = 0;

  if(ctx->abort_requested)
    return 1;

  if(!read_entries(dirfd, &entries, &count, &fail)) {
    node->item.flags |= FF_ERR;
    return 0;
  }

  if(fail)
    node->item.flags |= FF_ERR;

  for(i=0; i<count; i++)
    entries[i].full_path = join_path(node->full_path, entries[i].name);

  scan_entries(dirfd, ctx, entries, count);

  pending = xcalloc(count ? count : 1, sizeof(*pending));
  for(i=0; i<count && !ctx->abort_requested; i++) {
    pending[i].node = scan_item(ctx, dirfd, &entries[i], &pending[i].fd);
    node_add_child(node, pending[i].node);
#if HAVE_PTHREAD
    if(pending[i].fd >= 0 && ctx->parallel_enabled && try_acquire_worker()) {
      struct scan_job *job = xmalloc(sizeof(*job));
      job->ctx = ctx;
      job->node = pending[i].node;
      job->fd = pending[i].fd;
      if(pthread_create(&pending[i].tid, NULL, scan_job_main, job) == 0) {
        pending[i].async = 1;
        pending[i].fd = -1;
      } else {
        release_worker();
        free(job);
      }
    }
#endif
  }

  for(i=0; i<count; i++) {
#if HAVE_PTHREAD
    if(pending[i].async) {
      void *ret = NULL;
      pthread_join(pending[i].tid, &ret);
      free(ret);
      continue;
    }
#endif
    if(pending[i].fd >= 0) {
      scan_directory_tree(ctx, pending[i].node, pending[i].fd);
      close(pending[i].fd);
    }
  }

  free_entries(entries, count);
  free(pending);
  return 0;
}


static void pending_cleanup(struct scan_ctx *ctx, struct pending_subtree *pending, size_t count) {
  size_t i;

  (void)ctx;
  for(i=0; i<count; i++) {
#if HAVE_PTHREAD
    if(pending[i].async) {
      void *ret = NULL;
      pthread_join(pending[i].tid, &ret);
      free(ret);
      node_free(pending[i].node);
      continue;
    }
#endif
    if(pending[i].fd >= 0)
      close(pending[i].fd);
    node_free(pending[i].node);
  }
}


static int scan_directory_stream(struct scan_ctx *ctx, struct scan_node *node, int dirfd) {
  struct scan_entry *entries = NULL;
  struct pending_subtree *pending = NULL;
  size_t count = 0, i;
  int fail = 0;
  int out_fail = 0;

  if(ctx->abort_requested)
    return 1;

  if(!read_entries(dirfd, &entries, &count, &fail))
    node->item.flags |= FF_ERR;
  else {
    if(fail)
      node->item.flags |= FF_ERR;

    for(i=0; i<count; i++)
      entries[i].full_path = join_path(node->full_path, entries[i].name);

    scan_entries(dirfd, ctx, entries, count);

    pending = xcalloc(count ? count : 1, sizeof(*pending));
    for(i=0; i<count && !ctx->abort_requested; i++) {
      pending[i].node = scan_item(ctx, dirfd, &entries[i], &pending[i].fd);
#if HAVE_PTHREAD
      if(pending[i].fd >= 0 && ctx->parallel_enabled && try_acquire_worker()) {
        struct scan_job *job = xmalloc(sizeof(*job));
        job->ctx = ctx;
        job->node = pending[i].node;
        job->fd = pending[i].fd;
        if(pthread_create(&pending[i].tid, NULL, scan_job_main, job) == 0) {
          pending[i].async = 1;
          pending[i].fd = -1;
        } else {
          release_worker();
          free(job);
        }
      }
#endif
    }
  }

  if(emit_open(node)) {
    ctx->abort_requested = 1;
    out_fail = 1;
    goto out;
  }

  for(i=0; i<count && !ctx->abort_requested; i++) {
#if HAVE_PTHREAD
    if(pending[i].async) {
      void *ret = NULL;
      pthread_join(pending[i].tid, &ret);
      free(ret);
      pending[i].async = 0;
      if(emit_node(pending[i].node)) {
        ctx->abort_requested = 1;
        out_fail = 1;
      }
      node_free(pending[i].node);
      pending[i].node = NULL;
      continue;
    }
#endif
    if(pending[i].fd >= 0) {
      if(scan_directory_stream(ctx, pending[i].node, pending[i].fd)) {
        ctx->abort_requested = 1;
        out_fail = 1;
      }
      close(pending[i].fd);
      pending[i].fd = -1;
      node_free(pending[i].node);
      pending[i].node = NULL;
      continue;
    }
    if(pending[i].node) {
      if(emit_node(pending[i].node)) {
        ctx->abort_requested = 1;
        out_fail = 1;
      }
      node_free(pending[i].node);
      pending[i].node = NULL;
    }
  }

  if(!ctx->abort_requested && emit_close(node)) {
    ctx->abort_requested = 1;
    out_fail = 1;
  }

out:
  if(pending)
    pending_cleanup(ctx, pending, count);
  free(pending);
  free_entries(entries, count);
  return out_fail;
}


static int process(void) {
  struct scan_ctx ctx;
  struct scan_node *root = NULL;
  struct stat st;
  char *path;
  int dirfd = -1;
  int fail = 0;

  memset(&ctx, 0, sizeof(ctx));
  ctx.uring_enabled = scan_uring_enabled;
#if HAVE_PTHREAD
  ctx.parallel_enabled = scan_parallel_enabled;
  active_threads = 0;
  max_threads = 0;
  {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if(n > 1)
      max_threads = (unsigned)n - 1;
  }
#endif

  if((path = path_real(dir_curpath)) == NULL)
    dir_seterr("Error obtaining full path: %s", strerror(errno));
  else {
    dir_curpath_set(path);
    free(path);
  }

  if(!dir_fatalerr && (dirfd = open(dir_curpath, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0)
    dir_seterr("Error changing directory: %s", strerror(errno));

  if(!dir_fatalerr && fstat(dirfd, &st) != 0)
    dir_seterr("Error obtaining directory information: %s", strerror(errno));
  if(!dir_fatalerr && !S_ISDIR(st.st_mode))
    dir_seterr("Not a directory");

  if(!dir_fatalerr) {
    ctx.rootdev = (uint64_t)st.st_dev;
    root = node_create(dir_curpath, dir_curpath);
    node_from_stat(root, &st, ctx.rootdev);
    fail = scan_directory_stream(&ctx, root, dirfd);
  }

  if(dirfd >= 0)
    close(dirfd);

  node_free(root);

  while(dir_fatalerr && !input_handle(0))
    ;
  return dir_output.final(dir_fatalerr || fail || ctx.abort_requested);
}


void dir_scan_uring_init(const char *path, int enable_uring, int enable_parallel) {
  scan_uring_enabled = enable_uring;
  scan_parallel_enabled = enable_parallel;
  dir_curpath_set(path);
  dir_setlasterr(NULL);
  dir_seterr(NULL);
  dir_process = process;
  pstate = ST_CALC;
}
