/*
  Copyright (c) 2021 Red Hat, Inc. <https://www.redhat.com>
  This file is part of GlusterFS.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

#include <glusterfs/gf-io.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <errno.h>

#include <glusterfs/globals.h>
#include <glusterfs/logging.h>
#include <glusterfs/gf-event.h>
#include <glusterfs/libglusterfs-messages.h>
#include <glusterfs/common-utils.h>

#define GF_IO_REQUIRED_FEATS                                                   \
    (IORING_FEAT_NODROP | IORING_FEAT_SUBMIT_STABLE | IORING_FEAT_FAST_POLL)

#define LG_MSG_IO_NOT_SUPPORTED_LVL(_res) GF_LOG_INFO
#define LG_MSG_IO_NOT_SUPPORTED_FMT                                            \
    "Kernel's io_uring interface is not present or doesn't support "           \
    "required features."

#define LG_MSG_IO_SYSCALL_LVL(_res) GF_LOG_ERROR
#define LG_MSG_IO_SYSCALL_FMT "%s() failed."

#define LG_MSG_IO_RING_TOO_SMALL_LVL(_res) GF_LOG_WARNING
#define LG_MSG_IO_RING_TOO_SMALL_FMT                                           \
    "Maximum allowed I/O Ring size is too small (%u)."

#define LG_MSG_IO_STARTED_LVL(_res) GF_LOG_INFO
#define LG_MSG_IO_STARTED_FMT "I/O Framework started in %s mode."

#define LG_MSG_IO_GETEVENTS_FAILED_LVL(_res) GF_LOG_ERROR
#define LG_MSG_IO_GETEVENTS_FAILED_FMT "Failed to get events from io_uring."

#define LG_MSG_IO_TOO_MANY_ERRORS_LVL(_res) GF_LOG_CRITICAL
#define LG_MSG_IO_TOO_MANY_ERRORS_FMT "Too many errors in %s() system call. %s."

#define LG_MSG_IO_NO_SQES_LVL(_res) GF_LOG_CRITICAL
#define LG_MSG_IO_NO_SQES_FMT                                                  \
    "Unable to get SQEs from kernel. New operations cannot be submitted "      \
    "to the kernel. Cannot guarantee proper operation."

#define LG_MSG_IO_NO_CQES_LVL(_res) GF_LOG_CRITICAL
#define LG_MSG_IO_NO_CQES_FMT                                                  \
    "Unable to get CQEs from kernel. Pending operations may not get "          \
    "completed. Cannot guarantee proper operation."

#define LG_MSG_IO_SQE_PENDING_LVL(_res) GF_LOG_CRITICAL
#define LG_MSG_IO_SQE_PENDING_FMT                                              \
    "An SQE has been submitted to the kernel but it cannot be determined "     \
    "whether it's being processed or not. Pending operation may block."

#define LG_MSG_IO_JOIN_FAILED_LVL(_res) GF_LOG_CRITICAL
#define LG_MSG_IO_JOIN_FAILED_FMT                                              \
    "Unable to terminate the thread for worker %p. This could lead to "        \
    "instability or hangs, specially during process termination."

#define LG_MSG_IO_THREAD_FAILED_LVL(_res) GF_LOG_ERROR
#define LG_MSG_IO_THREAD_FAILED_FMT                                            \
    "Unable to create a worker thread. System may be extremely low on "        \
    "resources."

#define LG_MSG_IO_WORKER_STARTED_LVL(_res) GF_LOG_DEBUG
#define LG_MSG_IO_WORKER_STARTED_FMT "Worker %p started."

#define LG_MSG_IO_WORKER_STOPPED_LVL(_res)                                     \
    ((_res) == 0 ? GF_LOG_DEBUG : GF_LOG_WARNING)
#define LG_MSG_IO_WORKER_STOPPED_FMT "Worker %p stopped."

#define LG_MSG_IO_WORKER_FAILED_LVL(_res) GF_LOG_CRITICAL
#define LG_MSG_IO_WORKER_FAILED_FMT                                            \
    "Worker %p failed after multiple unrecoverable errors."

#define LG_MSG_IO_WORKER_RESULT_LVL(_res)                                      \
    ((_res) == 0 ? GF_LOG_DEBUG : GF_LOG_WARNING)
#define LG_MSG_IO_WORKER_RESULT_FMT "Thread of worker %p terminated."

#define LG_MSG_IO_STOP_LOST_LVL(_res) GF_LOG_CRITICAL
#define LG_MSG_IO_STOP_LOST_FMT                                                \
    "Previous processing errors made impossible to correctly handle a stop "   \
    "request. Process may not be able to terminate."

#define LG_MSG_IO_FALLBACK_LVL(_res) GF_LOG_INFO
#define LG_MSG_IO_FALLBACK_FMT "Falling back to traditional I/O mode."

#define LG_MSG_IO_UNSTABLE_LVL(_res) GF_LOG_CRITICAL
#define LG_MSG_IO_UNSTABLE_FMT                                                 \
    "An unrecoverable error has happened in the middle of a sequence of "      \
    "operations. This could cause other unexpected errors, hung requests "     \
    "or other misbehaviors."

#define gf_io_log(_res, _msg, _args...)                                        \
    gf_msg("io", _msg##_LVL(_res), -(_res), _msg, _msg##_FMT, ##_args)

#define gf_io_debug(_res, _fmt, _args...)                                      \
    gf_msg_debug("io", -(_res), _fmt, ##_args)

#ifdef HAVE_IO_URING

/* Special gf_io_list_item_t pointer to mark availability of requests. */
#define GF_IO_REQUEST_READY ((gf_io_list_item_t *)(intptr_t)-1L)

#define GF_IO_BITNAME(_prefix, _name)                                          \
    {                                                                          \
        _prefix##_##_name, #_name                                              \
    }

typedef struct _gf_io_bitname {
    uint64_t bit;
    const char *name;
} gf_io_bitname_t;

static __thread gf_io_worker_t gf_io_worker = {};

#endif /* HAVE_IO_URING */

gf_io_t gf_io = {};

#ifdef HAVE_IO_URING

/* Close a file descriptor. */
static int32_t
gf_io_sys_close(int32_t fd)
{
    int32_t res;

    res = close(fd);
    if (caa_unlikely(res < 0)) {
        res = -errno;
        gf_io_log(res, LG_MSG_IO_SYSCALL, "close");
    }

    return res;
}

/* Get a monotonic time. */
static int32_t
gf_io_sys_clock_gettime(struct timespec *now)
{
    int32_t res;

    res = clock_gettime(CLOCK_MONOTONIC, now);
    if (caa_unlikely(res < 0)) {
        res = -errno;
        gf_io_log(res, LG_MSG_IO_SYSCALL, "clock_gettime");
    }

    return res;
}

static uint64_t
gf_io_time_ns(struct timespec *time)
{
    uint64_t ns;

    ns = (uint64_t)time->tv_sec * 1000000000ULL;
    ns += (uint64_t)time->tv_nsec;

    return ns;
}

/* Destroy a mutex. */
static int32_t
gf_io_sys_mutex_destroy(pthread_mutex_t *mutex)
{
    int32_t res;

    res = pthread_mutex_destroy(mutex);
    if (caa_unlikely(res != 0)) {
        res = -res;
        gf_io_log(res, LG_MSG_IO_SYSCALL, "pthread_mutex_destroy");
    }

    return res;
}

/* Initialize a mutex. */
static int32_t
gf_io_sys_mutex_init(pthread_mutex_t *mutex)
{
    int32_t res;

    res = pthread_mutex_init(mutex, NULL);
    if (caa_unlikely(res != 0)) {
        res = -res;
        gf_io_log(res, LG_MSG_IO_SYSCALL, "pthread_mutex_init");
    }

    return res;
}

/* Acquire a mutex. */
static int32_t
gf_io_sys_mutex_lock(pthread_mutex_t *mutex)
{
    int32_t res;

    res = pthread_mutex_lock(mutex);
    if (caa_unlikely(res != 0)) {
        res = -res;
        gf_io_log(res, LG_MSG_IO_SYSCALL, "pthread_mutex_lock");
    }

    return res;
}

/* Release a mutex. */
static int32_t
gf_io_sys_mutex_unlock(pthread_mutex_t *mutex)
{
    int32_t res;

    res = pthread_mutex_unlock(mutex);
    if (caa_unlikely(res != 0)) {
        res = -res;
        gf_io_log(res, LG_MSG_IO_SYSCALL, "pthread_mutex_unlock");
    }

    return res;
}

/* Destroy a condition variable. */
static int32_t
gf_io_sys_cond_destroy(pthread_cond_t *cond)
{
    int32_t res;

    res = pthread_cond_destroy(cond);
    if (caa_unlikely(res != 0)) {
        res = -res;
        gf_io_log(res, LG_MSG_IO_SYSCALL, "pthread_cond_destroy");
    }

    return res;
}

/* Initialize a condition variable using a monotonic clock for timeouts. */
static int32_t
gf_io_sys_cond_init(pthread_cond_t *cond)
{
    pthread_condattr_t attr;
    int32_t res, tmp;

    res = pthread_condattr_init(&attr);
    if (caa_unlikely(res != 0)) {
        res = -res;
        gf_io_log(res, LG_MSG_IO_SYSCALL, "pthread_condattr_init");

        return res;
    }

    res = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    if (caa_unlikely(res != 0)) {
        res = -res;
        gf_io_log(res, LG_MSG_IO_SYSCALL, "pthread_condattr_setclock");
    } else {
        res = pthread_cond_init(cond, &attr);
        if (caa_unlikely(res != 0)) {
            res = -res;
            gf_io_log(res, LG_MSG_IO_SYSCALL, "pthread_cond_init");
        }
    }

    tmp = pthread_condattr_destroy(&attr);
    if (caa_unlikely(tmp != 0)) {
        tmp = -tmp;
        gf_io_log(tmp, LG_MSG_IO_SYSCALL, "pthread_condattr_destroy");
        if (res >= 0) {
            res = tmp;
        }
    }

    return res;
}

/* Wait on a condition variable. */
static int32_t
gf_io_sys_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                    int32_t (*check)(void *), void *arg)
{
    int32_t res, tmp;

    res = gf_io_sys_mutex_lock(mutex);
    if (caa_likely(res >= 0)) {
        while ((res = check(arg)) == 0) {
            res = pthread_cond_wait(cond, mutex);
            if (caa_unlikely(res != 0)) {
                res = -res;
                gf_io_log(res, LG_MSG_IO_SYSCALL, "ptrhead_cond_wait");

                break;
            }
        }

        tmp = gf_io_sys_mutex_unlock(mutex);
        if (caa_unlikely(tmp < 0) && (res >= 0)) {
            res = tmp;
        }
    }

    return res;
}

/* Wait on a condition variable with a limited time. */
static int32_t
gf_io_sys_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                         struct timespec *to, int32_t (*check)(void *),
                         void *arg)
{
    struct timespec now;
    int32_t res, tmp;

    res = gf_io_sys_clock_gettime(&now);
    if (caa_unlikely(res < 0)) {
        return res;
    }

    now.tv_nsec += to->tv_nsec;
    if (now.tv_nsec >= 1000000000) {
        now.tv_nsec -= 1000000000;
        now.tv_sec++;
    }
    now.tv_sec += to->tv_sec;

    res = gf_io_sys_mutex_lock(mutex);
    if (caa_likely(res >= 0)) {
        while ((res = check(arg)) == 0) {
            tmp = pthread_cond_timedwait(cond, mutex, &now);
            if (caa_unlikely(tmp != 0)) {
                if (tmp != ETIMEDOUT) {
                    res = -tmp;
                    gf_io_log(res, LG_MSG_IO_SYSCALL, "ptrhead_cond_timedwait");
                }

                break;
            }
        }

        tmp = gf_io_sys_mutex_unlock(mutex);
        if (caa_unlikely(tmp < 0) && (res >= 0)) {
            res = tmp;
        }
    }

    return res;
}

/* Update a condition variable and signal if necessary. */
static int32_t
gf_io_sys_cond_update(pthread_cond_t *cond, pthread_mutex_t *mutex,
                      int32_t (*update)(void *), void *arg)
{
    int32_t res, tmp;

    res = gf_io_sys_mutex_lock(mutex);
    if (caa_likely(res >= 0)) {
        res = update(arg);
        if (res > 0) {
            tmp = pthread_cond_signal(cond);
            if (caa_unlikely(tmp != 0)) {
                res = -tmp;
                gf_io_log(res, LG_MSG_IO_SYSCALL, "pthread_cond_signal");
            }
        }

        tmp = gf_io_sys_mutex_unlock(mutex);
        if (caa_unlikely(tmp < 0) && (res >= 0)) {
            res = tmp;
        }
    }

    return res;
}

/* Join a thread and return the error code. If an error is found during
 * join itself, a negative error number is returned. If join succeeded
 * but the thread returned an error. The error is returned as a positive
 * error number. Only 0 indicates that both join and the thread finished
 * successfully. */
static int32_t
gf_io_sys_thread_join(pthread_t thread)
{
    void *ret;
    int32_t res;

    res = pthread_join(thread, &ret);
    if (caa_unlikely(res != 0)) {
        res = -res;
        gf_io_log(res, LG_MSG_IO_SYSCALL, "pthread_join");
    } else {
        res = -(int32_t)(intptr_t)ret;
    }

    return res;
}

/* Unmap a memory region. */
static int32_t
gf_io_sys_munmap(void *ptr, size_t size)
{
    int32_t res;

    res = munmap(ptr, size);
    if (caa_unlikely(res < 0)) {
        res = -errno;
        gf_io_log(res, LG_MSG_IO_SYSCALL, "munmap");
    }

    return res;
}

/* Map a memory region and prevent it from being cloned on forks. */
static int32_t
gf_io_sys_mmap(void **pptr, uint32_t fd, size_t size, off_t offset)
{
    void *ptr;
    int32_t res;

    ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
               fd, offset);
    if (caa_unlikely(ptr == MAP_FAILED)) {
        res = -errno;
        gf_io_log(res, LG_MSG_IO_SYSCALL, "mmap");

        return res;
    }

    res = madvise(ptr, size, MADV_DONTFORK);
    if (caa_unlikely(res < 0)) {
        res = -errno;
        gf_io_log(res, LG_MSG_IO_SYSCALL, "madvise");

        gf_io_sys_munmap(ptr, size);

        return res;
    }

    *pptr = ptr;

    return 0;
}

/* Low level system call for io_uring_setup(). */
static int32_t
gf_io_sys_uring_setup(uint32_t entries, struct io_uring_params *params)
{
    int32_t res;

    res = syscall(SYS_io_uring_setup, entries, params);
    if (caa_unlikely(res < 0)) {
        res = -errno;
        gf_io_log(res, LG_MSG_IO_SYSCALL, "io_uring_setup");
    }

    return res;
}

/* Low level system call for io_uring_enter(). */
static int32_t
gf_io_sys_uring_enter(uint32_t fd, uint32_t to_submit, uint32_t min_complete,
                      uint32_t flags)
{
    int32_t res;

    res = syscall(SYS_io_uring_enter, fd, to_submit, min_complete, flags, NULL,
                  0);
    if (caa_unlikely(res < 0)) {
        res = -errno;
        if (res != -EINTR) {
            gf_io_log(res, LG_MSG_IO_SYSCALL, "io_uring_enter");
        }
    }

    return res;
}

/* Low level system call for io_uring_register(). */
static int32_t
gf_io_sys_uring_register(uint32_t fd, uint32_t opcode, void *arg,
                         uint32_t nr_args)
{
    int32_t res;

    res = syscall(SYS_io_uring_register, fd, opcode, arg, nr_args);
    if (caa_unlikely(res < 0)) {
        res = -errno;
        gf_io_log(res, LG_MSG_IO_SYSCALL, "io_uring_register");
    }

    return res;
}

/* Destroy the CQ management structures. */
static int32_t
gf_io_cq_fini(void)
{
    return gf_io_sys_munmap(gf_io.cq.ring, gf_io.cq.size);
}

/* Initialize the CQ management structures. */
static int32_t
gf_io_cq_init(struct io_uring_params *params)
{
    void *ring;
    size_t size;
    int32_t res;

    size = params->cq_off.cqes +
           params->cq_entries * sizeof(struct io_uring_cqe);

    res = gf_io_sys_mmap(&ring, gf_io.fd, size, IORING_OFF_CQ_RING);
    if (caa_unlikely(res < 0)) {
        return res;
    }

    gf_io.cq.ring = ring;
    gf_io.cq.size = size;

    gf_io.cq.head = ring + params->cq_off.head;
    gf_io.cq.tail = ring + params->cq_off.tail;
    gf_io.cq.ring_mask = *(uint32_t *)(ring + params->cq_off.ring_mask);
    gf_io.cq.ring_entries = *(uint32_t *)(ring + params->cq_off.ring_entries);
    gf_io.cq.overflow = ring + params->cq_off.overflow;
    gf_io.cq.cqes = ring + params->cq_off.cqes;
    gf_io.cq.flags = ring + params->cq_off.flags;

    return 0;
}

/* Wait for events in the CQ. It restarts the wait if it was interrupted
 * by a signal. */
static int32_t
gf_io_cq_wait(void)
{
    int32_t res;

    do {
        /* This will block until there's at least one CQE available. */
        res = gf_io_sys_uring_enter(gf_io.fd, 0, 1, IORING_ENTER_GETEVENTS);
        if (caa_likely(res >= 0)) {
            return res;
        }
    } while (res == -EINTR);

    gf_io_log(res, LG_MSG_IO_GETEVENTS_FAILED);

    return res;
}

/* Try to get a CQE from the CQ. If 'block' is false and there are no
 * entries, 0 is returned. If there are entries, one is copied to 'cqe'
 * and 1 is returned. Otherwise it waits until an entry is found. If too
 * many errors happen waiting for a CQE, the latest error is returned. */
static int32_t
gf_io_cqe_get(struct io_uring_cqe *cqe, bool block)
{
    uint32_t retries, current, head;
    int32_t res;

    retries = 0;
    do {
        current = CMM_LOAD_SHARED(*gf_io.cq.head);

        /* Check that the queue is not empty and try to get a CQE. */
        while (caa_likely(CMM_LOAD_SHARED(*gf_io.cq.tail) != current)) {
            /* We need to atomically update the 'head' of CQ to avoid
             * that other threads could process the same entry. However,
             * as soon as the 'head' is updated, the kernel could overwrite
             * the contents of the current CQE. To avoid this problem, the
             * CQE is temptatively copied before updating the 'head'. If
             * the update succeeds, 'cqe' contents will be good. Otherwise
             * it's discarded and a new CQE is read the next attempt. */
            *cqe = gf_io.cq.cqes[current & gf_io.cq.ring_mask];

            head = uatomic_cmpxchg(gf_io.cq.head, current, current + 1);
            if (caa_likely(head == current)) {
                return 1;
            }

            current = head;
        }

        if (!block) {
            return 0;
        }

        res = gf_io_cq_wait();
    } while (caa_likely(res >= 0) || (++retries < GF_IO_MAX_RETRIES));

    gf_io_log(res, LG_MSG_IO_NO_CQES);

    return res;
}

/* Destroy the SQ management structures. */
static int32_t
gf_io_sq_fini(void)
{
    int32_t res, tmp;

    res = gf_io_sys_munmap(gf_io.sq.sqes, gf_io.sq.sqes_size);
    tmp = gf_io_sys_munmap(gf_io.sq.ring, gf_io.sq.size);
    if (caa_likely(res >= 0)) {
        res = tmp;
    }

    return res;
}

/* Initialize the SQ management structures. */
static int32_t
gf_io_sq_init(struct io_uring_params *params)
{
    void *ring, *sqes;
    size_t ring_size, sqes_size;
    uint32_t i;
    int32_t res;

    ring_size = params->sq_off.array + params->sq_entries * sizeof(uint32_t);
    sqes_size = params->sq_entries * sizeof(struct io_uring_sqe);

    res = gf_io_sys_mmap(&ring, gf_io.fd, ring_size, IORING_OFF_SQ_RING);
    if (caa_unlikely(res < 0)) {
        return res;
    }

    res = gf_io_sys_mmap(&sqes, gf_io.fd, sqes_size, IORING_OFF_SQES);
    if (caa_unlikely(res < 0)) {
        gf_io_sys_munmap(ring, ring_size);

        return res;
    }

    gf_io.sq.ring = ring;
    gf_io.sq.size = ring_size;

    gf_io.sq.head = ring + params->sq_off.head;
    gf_io.sq.tail = ring + params->sq_off.tail;
    gf_io.sq.ring_mask = *(uint32_t *)(ring + params->sq_off.ring_mask);
    gf_io.sq.ring_entries = *(uint32_t *)(ring + params->sq_off.ring_entries);
    gf_io.sq.flags = ring + params->sq_off.flags;
    gf_io.sq.dropped = ring + params->sq_off.dropped;
    gf_io.sq.array = ring + params->sq_off.array;

    gf_io.sq.sqes = sqes;
    gf_io.sq.sqes_size = sqes_size;

    /* Preinitialize the SQ array. The mapping with SQEs is always 1:1. */
    for (i = 0; i < params->sq_entries; i++) {
        gf_io.sq.array[i] = i;
    }

    /* Clear all SQEs so that there's no need to initialize the paddings
     * for each request. */
    memset(sqes, 0, sqes_size);

    gf_io.sq.queue = NULL;

    return 0;
}

/* Wake up the kernel's SQPOLL thread if it's sleeping. Optionally, wait
 * until the SQ has some available entries when 'wait' is true. */
static int32_t
gf_io_sq_wake(bool wait)
{
    uint32_t flags;

    flags = CMM_LOAD_SHARED(*gf_io.sq.flags);
    if ((flags & IORING_SQ_NEED_WAKEUP) != 0) {
        if (wait) {
            flags = IORING_ENTER_SQ_WAKEUP | IORING_ENTER_SQ_WAIT;
        } else {
            flags = IORING_ENTER_SQ_WAKEUP;
        }
    } else if (wait) {
        flags = IORING_ENTER_SQ_WAIT;
    } else {
        return 0;
    }

    /* We pass 0 SQEs because we are using IO_URING_SQPOLL, so we are not
     * really adding SQEs here, we only wake the kernel's SQPOLL thread
     * if necessary. */
    return gf_io_sys_uring_enter(gf_io.fd, 0, 0, flags);
}

/* Add a request to a free SQE. If there are not free SQEs, it blocks until
 * one is available. If too many errors happen, the last error is returned. */
static int32_t
gf_io_sqe_add(gf_io_request_t *req)
{
    uint32_t head, retries;
    uint32_t tail;
    int32_t res;

    retries = 0;
    tail = *gf_io.sq.tail;
    do {
        head = CMM_LOAD_SHARED(*gf_io.sq.head);
        /* Check that the SQ is not full before filling the SQE. */
        if (caa_likely((tail - head) < gf_io.sq.ring_entries)) {
            req->prepare(req, &gf_io.sq.sqes[tail & gf_io.sq.ring_mask]);

            /* Make sure that SQE contents are visible to the kernel
             * before updating the tail. */
            cmm_smp_wmb();
            CMM_STORE_SHARED(*gf_io.sq.tail, tail + 1);

            /* We have already added the request to the SQ, so the kernel
             * may have started processing it. This could be true even if
             * the call to gf_io_sq_wake() fails. For this reason we cannot
             * return an error here (which could cause the callback of the
             * request to be processed again by the current thread). If
             * that situation happens, the best we can do is to write a
             * critical message in the log. */
            res = gf_io_sq_wake(false);
            if (caa_unlikely(res < 0)) {
                gf_io_log(res, LG_MSG_IO_SQE_PENDING);
            }

            return 0;
        }

        /* There are no SQEs available. Try wake the kernel's SQPOLL
         * thread if necessary and wait until there's some room in the
         * SQ. */
        res = gf_io_sq_wake(true);
    } while (caa_likely(res >= 0) || (++retries < GF_IO_MAX_RETRIES));

    gf_io_log(res, LG_MSG_IO_NO_SQES);

    return res;
}

/* Actively wait for some time for the next item to become different than
 * NULL. If this doesn't happen in GF_IO_BUSY_WAIT_ATTEMPTS, it returns
 * NULL. */
static gf_io_list_item_t *
gf_io_list_wait_next(gf_io_list_item_t *item)
{
    gf_io_list_item_t *next;
    uint32_t attempt;

    attempt = 0;
    while (caa_unlikely((next = CMM_LOAD_SHARED(item->next)) == NULL)) {
        if (caa_unlikely(++attempt >= GF_IO_BUSY_WAIT_ATTEMPTS)) {
            return NULL;
        }

        caa_cpu_relax();
    }

    return next;
}

/* Return whether the current item is ready or not. */
static bool
gf_io_list_is_ready(gf_io_list_item_t *item)
{
    gf_io_list_item_t *next;

    next = CMM_LOAD_SHARED(item->next);

    return (next == GF_IO_REQUEST_READY);
}

/* Actively wait for some time for the current item to become ready. If
 * this doesn't happen in GF_IO_BUSY_WAIT_ATTEMPTS, it returns false. */
static bool
gf_io_list_wait_ready(gf_io_list_item_t *item)
{
    uint32_t attempt;

    attempt = 0;
    while (caa_unlikely(!gf_io_list_is_ready(item))) {
        if (caa_unlikely(++attempt >= GF_IO_BUSY_WAIT_ATTEMPTS)) {
            return false;
        }

        caa_cpu_relax();
    }

    return true;
}

/* Disable the worker and store the error if necessary. */
static void
gf_io_worker_disable(gf_io_worker_t *worker, int32_t res)
{
    if (worker != NULL) {
        worker->enabled = false;
        if (worker->res == 0) {
            worker->res = res;
        }
    }
}

/* Execute a callback. If the callback returns something != 0, the current
 * worker is disabled. This is intended only for stop requests. */
static bool
gf_io_cbk(gf_io_worker_t *worker, gf_io_request_t *req)
{
    int32_t res;

    req->worker = worker;

    res = req->cbk(req);
    if (caa_unlikely(res != 0)) {
        gf_io_worker_disable(worker, res);

        return false;
    }

    return true;
}

/* Execute the callbacks from all ready requests in a list and remove them
 * from the list. It returns false if a callback has just disabled the
 * worker. */
static bool
gf_io_process_ready(gf_io_worker_t *worker, gf_io_request_t **pnext)
{
    gf_io_request_t *req;

    /* Try to process all pending requests. */
    while (caa_unlikely((req = *pnext) != NULL)) {
        if (caa_likely(gf_io_list_is_ready(&req->list))) {
            *pnext = req->next;

            if (caa_unlikely(!gf_io_cbk(worker, req))) {
                return false;
            }
        } else {
            /* The request cannot be processed yet. We have already waited
             * for some time in gf_io_list_wait_ready() before adding it to
             * the list. This means that the thread that has put the request
             * into the SQE is taking a long time to finish processing it
             * after enqueuing it. Most probably this means that the thread
             * has been preempted.
             *
             * Instead of waiting for a long time until the other thread
             * resumes and finishes processing the request, we continue
             * processing other requests in the mean time. */
            pnext = &req->next;
        }
    }

    return true;
}

/* Execute the callbacks from all ready requests in a list and remove them
 * from the list. If the worker becomes disabled, it keeps processing the
 * list until it's empty. This prevents new completions to be added to the
 * list while the worker is disabled. */
static bool
gf_io_process_ready_safe(gf_io_worker_t *worker, gf_io_request_t **pnext)
{
    if (caa_unlikely(!gf_io_process_ready(worker, pnext))) {
        while (*pnext != NULL) {
            gf_io_process_ready(worker, pnext);
            caa_cpu_relax();
        }

        return false;
    }

    return true;
}

/* Processes one or more CQEs. */
static bool
gf_io_pull(gf_io_worker_t *worker, bool block)
{
    struct io_uring_cqe cqe;
    gf_io_request_t *first, *req, **pnext;
    int32_t res;
    bool enabled;

    req = NULL;
    first = NULL;
    pnext = &first;
    do {
        res = gf_io_cqe_get(&cqe, block);
        if (caa_unlikely(res < 0)) {
            /* An error can only be returned when we do a blocking
             * gf_io_cqe_get(). This can only happen for the first request
             * because we set 'block' to false before any retry. So, if
             * the first one fails, we directly return the error because
             * we are sure that the local list will be empty. */
            gf_io_worker_disable(worker, res);

            return false;
        }

        if (caa_likely(res > 0)) {
            /* We have got a CQE. We add it to the list to be processed. */
            req = (gf_io_request_t *)cqe.user_data;
            req->res = cqe.res;
            req->next = NULL;
            *pnext = req;
            pnext = &req->next;

            /* Wait a little bit just in case the request is not yet ready. */
            gf_io_list_wait_ready(&req->list);
        }

        enabled = gf_io_process_ready_safe(worker, &first);

        block = false;

        /* If we have been unable to process all pending requests, we try
         * to get another request while we wait. */
    } while (first != NULL);

    /* If we have processed some requests, they could have added new
     * requests to the current worker. Submit them. */
    gf_io_worker_flush(worker, false);

    return enabled;
}

/* Wait for a new pending request indefinitely. If there are no pending
 * requests, it helps processing CQEs if the worker is enabled. */
static gf_io_list_item_t *
gf_io_push_wait(gf_io_worker_t *worker, gf_io_list_item_t *item)
{
    gf_io_list_item_t *next;

    while (caa_unlikely((next = gf_io_list_wait_next(item)) == NULL)) {
        if (caa_likely(worker->enabled)) {
            gf_io_pull(worker, false);
        }
    }

    return next;
}

/* Wait for a new pending request for a limited amount of time. If there
 * are no pending requests, it helps processing CQEs if the worker is
 * enabled. Otherwise it returns NULL immediately. */
static gf_io_list_item_t *
gf_io_push_wait_limited(gf_io_worker_t *worker, gf_io_list_item_t *item)
{
    struct timespec now;
    gf_io_list_item_t *next;
    uint64_t start, delta;

    next = gf_io_list_wait_next(item);
    if (caa_unlikely(next == NULL) && caa_likely(worker->enabled)) {
        if (caa_unlikely(gf_io_sys_clock_gettime(&now) < 0)) {
            return NULL;
        }
        start = gf_io_time_ns(&now);

        while ((next = gf_io_list_wait_next(item)) == NULL) {
            if (caa_unlikely(!gf_io_pull(worker, false))) {
                return NULL;
            }

            if (caa_unlikely(gf_io_sys_clock_gettime(&now) < 0)) {
                return NULL;
            }
            delta = gf_io_time_ns(&now) - start;
            if (delta >= GF_IO_POLL_TIMEOUT_MS * 1000000UL) {
                break;
            }
        }
    }

    return next;
}

static void
gf_io_push_ready(gf_io_list_item_t *item)
{
    CMM_STORE_SHARED(item->next, GF_IO_REQUEST_READY);
}

/* Get a new pending request to process. If there are no pending requests
 * available for some amount of time, the pending queue is resetted so
 * that other threads could manage it when new requests arrive. */
static gf_io_list_item_t *
gf_io_push_next(gf_io_worker_t *worker, gf_io_list_item_t *item)
{
    gf_io_list_item_t *next, *tmp;

    /* Actively wait for little bit to see if more requests are coming
     * (or the next one is still being queued) before releasing the
     * ownership of the pending requests queue. */
    next = gf_io_push_wait_limited(worker, item);
    if (caa_unlikely(next == NULL)) {
        /* After some time there are no more requests. The most likely
         * cause is that the queue is empty. We try to reset it. */
        tmp = uatomic_cmpxchg(&gf_io.sq.queue, item, NULL);
        if (caa_unlikely(tmp != item)) {
            /* More requests detected. We need to wait until the request
             * is fully inserted into the queue. */
            next = gf_io_push_wait(worker, item);
        }
    }

    /* Mark the old item as completely processed so that other threads
     * can process the completion results. */
    gf_io_push_ready(item);

    return next;
}

/* Submit one request to the kernel. */
static void
gf_io_push_one(gf_io_worker_t *worker, gf_io_request_t *req)
{
    int32_t res;

    res = gf_io_sqe_add(req);
    if (caa_unlikely(res < 0)) {
        /* In the unlikely case that we have been unable to obtain an SQE
         * for this request, we call the completion callback right now
         * passing the error code. */
        req->res = res;

        gf_io_cbk(worker, req);
    }
}

/* Send requests to the kernel. */
void
gf_io_push(gf_io_worker_t *worker, gf_io_list_item_t *item)
{
    do {
        gf_io_push_one(worker, gf_io_object(item, gf_io_request_t, list));

        /* Keep processing entries until the queue is empty. */
    } while ((item = gf_io_push_next(worker, item)) != NULL);
}

static int32_t
gf_io_push_delayed(gf_io_request_t *req)
{
    if (caa_unlikely(req->worker == NULL)) {
        /* This can only happen if there has been an error sending the
         * delayed request from a non worker thread. In that case, we
         * try to immediately process the pending requests. */
        gf_io_push(NULL, req->data);
    } else {
        /* Otherwise we attach the list of pending requests to the worker
         * so that they are executed after processing all completions.
         * This prevents potentially long delays while processing
         * completions. */
        req->worker->delayed = req->data;
    }

    return 0;
}

/* Send requests to the kernel in the background. */
void
gf_io_delayed(gf_io_worker_t *worker, gf_io_list_item_t *item)
{
    gf_io_request_t *req;

    req = &gf_io.sq.delay;

    req->res = 0;
    req->list.next = NULL;
    gf_io_async(req, gf_io_push_delayed, item);
    gf_io_push_one(worker, req);
    gf_io_push_ready(&req->list);
}

/* Terminate a worker and propagate the request if necessary. */
static int32_t
gf_io_worker_cleanup(gf_io_request_t *req)
{
    gf_io_worker_t *worker;
    int32_t res, tmp;
    bool stop;

    res = req->res;
    if (caa_likely(res >= 0)) {
        worker = req->data;

        stop = true;
        if (worker != NULL) {
            stop = worker->stop;
            res = worker->res;

            tmp = gf_io_sys_thread_join(worker->thread);
            if (caa_unlikely(tmp != 0)) {
                if (tmp < 0) {
                    gf_io_log(tmp, LG_MSG_IO_JOIN_FAILED, worker);
                } else {
                    gf_io_log(-tmp, LG_MSG_IO_WORKER_RESULT, worker);
                }
                if (res >= 0) {
                    res = tmp;
                }
            }

            if ((res != 0) && (gf_io.res == 0)) {
                gf_io.res = res;
            }
        }

        if (stop) {
            worker = req->worker;
            if (worker != NULL) {
                gf_io_worker_disable(worker, res);

                if (uatomic_sub_return(&gf_io.num_workers, 1) == 0) {
                    gf_io_done(req);
                }

                gf_io_async(req, gf_io_worker_cleanup, worker);
                gf_io_request_submit(worker, req, true);

                return 1;
            }
        }
    } else {
        gf_io_log(res, LG_MSG_IO_STOP_LOST);
    }

    return 0;
}

/* Main worker thread. */
static void *
gf_io_worker_thread(void *arg)
{
    gf_io_worker_t *self;
    gf_io_list_item_t *delayed;

    self = &gf_io_worker;

    gf_io_debug(0, "I/O Ring: Worker %p started.", self);

    self->thread = pthread_self();
    self->queue.last = &self->queue.first;
    self->delayed = NULL;
    self->stop = false;
    self->enabled = true;

    do {
        gf_io_pull(self, true);

        delayed = self->delayed;
        if (caa_unlikely(delayed != NULL)) {
            self->delayed = NULL;

            gf_io_push(self, delayed);
        }
    } while (caa_likely(self->enabled));

    gf_io_log(self->res, LG_MSG_IO_WORKER_STOPPED, self);

    return (void *)(intptr_t)self->res;
}

/* Build a string containing the names of bits present in a bitmap. The
 * caller must ensure that the buffer size will be enough in all cases. */
static void
gf_io_name_list(char *buffer, gf_io_bitname_t *names, uint64_t bitmap)
{
    char *ptr;
    gf_io_bitname_t *bn;

    ptr = buffer;
    for (bn = names; bn->name != NULL; bn++) {
        if ((bitmap & bn->bit) != 0) {
            bitmap ^= bn->bit;
            ptr += sprintf(ptr, "%s(%" PRIx64 ") ", bn->name, bn->bit);
        }
    }
    if (bitmap != 0) {
        sprintf(ptr, "?(%" PRIx64 ")", bitmap);
    } else if (ptr == buffer) {
        strcpy(buffer, "<none>");
    } else {
        ptr[-1] = 0;
    }
}

/* Logs the configuration and features of an io_uring instance. */
static void
gf_io_dump_params(struct io_uring_params *params)
{
    static gf_io_bitname_t flag_names[] = {
        GF_IO_BITNAME(IORING_SETUP, IOPOLL),
        GF_IO_BITNAME(IORING_SETUP, SQPOLL),
        GF_IO_BITNAME(IORING_SETUP, SQ_AFF),
        GF_IO_BITNAME(IORING_SETUP, CQSIZE),
        GF_IO_BITNAME(IORING_SETUP, CLAMP),
        GF_IO_BITNAME(IORING_SETUP, ATTACH_WQ),
        {}};
    static gf_io_bitname_t feature_names[] = {
        GF_IO_BITNAME(IORING_FEAT, SINGLE_MMAP),
        GF_IO_BITNAME(IORING_FEAT, NODROP),
        GF_IO_BITNAME(IORING_FEAT, SUBMIT_STABLE),
        GF_IO_BITNAME(IORING_FEAT, RW_CUR_POS),
        GF_IO_BITNAME(IORING_FEAT, CUR_PERSONALITY),
        GF_IO_BITNAME(IORING_FEAT, FAST_POLL),
        GF_IO_BITNAME(IORING_FEAT, POLL_32BITS),
        {}};

    char names[128];

    gf_io_debug(0, "I/O Ring: SQEs=%u, CQEs=%u, CPU=%u, Idle=%u",
                params->sq_entries, params->cq_entries, params->sq_thread_cpu,
                params->sq_thread_idle);

    gf_io_name_list(names, flag_names, params->flags);
    gf_io_debug(0, "I/O Ring: Flags: %s", names);

    gf_io_name_list(names, feature_names, params->features);
    gf_io_debug(0, "I/O Ring: Features: %s", names);
}

/* Logs the list of supported operations. */
static void
gf_io_dump_ops(struct io_uring_probe *probe)
{
    static const char *op_names[] = {
        [IORING_OP_NOP] = "NOP",
        [IORING_OP_READV] = "READV",
        [IORING_OP_WRITEV] = "WRITEV",
        [IORING_OP_FSYNC] = "FSYNC",
        [IORING_OP_READ_FIXED] = "READ_FIXED",
        [IORING_OP_WRITE_FIXED] = "WRITE_FIXED",
        [IORING_OP_POLL_ADD] = "POLL_ADD",
        [IORING_OP_POLL_REMOVE] = "POLL_REMOVE",
        [IORING_OP_SYNC_FILE_RANGE] = "SYNC_FILE_RANGE",
        [IORING_OP_SENDMSG] = "SENDMSG",
        [IORING_OP_RECVMSG] = "RECVMSG",
        [IORING_OP_TIMEOUT] = "TIMEOUT",
        [IORING_OP_TIMEOUT_REMOVE] = "TIMEOUT_REMOVE",
        [IORING_OP_ACCEPT] = "ACCEPT",
        [IORING_OP_ASYNC_CANCEL] = "ASYNC_CANCEL",
        [IORING_OP_LINK_TIMEOUT] = "LINK_TIMEOUT",
        [IORING_OP_CONNECT] = "CONNECT",
        [IORING_OP_FALLOCATE] = "FALLOCATE",
        [IORING_OP_OPENAT] = "OPENAT",
        [IORING_OP_CLOSE] = "CLOSE",
        [IORING_OP_FILES_UPDATE] = "FILES_UPDATE",
        [IORING_OP_STATX] = "STATX",
        [IORING_OP_READ] = "READ",
        [IORING_OP_WRITE] = "WRITE",
        [IORING_OP_FADVISE] = "FADVISE",
        [IORING_OP_MADVISE] = "MADVISE",
        [IORING_OP_SEND] = "SEND",
        [IORING_OP_RECV] = "RECV",
        [IORING_OP_OPENAT2] = "OPENAT2",
        [IORING_OP_EPOLL_CTL] = "EPOLL_CTL",
        [IORING_OP_SPLICE] = "SPLICE",
        [IORING_OP_PROVIDE_BUFFERS] = "PROVIDE_BUFFERS",
        [IORING_OP_REMOVE_BUFFERS] = "REMOVE_BUFFERS",
        [IORING_OP_TEE] = "TEE"};

    char names[4096];
    char *ptr;
    const char *name;
    uint32_t i, op;

    gf_io_debug(0, "I/O Ring: Max opcode = %u", probe->last_op);

    ptr = names;
    for (i = 0; i < probe->ops_len; i++) {
        if ((probe->ops[i].flags & IO_URING_OP_SUPPORTED) != 0) {
            op = probe->ops[i].op;
            name = "?";
            if ((op < CAA_ARRAY_SIZE(op_names)) && (op_names[op] != NULL)) {
                name = op_names[op];
            }
            ptr += sprintf(ptr, "%s(%u) ", name, op);
        }
    }
    if (ptr == names) {
        strcpy(names, "<none>");
    } else {
        ptr[-1] = 0;
    }

    gf_io_debug(0, "I/O Ring: Ops: %s", names);
}

/* Terminate an io_uring instance. */
static int32_t
gf_io_uring_fini(void)
{
    int32_t res, tmp;

    res = gf_io_sys_cond_destroy(&gf_io.cond);
    tmp = gf_io_sys_mutex_destroy(&gf_io.mutex);
    if (caa_likely(res >= 0)) {
        res = tmp;
    }
    tmp = gf_io_cq_fini();
    if (caa_likely(res >= 0)) {
        res = tmp;
    }
    tmp = gf_io_sq_fini();
    if (caa_likely(res >= 0)) {
        res = tmp;
    }
    tmp = gf_io_sys_close(gf_io.fd);
    if (caa_likely(res >= 0)) {
        res = tmp;
    }

    return res;
}

/* Initialize an io_uring instance. */
static int32_t
gf_io_uring_init(void)
{
    struct io_uring_params params;
    struct io_uring_probe *probe;
    uint32_t count;
    int32_t fd, res;

    memset(&params, 0, sizeof(params));
    params.flags = IORING_SETUP_SQPOLL | IORING_SETUP_CLAMP;
    params.sq_thread_idle = GF_IO_POLL_TIMEOUT_MS;

    fd = gf_io_sys_uring_setup(GF_IO_QUEUE_SIZE, &params);
    if (caa_unlikely(fd < 0)) {
        return fd;
    }
    gf_io_dump_params(&params);

    if (params.sq_entries < GF_IO_QUEUE_MIN) {
        res = -ENOBUFS;
        gf_io_log(res, LG_MSG_IO_RING_TOO_SMALL, params.sq_entries);
        goto failed_close;
    }

    if ((params.features & GF_IO_REQUIRED_FEATS) != GF_IO_REQUIRED_FEATS) {
        res = -ENOTSUP;
        gf_io_log(res, LG_MSG_IO_NOT_SUPPORTED);
        goto failed_close;
    }
    gf_io.fd = fd;

    res = gf_io_sq_init(&params);
    if (caa_unlikely(res < 0)) {
        goto failed_close;
    }

    res = gf_io_cq_init(&params);
    if (caa_unlikely(res < 0)) {
        goto failed_sq;
    }

    probe = (struct io_uring_probe *)gf_io.sq.sqes;
    /* The opcode is an 8 bit integer, so the maximum number of entries will
     * be 256. We have ensured that there are at least GF_IO_URING_QUEUE_MIN
     * SQEs, so the size of the SQE's memory area should be enough to hold
     * the io_uring_probe structure with 256 entries. This way we avoid an
     * unnecessary memory allocation. */
    count = 256;

    res = gf_io_sys_uring_register(fd, IORING_REGISTER_PROBE, probe, count);
    if (caa_unlikely(res < 0)) {
        goto failed_cq;
    }
    gf_io_dump_ops(probe);

    /* TODO: we may check if the system supports the required subset of
     *       operations. */

    res = gf_io_sys_mutex_init(&gf_io.mutex);
    if (caa_unlikely(res < 0)) {
        goto failed_cq;
    }
    res = gf_io_sys_cond_init(&gf_io.cond);
    if (caa_unlikely(res < 0)) {
        goto failed_mutex;
    }

    return 0;

failed_mutex:
    gf_io_sys_mutex_destroy(&gf_io.mutex);
failed_cq:
    gf_io_cq_fini();
failed_sq:
    gf_io_sq_fini();
failed_close:
    close(fd);

    gf_io_log(res, LG_MSG_IO_FALLBACK);

    return res;
}

/* Helper function to mark a call as completed. */
static int32_t
gf_io_call_update(void *arg)
{
    gf_io_request_t *req = (gf_io_request_t *)arg;

    req->next = NULL;

    return 1;
}

/* Helper function to identify when a call has completed. */
static int32_t
gf_io_call_wait(void *arg)
{
    gf_io_request_t *req = (gf_io_request_t *)arg;

    return (req->next == NULL) ? 1 : 0;
}

/* Mark a call as completed. */
void
gf_io_done(gf_io_request_t *req)
{
    int32_t res;

    res = gf_io_sys_cond_update(&gf_io.cond, &gf_io.mutex, gf_io_call_update,
                                req);
    if (caa_unlikely(res < 0)) {
        gf_io_log(res, LG_MSG_IO_UNSTABLE);
    }
}

#endif /* HAVE_IO_URING */

/* Process an asynchronous callback in the background and wait for a call
 * to gf_io_done() or until a timeout expires. The return value is a negative
 * error code if the wait fails. Otherwise it's the value passed to
 * gf_io_done() but in positive. If everything succeeds, it returns 0. */
static int32_t
gf_io_call(gf_io_callback_t cbk, void *data, uint32_t to_secs)
{
    gf_io_request_t req;
    int32_t res;

    gf_io_async(&req, cbk, data);
    gf_io_request_submit(NULL, &req, true);

#ifdef HAVE_IO_URING
    struct timespec to = {.tv_sec = to_secs, .tv_nsec = 0};

    res = gf_io_sys_cond_timedwait(&gf_io.cond, &gf_io.mutex, &to,
                                   gf_io_call_wait, &req);
    if (caa_likely(res >= 0)) {
        res = req.res;
        if (res < 0) {
            res = -res;
        }
    }
#else  /* ! HAVE_IO_URING */
    res = req.res;
    if (res < 0) {
        res = -res;
    }
#endif /* HAVE_IO_URING */

    return res;
}

#ifdef HAVE_IO_URING

/* Stop the workers. */
static int32_t
gf_io_workers_stop(void)
{
    return gf_io_call(gf_io_worker_cleanup, NULL, 5);
}

/* Start the workers. */
static int32_t
gf_io_workers_start(uint32_t workers)
{
    pthread_t thread;
    uint32_t i;
    int32_t res;

    gf_io.num_workers = workers + 1;

    for (i = 0; i < workers; i++) {
        res = gf_thread_create(&thread, NULL, gf_io_worker_thread, NULL,
                               "worker/%03u", i);
        if (caa_unlikely(res < 0)) {
            gf_io_log(res, LG_MSG_IO_THREAD_FAILED);

            gf_io_workers_stop();

            break;
        }
    }

    return res;
}

/* Helper function to initiate a shutdown. */
static int32_t
gf_io_shutdown_update(void *arg)
{
    gf_io.shutdown = true;

    return 1;
}

/* Helper function to identify when a shutdown has been initiated. */
static int32_t
gf_io_shutdown_wait(void *arg)
{
    return gf_io.shutdown ? 1 : 0;
}

/* Trigger a shutdown. */
int32_t
gf_io_shutdown(void)
{
    return gf_io_sys_cond_update(&gf_io.cond, &gf_io.mutex,
                                 gf_io_shutdown_update, NULL);
}

#endif /* HAVE_IO_URING */

/* Wait until shutdown is initiated and stop all workers. */
static int32_t
gf_io_main(uint32_t workers)
{
    int32_t res;

    switch (gf_io.mode) {
        case GF_IO_MODE_LEGACY:
            res = gf_event_dispatch(global_ctx->event_pool);
            break;
#ifdef HAVE_IO_URING
        case GF_IO_MODE_IO_URING:
            /* TODO: This is not correct because this way we can't control
             *       shutdown, but until the events module is migrated to
             *       io_uring there's nothing we can do. */
            res = gf_event_dispatch(global_ctx->event_pool);

            int32_t tmp = gf_io_sys_cond_wait(&gf_io.cond, &gf_io.mutex,
                                              gf_io_shutdown_wait, NULL);
            if (caa_likely(res >= 0)) {
                res = tmp;
            }

            tmp = gf_io_workers_stop();
            if (caa_likely(res >= 0)) {
                res = tmp;
            }
            break;
#endif /* HAVE_IO_URING */
    }

    return res;
}

/* Main entry function. */
int32_t
gf_io_run(uint32_t workers, gf_io_handlers_t *handlers, void *data)
{
    int32_t res, tmp;

    gf_io.mode = GF_IO_MODE_LEGACY;

#ifdef HAVE_IO_URING
    res = gf_io_uring_init();
    if (caa_likely(res >= 0)) {
        if (workers == 0) {
            workers = get_nprocs();
        }
        if (workers < GF_IO_WORKERS_MIN) {
            workers = GF_IO_WORKERS_MIN;
        }
        if (workers > GF_IO_WORKERS_MAX) {
            workers = GF_IO_WORKERS_MAX;
        }

        res = gf_io_workers_start(workers);
        if (caa_unlikely(res < 0)) {
            gf_io_uring_fini();
        } else {
            gf_io.mode = GF_IO_MODE_IO_URING;
        }
    }
#endif /* HAVE_IO_URING */

    /* 5 seconds should be much more than enough to execute a function. */
    res = gf_io_call(handlers->start, data, 5);
    if (caa_likely(res == 0)) {
        res = gf_io_main(workers);

        /* 5 seconds should be much more than enough to execute a function. */
        tmp = gf_io_call(handlers->terminate, data, 5);
        if (caa_likely(res >= 0)) {
            res = tmp;
        }
    }

#ifdef HAVE_IO_URING
    if (gf_io.mode == GF_IO_MODE_IO_URING) {
        tmp = gf_io_uring_fini();
        if (caa_likely(res == 0)) {
            res = tmp;
        }
    }
#endif /* HAVE_IO_URING */

    return res;
}

#ifdef HAVE_IO_URING

void
gf_io_prepare_async(gf_io_request_t *req, struct io_uring_sqe *sqe)
{
    sqe->opcode = IORING_OP_NOP;
    sqe->flags = 0;
    sqe->ioprio = 0;
    sqe->fd = -1;
    sqe->off = 0;
    sqe->addr = 0;
    sqe->len = 0;
    sqe->rw_flags = 0;
    sqe->user_data = (uintptr_t)req;
}

#endif /* HAVE_IO_URING */
