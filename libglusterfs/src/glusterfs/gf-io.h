/*
  Copyright (c) 2021 Red Hat, Inc. <https://www.redhat.com>
  This file is part of GlusterFS.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

#ifndef __GF_IO_H__
#define __GF_IO_H__

#include <inttypes.h>

#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

#include <urcu/uatomic.h>

#ifdef HAVE_IO_URING

#include <sys/mount.h>
#include <linux/io_uring.h>

#endif /* HAVE_IO_URING */

#define gf_io_object(_ptr, _type, _field) caa_container_of(_ptr, _type, _field)

#define GF_IO_WORKERS_MIN 2
#define GF_IO_WORKERS_MAX 16

#define GF_IO_QUEUE_SIZE 65536
#define GF_IO_QUEUE_MIN 4096
#define GF_IO_POLL_TIMEOUT_MS 1000
#define GF_IO_BUSY_WAIT_ATTEMPTS 20
#define GF_IO_MAX_RETRIES 10

enum _gf_io_mode;
typedef enum _gf_io_mode gf_io_mode_t;

struct _gf_io_list_item;
typedef struct _gf_io_list_item gf_io_list_item_t;

struct _gf_io_list;
typedef struct _gf_io_list gf_io_list_t;

struct _gf_io_request;
typedef struct _gf_io_request gf_io_request_t;

struct _gf_io_worker;
typedef struct _gf_io_worker gf_io_worker_t;

struct _gf_io_handlers;
typedef struct _gf_io_handlers gf_io_handlers_t;

#ifdef HAVE_IO_URING
struct _gf_io_sq;
typedef struct _gf_io_sq gf_io_sq_t;

struct _gf_io_cq;
typedef struct _gf_io_cq gf_io_cq_t;
#endif /* HAVE_IO_URING */

struct _gf_io;
typedef struct _gf_io gf_io_t;

enum _gf_io_mode {
    GF_IO_MODE_LEGACY,
#ifdef HAVE_IO_URING
    GF_IO_MODE_IO_URING,
#endif /* HAVE_IO_URING */
};

struct _gf_io_list_item {
    gf_io_list_item_t *next;
};

struct _gf_io_list {
    gf_io_list_item_t first;
    gf_io_list_item_t *last;
};

#ifdef HAVE_IO_URING
typedef void (*gf_io_prepare_t)(gf_io_request_t *req, struct io_uring_sqe *sqe);
#endif /* HAVE_IO_URING */

typedef int32_t (*gf_io_callback_t)(gf_io_request_t *req);

struct _gf_io_request {
    gf_io_list_item_t list;
    gf_io_worker_t *worker;
    gf_io_callback_t cbk;
    void *data;
    union {
#ifdef HAVE_IO_URING
        gf_io_prepare_t prepare; /* Used before submitting the SQE. */
#endif                           /* HAVE_IO_URING */
        gf_io_request_t *next; /* Used during processing of the CQE. */
    };

    union {
        struct {
        } async;
    };

    int32_t res;
};

struct _gf_io_worker {
    gf_io_list_t queue;
#ifdef HAVE_IO_URING
    gf_io_list_item_t *delayed;
    pthread_t thread;
#endif /* HAVE_IO_URING */
    int32_t res;
    bool enabled;
    bool stop;
};

struct _gf_io_handlers {
    gf_io_callback_t start;
    gf_io_callback_t terminate;
};

#ifdef HAVE_IO_URING

struct _gf_io_sq {
    uint32_t *head;
    uint32_t *tail;
    uint32_t *flags;
    uint32_t *dropped;
    uint32_t *array;
    struct io_uring_sqe *sqes;

    gf_io_list_item_t *queue;

    gf_io_request_t delay;

    void *ring;
    size_t size;
    size_t sqes_size;
    uint32_t sqes_idx;

    uint32_t ring_mask;
    uint32_t ring_entries;
};

struct _gf_io_cq {
    uint32_t *head;
    uint32_t *tail;
    uint32_t *overflow;
    struct io_uring_cqe *cqes;
    uint32_t *flags;

    void *ring;
    size_t size;

    uint32_t ring_mask;
    uint32_t ring_entries;
};

#endif /* HAVE_IO_URING */

struct _gf_io {
#ifdef HAVE_IO_URING
    gf_io_sq_t sq;
    gf_io_cq_t cq;
#endif /* HAVE_IO_URING */

    pthread_mutex_t mutex;
    pthread_cond_t cond;

    gf_io_mode_t mode;

    uint32_t num_workers;

    uint32_t fd;
    int32_t res;
    bool shutdown;
};

extern gf_io_t gf_io;

int32_t
gf_io_run(uint32_t workers, gf_io_handlers_t *handlers, void *data);

void
gf_io_done(gf_io_request_t *req);

#ifdef HAVE_IO_URING

/* Send requests to the kernel. This cannot be called directly, only
 * through gf_io_request_submit_list(). */
void
gf_io_push(gf_io_worker_t *worker, gf_io_list_item_t *item);

/* Send requests to the kernel. This cannot be called directly, only
 * through gf_io_request_submit_list(). */
void
gf_io_delayed(gf_io_worker_t *worker, gf_io_list_item_t *item);

/* Prepare an asynchronous request into the SQE. */
void
gf_io_prepare_async(gf_io_request_t *req, struct io_uring_sqe *sqe);

#endif /* HAVE_IO_URING */

static inline gf_io_mode_t
gf_io_mode(void)
{
    return gf_io.mode;
}

static inline void
gf_io_request_submit_list(gf_io_worker_t *worker, gf_io_list_item_t *first,
                          gf_io_list_item_t *last, bool fast)
{
    gf_io_request_t *req;
    gf_io_list_item_t *prev, *current;

    last->next = NULL;
    switch (gf_io_mode()) {
#ifdef HAVE_IO_URING
        case GF_IO_MODE_IO_URING:
            prev = uatomic_xchg(&gf_io.sq.queue, last);
            if (prev == NULL) {
                if (fast) {
                    gf_io_delayed(worker, first);
                } else {
                    /* We are the first one inserting requests to the
                     * pending queue. This means we have taken ownership
                     * of it and we are the only thread that can submit
                     * SQEs to the kernel. */
                    gf_io_push(worker, current);
                }
            } else {
                /* Another thread owns the pending queue. We complete the
                 * insertion into the queue and it will be processed by
                 * the other thread. */
                CMM_STORE_SHARED(prev->next, current);
            }
            break;
#endif /* HAVE_IO_URING */

        case GF_IO_MODE_LEGACY:
            do {
                req = gf_io_object(first, gf_io_request_t, list);
                req->worker = worker;
                first = first->next;
                req->cbk(req);
            } while (first != NULL);
            break;
    }
}

static inline void
gf_io_request_submit(gf_io_worker_t *worker, gf_io_request_t *req, bool fast)
{
    gf_io_request_submit_list(worker, &req->list, &req->list, fast);
}

/* Add a request to the worker. */
static inline void
gf_io_worker_add(gf_io_worker_t *worker, gf_io_request_t *req)
{
    if (worker == NULL) {
        gf_io_request_submit(worker, req, true);
    } else {
        worker->queue.last->next = &req->list;
        worker->queue.last = &req->list;
    }
}

/* Submit any pending requests added to the worker. */
static inline void
gf_io_worker_flush(gf_io_worker_t *worker, bool fast)
{
    gf_io_list_item_t *last;

    if (worker != NULL) {
        last = worker->queue.last;
        if (last != &worker->queue.first) {
            worker->queue.last = &worker->queue.first;

            gf_io_request_submit_list(worker, worker->queue.first.next, last,
                                      fast);
        }
    }
}

/* Setup a request for an asynchronous call. */
static inline void
gf_io_async(gf_io_request_t *req, gf_io_callback_t cbk, void *data)
{
#ifdef HAVE_IO_URING
    req->prepare = gf_io_prepare_async;
#endif /* HAVE_IO_URING */

    req->cbk = cbk;

    req->data = data;

    req->res = 0;
}

#endif /* __GF_IO_H__ */
