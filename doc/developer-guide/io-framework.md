# I/O Framework for GlusterFS

This framework provides a basic infrastructure to abstract I/O operations
from the actual system calls to support multiple lower level I/O
implementations.

## Introduction

This abstraction makes it possible to always use the same generic API for
I/O related operations independently of how they are internally implemented.

The changes required to use this framework can be significant given that
it's based on a callback architecture while current implementation is
basically sequential. For this reason it will be very useful that the
framework can fully replace the current code to avoid maintaining two
very different implementations, even if the legacy implementation is used.

For example, in the current implementation there are two supported ways to
do I/O:

- **Synchronous I/O** _(legacy implementation)_
  This is the most simple approach. Every time a I/O operation is done,
  it's executed in the foreground, blocking the executing thread until
  the operation finishes.

- **io_uring I/O** ^[1]
  This is a new and powerful kernel API that provides asynchronous I/O
  execution with little overhead. This approach is superior because it
  doesn't block the executing thread, allowing more work to be done while
  the I/O operation is being processed in the background.

_io_uring_ is only present on latest linux kernels and it's dynamically
detected and used if available. Otherwise it silently fails back to the
synchronous implementation in a transparent way for the rest of the code
that uses this framework.

## How to use it

In this section a general overview of the operation will be provided,
focused on the io_uring-based implementation. For differences when
io_uring is not present, check section [Fallback mode](#fallback-mode)

### Initialization

The framework is initialized using `gf_io_run()`.

```c
typedef int32_t (*gf_io_callback_t)(gf_io_request_t *req);

typedef struct {
    gf_io_callback_t start;
    gf_io_callback_t terminate;
} gf_io_handlers_t;

int32_t gf_io_run(uint32_t workers, gf_io_handlers_t handlers, void *data);
```

The first argument defines how many threads will be created to process
the requests. It can be 0 to create as many threads as cores the system
has. If the given value is too small or too big, it's adjusted silently.
Currently the limits are between 2 and 16.

The handlers structure contains two callbacks, one that is called just
after having initialized the I/O infrastructure, and another one that is
called after stopping everything else. The 'data' argument is an extra
argument that will be passed to each callback.

The returned value can be a negative error code if there has been any wait
problem while initializing the system, or a positive error number if the
system has been correctly initialized but it didn't complete cleany. If
everything finished fine, 0 will be returned.

### Termination

When it's determined that the process must be terminated, a call to
`gf_io_shutdown()` must be done.

```c
void gf_io_shutdown(void);
```

This function initiates a shutdown procedure, but returns immediately.
Once the shutdown is completed, `gf_io_run()` will return. It can be
called from anywhere.

When shutdown is initiated, all I/O should have been stopped. If there
is active I/O during the shutdown, they can complete, fail or be cancelled,
depending on what state the request was. To ensure consistent behavior, try
to always stop I/O before terminating the I/O framework.

### Normal operation

After everything is ready, the normal operation of the I/O framework is
very simple:

1. A worker picks one completion event from the kernel.
2. The callback associated to the completion event is executed.
   2.1. The callback can prepare new I/O requests using one of the
        `gf_io_*` I/O functions available for I/O operations.
   2.2. Requests are added to a private queue in the current worker
        using `gf_io_worker_add()`.
   2.3. The callback may (but it's not required to) explicitly flush all
        queued requests to the kernel using `gf_io_worker_flush()`.
3. Once the callback finishes, any queued requests are automatically
   flushed.

### Available I/O operations

The `gf_io_request_t` object used to manage the request is recommended to
be embedded into bigger context structures so that a request can easily
be mapped to its containing object using `gf_io_object()`. This way it's
very easy to pass all needed information between the caller and the callback
without additional memory allocations.

All operations will also have a `data` argument to pass any additional
per-request private data that the callback may need. This data will be
available in `req->data`.

Many of the I/O operations will have a timeout argument, which represents
the maximum time allowed for the I/O to complete. If the operation takes
more than that time, the system call will be cancelled and the callback
will be executed passing a `-ETIMEDOUT` error.

I/O operations will also have a priority argument that makes it possible
to give different priorities to each requests so that the kernel scheduler
can efficiently manage them based on their priority.

#### Asynchronous call

```c
void gf_io_async(gf_io_request_t *req, gf_io_callback_t callback, void *data);
```

#### Read operation

```c
void gf_io_preadv(gf_io_request_t *req, gf_io_callback_t callback, void *data,
                  int32_t fd, const struct iovec *iov, uint32_t count,
                  uint64_t offset, int32_t flags, uint64_t to, int32_t prio);
```

#### Write operation

```c
void gf_io_writev(gf_io_request_t *req, gf_io_callback_t callback, void *data,
                  int32_t fd, const struct iovec *iov, uint32_t count,
                  uint64_t offset, int32_t flags, uint64_t to, int32_t prio);
```

## API Reference

### Types

**gf_io_worker_t**: Context information of a worker.

**gf_io_request_t**: Object to track requests.

**gf_io_callback_t**: Callback function signature to process completion events.

**gf_io_mode_t**: Enumeration of available I/O modes.

### Functions

**gf_io_run**: Main initialization function.

```c
int32_t gf_io_run();
```

**gf_io_shutdown**: Trigger termination of the I/O framework.

```c
void gf_io_shutdown();
```

**gf_io_mode**: Check the current running mode.

```c
gf_io_mode_t gf_io_mode();
```

## Fallback mode

When _io_uring_ cannot be started for any reason, the framework falls back
to a legacy operation mode. In this mode the API will be the same but it
will work in a more simpler way. In this case, the thread pool won't be
started.

The most important difference is that most of the requests are processed
as soon as they are initialized, for example in `gf_io_readv()` a `readv()`
system call will be executed synchronously. The result will be kept into
the request object.

When a request is added to a worker with `gf_io_worker_add()`, instead of
deferring the execution of the callback till the worker processes it, the
callback will be immediately executed.

The other functions do nothing in this mode.

## Remaining improvements

### Reorganize initialization and termination of the process

### Replace io-threads

### Move fuse I/O to this framework

### Move posix I/O to this framework

### Move sockets I/O to this framework

### Move timers to this framework

### Move synctasks to this framework

### Implement a third threaded mode not based on io_uring

[1]: https://kernel.dk/io_uring.pdf
