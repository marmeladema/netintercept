# netintercept
User space network intercepting library

## What is netintercept?
netintercept is a library that allows you to intercept network traffic without priviledges and create clean pcap files that you can then read with your favorite network analysis tools (Wireshark, ...).

## How does it work?
It uses LD_PRELOAD environment variable to preload the library and redefine various network related functions from `GNU libc`, `Mozilla nspr`, or `OpenSSL` using `dlsym`:

```c
typedef ssize_t write_t(int fd, const void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count) {
    write_t write_func = dlsym(RTLD_NEXT, "write");
    if(!write_func) {
        printf("[%d] dlsym error: %s\n", getpid(), dlerror());
        abort();
    }
    /* netintercept code */
    int ret = write_func(fd, buf, count);
    /* netintercept code */
    return ret;
}
```

Then, each time the target program calls write, our function is called and is able to track file descriptor and write data to an output pcap file using `libpcap`.

In order to have a usable pcap file, we reconstruct "ideal" layer 3 (IPv4, IPv6) and layer 4 (TCP, UDP).

`Mozilla nspr` and `OpenSSL` libraries are also hooked to dump unencrypted traffic that we would see encrypted with kernel space traffic capture.

## Limitations

### Layer 2

This level of information is fully managed by the operating system and we can not get those reliably from user space.
Thus you will not see ARP request / response or even ethernet layer in the pcaps.

### Inline syscall

Because of the technique we use to hook function calls, we can not see inline syscall. Especially, we currently miss some `close` calls from the `GNU libc` itself.
To prevent this, we developed a clever file descriptor tracking system. If file descriptor has changed between two intercepted calls, we can deduce that we missed a `close` call. It works well in practice.

### Ideal layer 3/4

Because we reconstruct and simulate layer 3 and 4, you will not see real traffic as you would have with kernel space traffic capture.

## How to build it?
First you need to configure CMake build system:

    cmake <path_to_netintercept>

Then, you can build the library:

    make

## How to use it?

    LD_PRELOAD=$PWD/netintercept.so <program>

This will launch `<program>` and dump network packets in `netintercept.pcap`

You can configure the name of the pcap file with the `NETINTERCEPT_FILE` environment variable. You can also use special patterns that will by dynamicaly replaced by their value:
* `%p`: pid of the running process
* `%t`: timestamp of start of the program
* `%h`: hostname
* `%e`: executable filename (without path prefix)
* `%E`: pathname of executable, with slashes ('/') replaced by exclamation marks ('!')
* `%u`: (numeric) real UID of dumped process

Those patterns are indeed inspired by the `/proc/sys/kernel/core_pattern` file from Linux (see man 5 core).

You can also select the packets you are interested in with a tcpdump filter using the `NETINTERCEPT_FILTER` environment variable:

    LD_PRELOAD=$PWD/netintercept.so NETINTERCEPT_FILTER=tcp <program>

For more information about tcpdump filters, read https://www.tcpdump.org/manpages/pcap-filter.7.html
