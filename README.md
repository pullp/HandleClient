# HandleClient

A HandleSystem Client written in python.

# 1. About HandleSystem

> Handle System is a general-purpose global name service that allows secured name resolution and administration over networks such as the Internet.

- [official site](http://www.handle.net/)
- [RFC 3650 : Handle System Overview](https://tools.ietf.org/html/rfc3650)
- [RFC 3651 : Handle System Namespace and Service Definition](https://tools.ietf.org/html/rfc3651)
- [RFC 3652 : Handle System Protocol (v2.1)](https://tools.ietf.org/html/rfc3652)


# 2. About this repository

Please note that the official site[1] has provided a client (also opensource ) written in Java.

There are also some repository [4][5] implement a HandleSystem Client, but they all use HDL.NET® Proxy Server System [7] instead of directly interacting with a HandleSystem server.

This repository is mainly for learning and researching purpose. The implementation is mainly based on three RFCs [2][3][4], also some reference to official client implementation. Codes are tested under Python 3.9

# 3. Things to do

Still lots of things todo XD.

- [ ] simple resolution request
- [ ] detailed documentation
- [ ] ...


# 4. References

1. [official site](http://www.handle.net/)
2. [RFC 3650 : Handle System Overview](https://tools.ietf.org/html/rfc3650)
3. [RFC 3651 : Handle System Namespace and Service Definition](https://tools.ietf.org/html/rfc3651)
4. [RFC 3652 : Handle System Protocol (v2.1)](https://tools.ietf.org/html/rfc3652)
5. [B2HANDLE - github](https://github.com/EUDAT-B2SAFE/B2HANDLE)
6. [handleserver-samples - github](https://github.com/theNBS/handleserver-samples)
7. [HDL.NET® Proxy Server System](http://www.handle.net/proxy_servlet.html)