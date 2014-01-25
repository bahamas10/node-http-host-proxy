HTTP Host Proxy
===============

HTTP(s) proxy with host based routing to front servers, with optional SSL or authentication

Installation
------------

First, install [Node.js][0].  Then:

    [sudo] npm install -g http-host-proxy

Example
-------

First create a router file

`example-router.json`

``` json
{
  "test1.com": "localhost:8080",
  "test2.com": "127.0.0.1:8081",
  "test3.com": {
    "host": "192.168.1.15",
    "port": 8000
  },
  "daveeddy.com": "daveeddy.com",
  "google.com": "google.com:80",
  "github.com": {
    "host": "github.com",
    "port": 80
  }
}
```

This file maps incoming `host` headers, to the endpoint the server will proxy.
Any of the above forms are permitted in the config.

### Basic

Now, we can fire up the server:

    $ http-host-proxy -r example-router.json
    listening on http://0.0.0.0:8080

By default, the server listens on HTTP, host `0.0.0.0`, port `8080`

In a second terminal, we can trigger some requests to the server

    $ curl -i localhost:8080
    HTTP/1.1 404 Not Found
    Date: Thu, 14 Nov 2013 22:14:59 GMT
    Connection: keep-alive
    Transfer-Encoding: chunked

    no route found for host: localhost:8080
    $ curl -i -H 'host: daveeddy.com' localhost:8080
    HTTP/1.1 200 OK
    server: nginx
    date: Thu, 14 Nov 2013 22:15:12 GMT
    content-type: text/html
    content-length: 18692
    last-modified: Tue, 12 Nov 2013 23:58:31 GMT
    connection: keep-alive
    accept-ranges: bytes

    <!doctype html>
    <html>
    .... SNIPPED ....

In the first request, you can see that we are thrown a `404` from the proxy itself,
because it doesn't have a route defined for the host header `localhost:8080`.  In the
second request however a manual host header is set to `daveeddy.com`, which matches
a route in the router.  The request is proxied to http://www.daveeddy.com, and the
response headers and the body are delivered directly through the proxy.

On the server end, you can see Apache style logs, prefixed with the host header.

    $ http-host-proxy -r example-router.json
    listening on http://0.0.0.0:8080
    [localhost:8080] 127.0.0.1 - - [14/Nov/2013:17:14:59 -0500] "GET / HTTP/1.1" 404 - "-" "curl/7.30.0"
    [daveeddy.com] 127.0.0.1 - - [14/Nov/2013:17:15:12 -0500] "GET / HTTP/1.1" 200 18692 "-" "curl/7.30.0"

### Default Route

You can specify the following in the router file to create a default route for
unmatched host headers:

``` json
{
  "*": "google.com"
}
```

With the above in place, any successful request will be proxied to google

### SSL

Enabling ssl is easy.  You need to already have a certificate and key file, or
generate your own.  To generate your own you can run:

    openssl genrsa -out my.key 4096
    openssl req -new -x509 -days 1826 -key my.key -out my.crt

These 2 commands will create `my.key` and `my.crt` in your current directory.  Now,
just fire up the server with the following options to listen securely.

    $ http-host-proxy -r example-router.json --ssl -k my.key -c my.crt
    listening on https://0.0.0.0:8080
    [daveeddy.com] 127.0.0.1 - - [14/Nov/2013:17:25:19 -0500] "GET / HTTPS/1.1" 200 18692 "-" "curl/7.30.0"

And to generate a request, just change `curl` to use `https`, and supply `-k` if the certificate
is self-signed.

    $ curl -k -i -H 'host: daveeddy.com' https://localhost:8080
    HTTP/1.1 200 OK
    server: nginx
    date: Thu, 14 Nov 2013 22:26:03 GMT
    content-type: text/html
    content-length: 18692
    last-modified: Tue, 12 Nov 2013 23:58:31 GMT
    connection: keep-alive
    accept-ranges: bytes

    <!doctype html>
    <html>
    .... SNIPPED ....

### Authentication

Authentication can also be done by the proxy; It will use basic HTTP auth
before proxying any requests.  The file format for the authentication database file
can be thought of as a stronger version of `htpasswd`, and can be found in the
[Passhash Node Module][1].

**NOTE:** [Passhash][1] supports bycrypt and sha-512, but this proxy currently only
supports sha-512 with a variable amount of iterations.

First, we can create a passhash authentication database by running the following commands:

    $ [sudo] npm install -g passhash
    ...
    $ echo -n 'test' | passhash -u test -i 50 -t sha-512 -s > passhash.txt
    $ cat passhash.txt
    test:M/LBFOs4Q1y/Tu8k+GyF2SO2u4wVUYSu945Gd/lplUWd1hUwGYEecMOi7dT7b3hppKwS08appAs+f9JEdTneM2ag9JZOT2iNFp9fPxMIcfEamGrofnP/RmABR8SnltyAe0AItNx1xAogItKQdfqFsnE/FNBmlggAh9JHryVwNaw=:e11c1c5145a37c5c16c2345e1194499938657fe8dc513341e6caf315f128868d6d2ae7768145498385cc1ebe067529da722d908c992104dc2304b4fd25a04545:50

Now, we start the server with this file

    $ http-host-proxy -r example-router.json -a passhash.txt
    listening on http://0.0.0.0:8080

Make a few requests, first without authorization, then with it supplied

     $ curl -i -H 'host: daveeddy.com' localhost:8080
     HTTP/1.1 401 Unauthorized
     WWW-Authenticate: Basic realm="Auth Required"
     Date: Thu, 14 Nov 2013 22:51:30 GMT
     Connection: keep-alive
     Transfer-Encoding: chunked

     $ curl -i -H 'host: daveeddy.com' --user test:test localhost:8080
     HTTP/1.1 200 OK
     server: nginx
     date: Thu, 14 Nov 2013 22:51:42 GMT
     content-type: text/html
     content-length: 18692
     last-modified: Tue, 12 Nov 2013 23:58:31 GMT
     connection: keep-alive
     accept-ranges: bytes

     <!doctype html>
     <html>
     .... SNIPPED ....

And on the server we see:

    $ http-host-proxy -r example-router.json -a passhash.txt
    listening on http://0.0.0.0:8080
    [<empty>@daveeddy.com] 127.0.0.1 - - [14/Nov/2013:17:51:30 -0500] "GET / HTTP/1.1" 401 - "-" "curl/7.30.0"
    [test@daveeddy.com] 127.0.0.1 - - [14/Nov/2013:17:51:42 -0500] "GET / HTTP/1.1" 200 18692 "-" "curl/7.30.0"

In the logs you can see `test@daveeddy.com`, the username is automatically prepended to the host
header when authentication is enabled.

**NOTE:** The authorization header is stripped out by the proxy before being sent
to the destination.

Usage
-----

    usage: http-host-proxy [options] -r routefile.json

    HTTP(s) proxy with host based routing to front servers, with optional SSL or authentication

    required options
      -r, --routes <file.json>      [env HTTPHOSTPROXY_ROUTES] a JSON file of host based routes

    authentication options
      -a, --auth <authfile>         [env HTTPHOSTPROXY_AUTH] enable basic http authorization
                                    and use <authfile> as the `passhash-auth` file
      -f, --fail-delay <seconds>    [env HTTPHOSTPROXY_FAIL_DELAY] delay, in seconds, before sending a response to a client
                                    that failed authentication, defaults to 2

    ssl options
      -c, --cert <certfile>         [env HTTPHOSTPROXY_CERT] the SSL cert file to use when `--ssl` is switched on
      -k, --key <keyfile>           [env HTTPHOSTPROXY_KEY] the SSL key file to use when `--ssl` is switched on
      -s, --ssl                     [env HTTPHOSTPROXY_SSL] enable ssl, requires `--key` and `--cert` be specified

    socket options
      -H, --host <host>             [env HTTPHOSTPROXY_HOST] the host address on which to listen, defaults to 0.0.0.0
      -p, --port <port>             [env HTTPHOSTPROXY_PORT] the port on which to listen, defaults to 8080

    options
      -b, --buffer                  [env HTTPHOSTPROXY_BUFFER] buffer log output, useful if this webserver is heavily used
      -h, --help                    print this message and exit
      -u, --updates                 check for available updates on npm
      -v, --version                 print the version number and exit

Authors
-------

- [bahamas10](https://github.com/bahamas10)
- [shaggy-rl](https://github.com/shaggy-rl)

License
-------

MIT License

[0]: http://nodejs.org
[1]: https://github.com/shaggy-rl/passhash#sha512
