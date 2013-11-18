#!/usr/bin/env node
/*
 * http-host-proxy
 *
 * HTTP(s) proxy with host based routing to front servers, with optional SSL or authentication
 *
 * Authors: Shaggy and Dave
 *   - https://github.com/shaggy-rl
 *   - https://github.com/bahamas10
 * License: MIT License
 *
 */

var fs = require('fs');
var http = require('http');
var https = require('https');
var util = require('util');

var accesslog = require('access-log');
var getopt = require('posix-getopt');
var httpProxy = require('http-proxy');
var PasshashAuth = require('passhash-auth');
var strsplit = require('strsplit');

var defaulthost = '0.0.0.0';
var defaultport = 8080;
var defaultfaildelay = 2;

var package = require('./package.json');

function usage() {
  return [
    'usage: http-host-proxy [options] -r routefile.json',
    '',
    'HTTP(s) proxy with host based routing to front servers, with optional SSL or authentication',
    '',
    'required options',
    '  -r, --routes <file.json>      [env HTTPHOSTPROXY_ROUTES] a JSON file of host based routes',
    '',
    'authentication options',
    '  -a, --auth <authfile>         [env HTTPHOSTPROXY_AUTH] enable basic http authorization',
    '                                and use <authfile> as the `passhash-auth` file',
    '  -f, --fail-delay <seconds>    [env HTTPHOSTPROXY_FAIL_DELAY] delay, in seconds, before sending a response to a client',
    '                                that failed authentication, defaults to ' + defaultfaildelay,
    '',
    'ssl options',
    '  -c, --cert <certfile>         [env HTTPHOSTPROXY_CERT] the SSL cert file to use when `--ssl` is switched on',
    '  -k, --key <keyfile>           [env HTTPHOSTPROXY_KEY] the SSL key file to use when `--ssl` is switched on',
    '  -s, --ssl                     [env HTTPHOSTPROXY_SSL] enable ssl, requires `--key` and `--cert` be specified',
    '',
    'socket options',
    '  -H, --host <host>             [env HTTPHOSTPROXY_HOST] the host address on which to listen, defaults to ' + defaulthost,
    '  -p, --port <port>             [env HTTPHOSTPROXY_PORT] the port on which to listen, defaults to ' + defaultport,
    '',
    'options',
    '  -h, --help                    print this message and exit',
    '  -u, --updates                 check for available updates on npm',
    '  -v, --version                 print the version number and exit'
  ].join('\n');
}

// command line arguments
var options = [
  'a:(auth)',
  'c:(cert)',
  'f:(fail-delay)',
  'h(help)',
  'H:(host)',
  'k:(key)',
  'p:(port)',
  'r:(routes)',
  's(ssl)',
  'u(updates)',
  'v(version)'
].join('');
var parser = new getopt.BasicParser(options, process.argv);

var opts = {
  auth: process.env.HTTPHOSTPROXY_AUTH,
  cert: process.env.HTTPHOSTPROXY_CERT,
  faildelay: process.env.HTTPHOSTPROXY_FAIL_DELAY,
  host: process.env.HTTPHOSTPROXY_HOST,
  key: process.env.HTTPHOSTPROXY_KEY,
  port: process.env.HTTPHOSTPROXY_PORT,
  routesfile: process.env.HTTPHOSTPROXY_ROUTES,
  ssl: process.env.HTTPHOSTPROXY_SSL,
};
var option;
while ((option = parser.getopt()) !== undefined) {
  switch (option.option) {
    case 'a': opts.auth = option.optarg; break;
    case 'c': opts.cert = option.optarg; break;
    case 'f': opts.faildelay = option.optarg; break;
    case 'h': console.log(usage()); process.exit(0);
    case 'H': opts.host = option.optarg; break;
    case 'k': opts.key = option.optarg; break;
    case 'p': opts.port = option.optarg; break;
    case 'r': opts.routesfile = option.optarg; break;
    case 's': opts.ssl = true; break;
    case 'u': // check for updates
      require('latest').checkupdate(package, function(ret, msg) {
        console.log(msg);
        process.exit(ret);
      });
      return;
    case 'v': console.log(package.version); process.exit(0);
    default: console.error(usage()); process.exit(1); break;
  }
}
var args = process.argv.slice(parser.optind());

opts.host = opts.host || defaulthost;
opts.port = opts.port || defaultport;
opts.faildelay = typeof opts.faildelay === 'undefined' ? defaultfaildelay : opts.faildelay;

if (!opts.routesfile) {
  console.error('[error] `-r, --routes` must be specified!\n\n%s',
      usage());
  process.exit(1);
}

if (opts.ssl && (!opts.key || !opts.cert)) {
  console.error('[error] `-k` and `-c` must be specified with `--ssl`\n\n%s',
      usage());
  process.exit(1);
}

// create the proxies
var routes = JSON.parse(fs.readFileSync(opts.routesfile, 'utf-8'));
var proxies = {};
Object.keys(routes).forEach(function(key) {
  var val = routes[key];
  if (typeof val === 'string') {
    var s = val.split(':');
    var host = s[0];
    var port = s[1];
    if (!port)
      port = host.indexOf('https') === 0 ? 443 : 80
    val = {
      host: host,
      port: port
    };
  }
  proxies[key] = new httpProxy.HttpProxy({target:val});
});

// create the HTTP or HTTPS server
var server;
if (opts.ssl) {
  var options = {
    key: fs.readFileSync(opts.key, 'utf8'),
    cert: fs.readFileSync(opts.cert, 'utf8')
  };
  server = https.createServer(options, onrequest);
} else {
  server = http.createServer(onrequest);
}
server.listen(opts.port, opts.host, listening);

// create an authorization object if necessary
var auth;
if (opts.auth)
  auth = new PasshashAuth(opts.auth);

// web server started
function listening() {
  console.log('listening on %s://%s:%d',
      opts.ssl ? 'https' : 'http', opts.host, opts.port);
}

// new web request
function onrequest(req, res) {
  // log every request with relevant information
  accesslog(req, res, function(s) {
    var prefix;
    if (opts.auth) {
      prefix = util.format('%s@%s',
          credentials && credentials.user || '<empty>',
          host || '<empty>');
    } else {
      prefix = util.format('%s',
          host || '<empty>');
    }
    console.log('[%s] %s',
      prefix, s);
  });

  var host = req.headers.host;
  var p = proxies.hasOwnProperty(host) ? proxies[host] : null;
  var credentials = getcredentials(req);

  // don't expose auth info to the backend service if we are handling it
  if (opts.auth)
    delete req.headers.authorization;

  // check auth first if applicable
  if (auth) {
    // check if credentials were given
    if (!credentials) {
      fail(res, credentials);
      return;
    }

    // check if credentials match a known user/pass
    if (!auth.checkHashMatch(credentials.user, credentials.pass)) {
      setTimeout(function() {
        fail(res, credentials);
      }, opts.faildelay * 1000);
      return;
    }
  }

  // check host header
  if (!host) {
    res.statusCode = 400;
    res.end('no host header found\n');
    return;
  }

  // check router for proxy
  if (!p) {
    res.statusCode = 404;
    res.end('no route found for host: ' + host + '\n');
    return;
  }

  // proxy it!
  p.proxyRequest(req, res);
}

// failed auth, send auth headers back
function fail(res, creds) {
  res.setHeader('WWW-Authenticate', 'Basic realm="Auth Required"');
  res.statusCode = 401;
  res.end();
}

// extract the credentials from the req object
function getcredentials(req) {
  var a = req.headers.authorization;
  if (!a || !a.indexOf('Basic ') === 0)
    return null;

  var ret = null;
  try {
    var s = new Buffer(a.split(' ')[1], 'base64').toString();
    var split = strsplit(n, ':', 2);
    var user = split[0];
    var pass = split[1];
    ret = {
      user: user,
      pass: pass
    };
  } catch (e) {}
  return ret;
}
