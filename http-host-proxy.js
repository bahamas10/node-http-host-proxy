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
var auth = require('basic-auth');
var getopt = require('posix-getopt');
var httpProxy = require('http-proxy');
var HashP = require('hashp').HashP;
var strsplit = require('strsplit');
var uuid = require('node-uuid');

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
    '                                and use <authfile> as the `hashp` file',
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
    '  -b, --buffer                  [env HTTPHOSTPROXY_BUFFER] buffer log output, useful if this webserver is heavily used',
    '  -d, --debug                   [env HTTPHOSTPROXY_DEBUG] print verbose logs, defaults to false',
    '  -h, --help                    print this message and exit',
    '  -u, --updates                 check for available updates on npm',
    '  -v, --version                 print the version number and exit',
  ].join('\n');
}

function debug() {
  if (opts.debug)
    return console.error.apply(console, arguments);
}

// command line arguments
var options = [
  'a:(auth)',
  'b(buffer)',
  'c:(cert)',
  'd(debug)',
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
  buffer: process.env.HTTPHOSTPROXY_BUFFER,
  cert: process.env.HTTPHOSTPROXY_CERT,
  debug: process.env.HTTPHOSTPROXY_DEBUG,
  faildelay: process.env.HTTPHOSTPROXY_FAIL_DELAY,
  gid: process.env.HTTPHOSTPROXY_GID,
  host: process.env.HTTPHOSTPROXY_HOST,
  key: process.env.HTTPHOSTPROXY_KEY,
  port: process.env.HTTPHOSTPROXY_PORT,
  routesfile: process.env.HTTPHOSTPROXY_ROUTES,
  ssl: process.env.HTTPHOSTPROXY_SSL && process.env.HTTPHOSTPROXY !== '0',
  uid: process.env.HTTPHOSTPROXY_UID,
};
var option;
while ((option = parser.getopt()) !== undefined) {
  switch (option.option) {
    case 'a': opts.auth = option.optarg; break;
    case 'b': opts.buffer = true; break;
    case 'c': opts.cert = option.optarg; break;
    case 'd': opts.debug = true; break;
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
var proxies = {};
function loadroutes(shouldthrow) {
  debug('loading routes: %s', opts.routesfile);
  var routes;
  try {
    routes = JSON.parse(fs.readFileSync(opts.routesfile, 'utf-8'));
  } catch(e) {
    debug('failed to load routes: %s', e.message);
    if (shouldthrow)
      throw e;
    else
      return;
  }

  // clear the old proxies object
  Object.keys(proxies).forEach(function(key) {
    delete proxies[key];
  });
  Object.keys(routes).forEach(function(key) {
    var val = routes[key];
    if (typeof val === 'string') {
      var s = val.split(':');
      var host = s[0];
      var port = s[1];
      if (!port)
        port = host.indexOf('https') === 0 ? 443 : 80;
      val = {
        host: host,
        port: port
      };
    }
    debug('creating proxy: %s => %s', key, JSON.stringify(val));
    proxies[key] = httpProxy.createProxyServer({target: val, xfwd: true});
  });
}

loadroutes(true);
process.on('SIGHUP', loadroutes);

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
var hp;
if (opts.auth) {
  debug('using auth: %s', opts.auth);
  hp = new HashP(fs.readFileSync(opts.auth, 'utf8'));
}

// web server started
function listening() {
  debug('pid: %d', process.pid);
  // step down permissions
  if (opts.gid) {
    debug('changing gid to %s', opts.gid);
    process.setgid(opts.gid);
  }
  if (opts.uid) {
    debug('changing uid to %s', opts.gid);
    process.setuid(opts.uid);
  }
  console.log('listening on %s://%s:%d',
      opts.ssl ? 'https' : 'http', opts.host, opts.port);
  if (opts.buffer) {
    // buffer the logs
    var logbuffer = require('log-buffer');
    logbuffer(8192);
    // flush every 5 seconds
    setInterval(logbuffer.flush.bind(logbuffer), 5 * 1000);
  }
}

// new web request
function onrequest(req, res) {
  var id = uuid.v4();
  var now = Date.now();
  function d() {
    var s = util.format.apply(util, arguments);
    return debug('[%s] %s', id, s);
  }

  d('starting request');
  // log every request with relevant information
  accesslog(req, res, function(s) {
    var prefix;
    if (opts.auth) {
      prefix = util.format('%s@%s',
          credentials && credentials.name || '<empty>',
          host || '<empty>');
    } else {
      prefix = util.format('%s',
          host || '<empty>');
    }
    var _s = util.format('[%s] %s', prefix, s);
    if (opts.debug) {
      d(_s);
    } else {
      console.log(_s);
    }
    d('finished request (%d ms)', Date.now() - now);
  });

  var host = req.headers.host;
  d('host header `%s`', host);
  var implicit = false;
  var p = hasOwnProperty.call(proxies, host) && proxies[host];
  if (!p) {
    d('no explicit route found for %s', host);
    implicit = true;
    p = proxies['*'];
  }
  var credentials = auth(req);

  // check auth first if applicable
  if (opts.auth) {
    // don't expose auth info to the backend service if we are handling it
    delete req.headers.authorization;

    // check if credentials were given
    if (!credentials) {
      d('no credentials supplied');
      fail(res, credentials);
      return;
    }

    // check if credentials match a known user/pass
    if (!hp.checkMatch(credentials.name, credentials.pass)) {
      d('credentials incorrect');
      setTimeout(function() {
        fail(res, credentials);
      }, opts.faildelay * 1000);
      return;
    }
  }

  // check host header
  if (!host && !implicit) {
    d('no host header found');
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

  // everything is set, proxy it!
  if (credentials)
    req.headers['X-Forwarded-User'] = credentials.name;

  d('proxying request to %s:%d', p.options.target.host, p.options.target.port);
  p.web(req, res, function(e) {
    d('proxy failed! %s', e.message);
    res.statusCode = 500;
    res.end();
  });
}

// failed auth, send auth headers back
function fail(res, creds) {
  res.setHeader('WWW-Authenticate', 'Basic realm="Auth Required"');
  res.statusCode = 401;
  res.end();
}
