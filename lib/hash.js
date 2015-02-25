#!/usr/bin/env node
/**
 * generate an auth suitable for http-host-proxy
 *
 * Author: Dave Eddy <dave@daveeddy.com>
 * Date: July 29, 2014
 * License: MIT
 */

var crypto = require('crypto');
var fs = require('fs');

var format = '{username}:{salt}:{hash}:{iterations}';

module.exports = hash;
module.exports.cli = cli;

function cli(args) {
  var username = args[0];
  if (!username) {
    console.error('username must be specified as the first argument');
    process.exit(1);
  }

  if (process.stdin.isTTY) {
    process.stderr.write('enter password: ');
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    process.stdin.setRawMode(true);
    var password = '';
    process.stdin.on('data', function(c) {
      c = c.toString();

      switch (c) {
        case "\n": case "\r": case "\u0004":
          // They've finished typing their password
          process.stdin.setRawMode(false);
          process.stdin.pause();
          console.log();
          console.log(hash(username, password));
          break;
        case "\u0003":
          // Ctrl C
          process.exit(1);
          break;
        default:
          process.stdout.write('*');
          password += c;
          break;
      }
    });
  } else {
    var password = fs.readFileSync('/dev/stdin', 'utf8');
    console.log(hash(username, password));
  }
}

function hash(username, password, opts) {
  opts = opts || {};
  opts.salt = opts.salt || Math.random().toString(36).slice(-8);
  opts.iterations = opts.iterations || Math.floor(Math.random() * 100) + 50;

  var h = password;
  for (var i = 0; i <= opts.iterations; i++) {
    h = crypto.createHmac('sha512', opts.salt).update(h).digest('hex');
  }

  var s = format
    .replace('{username}', username)
    .replace('{salt}', opts.salt)
    .replace('{hash}', h)
    .replace('{iterations}', opts.iterations);

  return s;
}
