'use strict';
// HTTP-server half of the elfuse-oci node image CI (issue #224 node profile).
// elfuse forwards socket syscalls to host sockets and does no network-namespace
// isolation, so a guest bound to 127.0.0.1 is reachable from the host loopback;
// the driver curls it repeatedly, then GET /quit exits the guest 0. This
// exercises node's accept4/epoll_pwait/writev/shutdown signature. Passed to the
// guest via `node -e`.
//
// The listener binds port 0 (an ephemeral port the kernel picks) and prints
// "PORT=<n>" on stdout so the driver reads the exact port back; a fixed port
// would collide with a leaked or concurrent guest on the shared host loopback.

const http = require('http');

const server = http.createServer((req, res) => {
  if (req.url === '/quit') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('bye\n');
    // Close the listener and exit 0 so the run reports a clean shutdown.
    server.close(() => process.exit(0));
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('elfuse-node-server-ok\n');
});

server.on('error', (e) => {
  console.error('server error: ' + e.message);
  process.exit(1);
});

server.listen(0, '127.0.0.1', () => {
  console.log('PORT=' + server.address().port);
});
