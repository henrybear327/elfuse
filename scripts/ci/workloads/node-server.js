'use strict';
// HTTP-server half of the elfuse-oci node image CI, passed via node -e.
// elfuse forwards socket syscalls to host sockets with no netns isolation,
// so the 127.0.0.1 listener is host-reachable. It binds port 0: a fixed
// port would collide with a leaked or concurrent guest on the shared
// host loopback.

const http = require('http');

const server = http.createServer((req, res) => {
  if (req.url === '/quit') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('bye\n');
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
