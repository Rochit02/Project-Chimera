const io = require('socket.io-client');

const socket = io('http://localhost:4001');
socket.on('connect', () => {
  console.log('connected, starting run');
  socket.emit('start', process.argv[2] || 'http://example.com');
});
socket.on('log', (m) => console.log('[log]', m));
socket.on('lynx', (m) => console.log('[lynx]', m));
socket.on('aegis', (m) => console.log('[aegis]', m));
socket.on('logs', (m) => console.log('[logs]', m));
socket.on('disconnect', () => { console.log('disconnected'); process.exit(0); });

setTimeout(()=>{ console.log('demo timeout'); process.exit(0); }, 10000);
