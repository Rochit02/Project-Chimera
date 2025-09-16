const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const { attemptAttack } = require('./lynx');
const { attemptDefend } = require('./aegis');
const { readJson } = require('./utils');

require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static(path.join(__dirname, '../public')));

io.on('connection', (socket) => {
  console.log('client connected');
  socket.on('start', async (targetUrl) => {
    socket.emit('log', `Starting run on ${targetUrl}`);
    // simple loop: alternate lynx and aegis
    for (let i=0;i<10;i++) {
      const attack = await attemptAttack(targetUrl);
      io.emit('lynx', attack);
      const defend = await attemptDefend(targetUrl);
      io.emit('aegis', defend);
      // emit summaries of logs
      const lynxLog = readJson(path.join(__dirname, '../data/lynx.log')) || [];
      const aegisLog = readJson(path.join(__dirname, '../data/aegis.log')) || [];
      io.emit('logs', { lynx: lynxLog.slice(-5), aegis: aegisLog.slice(-5) });
      await new Promise(r=>setTimeout(r, 500));
    }
    socket.emit('log', 'Run complete');
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  const addr = server.address();
  const realPort = addr && addr.port ? addr.port : PORT;
  console.log('Server listening on', realPort);
});
