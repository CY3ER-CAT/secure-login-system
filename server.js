'use strict';

const { createApp } = require('./app');

const app = createApp();
const { port, nodeEnv } = app.locals.config;

const server = app.listen(port, () => {
  console.log(`Secure Login System listening on http://localhost:${port} (${nodeEnv})`);
});

server.on('error', (error) => {
  console.error('[server] Failed to start:', error.message);
  app.locals.close();
  process.exitCode = 1;
});

let shuttingDown = false;

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`[server] ${signal} received, shutting down gracefully.`);

  const forceExit = setTimeout(() => {
    console.error('[server] Forced shutdown after timeout.');
    process.exit(1);
  }, 10000);
  forceExit.unref();

  server.close(() => {
    app.locals.close();
    clearTimeout(forceExit);
    process.exit(0);
  });
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
