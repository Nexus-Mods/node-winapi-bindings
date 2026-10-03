if (process.platform !== 'win32') {
  module.exports = require('./ini');
  return;
}

const winapi = require('./build/Release/winapi');
// const winapi = require('./build/Debug/winapi')

module.exports = winapi;
