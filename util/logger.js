class Logger {
  constructor(loggingEnabled, logLevel) {
    this.loggingEnabled = loggingEnabled;
    this.logLevel = logLevel;
  }

  log(msg, logLevel = 1) {
    if (this.loggingEnabled && logLevel <= this.logLevel) {
      console.log(msg);
    }
  }
}

module.exports = { Logger };