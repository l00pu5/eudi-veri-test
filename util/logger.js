// overall styling
const C_RESET = "\x1b[0m";
const C_BOLD = "\x1b[1m";
const C_BOLD_RESET = "\x1b[21m";
const C_DIM = "\x1b[2m";
const C_DIM_RESET = "\x1b[22m";
const C_ITALIC = "\x1b[3m";
const C_ITALIC_RESET = "\x1b[23m";
const C_UNDERLINE = "\x1b[4m";
const C_UNDERLINE_RESET = "\x1b[24m";
const C_BLINK = "\x1b[5m";
const C_BLINK_RRESET = "\x1b[25m";
const C_INVERSE = "\x1b[7m";
const C_INVERSE_RESET = "\x1b[27m";
const C_STRIKETHROUGH = "\x1b[9m";
const C_STRIKETHROUGH_RESET = "\x1b[29m";

// colors (foreground)
const C_BLACK = "\x1b[30m";
const C_BRIGHT_BLACK = "\x1b[90";
const C_GREEN = "\x1b[32m";
const C_BRIGHT_GREEN = "\x1b[92";
const C_BLUE = "\x1b[34m";
const C_BRIGHT_BLUE = "\x1b[94";
const C_YELLOW = "\x1b[33m";
const C_BRIGHT_YELLOW = "\x1b[93";
const C_RED = "\x1b[31m";
const C_BRIGHT_RED = "\x1b[91";
const C_MAGENTA = "\x1b[35m";
const C_BRIGHT_MAGENTA = "\x1b[95";
const C_CYAN = "\x1b[36m";
const C_BRIGHT_CYAN = "\x1b[96";
const C_WHITE = "\x1b[37m";
const C_BRIGHT_WHITE = "\x1b[96";
const C_DEFAULT = "\x1b[39m";

// colors (background)
const C_BG_BLACK = "\x1b[40m";
const C_BG_BRIGHT_BLACK = "\x1b[100";
const C_BG_RED = "\x1b[41m";
const C_BG_BRIGHT_RED = "\x1b[101";
const C_BG_GREEN = "\x1b[42m";
const C_BG_BRIGHT_GREEN = "\x1b[102";
const C_BG_YELLOW = "\x1b[43m";
const C_BG_BRIGHT_YELLOW = "\x1b[103";
const C_BG_BLUE = "\x1b[44m";
const C_BG_BRIGHT_BLUE = "\x1b[104"
const C_BG_MAGENTA = "\x1b[45m";
const C_BG_BRIGHT_MAGENTA = "\x1b[105";
const C_BG_CYAN = "\x1b[46m";
const C_BG_BRIGHT_CYAN = "\x1b[106";
const C_BG_WHITE = "\x1b[47m";
const C_BG_BRIGHT_WHITE = "\x1b[107";
const C_BG_DEFAULT = "\x1b[49m";

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

  log_msg(msg, config) {
    let logLevel = config.logLevel || 0;
    let logType = config.type || "LOG"; // can be LOG, WARNING, ERROR
    let logPrefix = config.prefix || "";
    let logModule = config.module || "";
    let includeTimestamp = config.timestamp || false;
    if (this.loggingEnabled && logLevel <= this.logLevel) {
      if (!Array.isArray(msg)) {
        throw new Error("Logger: invalid input format!");
      }
      let result = ``;
      for (seg of msg) {
        // TODO: implement proper segment handling
        result.concat("", seg);
      }
    }
  }
}

module.exports = { Logger };