// Don't silently swallow unhandled rejections
process.on("unhandledRejection", (e) => {
  throw e;
});

// Enable Chai's should interface and promise assertions.
const chaiAsPromised = require("chai-as-promised");
const { should, use } = require("chai");

should();
use(chaiAsPromised);
