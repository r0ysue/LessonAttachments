const {VM, VMScript} = require('vm2');
const fs = require('fs');

// By providing a file name as second argument you enable breakpoints
const script = new VMScript(fs.readFileSync("./env.js")  + fs.readFileSync( `./code.js`) , "debugcode");

new VM().run(script);
