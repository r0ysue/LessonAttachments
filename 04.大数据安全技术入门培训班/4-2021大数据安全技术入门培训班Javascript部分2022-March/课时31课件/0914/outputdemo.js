var inputstr = "123";

function encrypt(str) {
  return str + Math.random();
}

var res = encrypt("123");
console.log(res);
var key = "123" + res;
console.log(key);