let target = {
  a: 1,
  b: 2,
  c: 3
};

let handler = {
  ownKeys(target) {
    var result = Reflect.ownKeys(target)
    console.log(`invoke ownkeys, result is [${result}]`)
    return result
  },
    getOwnPropertyDescriptor(target, propKey){
    var result = Reflect.getOwnPropertyDescriptor(target, propKey);
    console.log(`getOwnPropertyDescriptor  propKey [${propKey}] result is [${JSON.stringify(result)}]`)
    return result;
},
};

let proxy = new Proxy(target, handler);

console.log(Object.keys(proxy))