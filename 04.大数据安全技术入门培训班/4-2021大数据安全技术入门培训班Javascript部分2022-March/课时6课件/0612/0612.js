// var obj = new Proxy({}, {
//   get: function (target, propKey, receiver) {
//     console.log(`getting ${propKey}!`);
//     return Reflect.get(target, propKey, receiver);
//   },
//   set: function (target, propKey, value, receiver) {
//     console.log(`setting ${propKey}!`);
//     return Reflect.set(target, propKey, value, receiver);
//   }
// });
//
// var obj2 = Object.create(obj,{
//   "abc":{value:123,writable:true}
// })
// obj2.abc = 456

function test(a,b){
  this.a = a;
  this.b = b;
  return a+b;
}

test = new Proxy(test,{
  apply(target, thisArg, argArray) {
    let result = Reflect.apply(target, thisArg, argArray)
    console.log(`function name is ${target.name}, thisArg is ${thisArg}, argArray is [${argArray}], result is ${result}.`)
    return result
  },
  construct(target, argArray, newTarget) {
    var result = Reflect.construct(target, argArray, newTarget)
    console.log(`construct function name is ${target.name}, argArray is [${argArray}], result is ${JSON.stringify(result)}.`)
    return result;
  }
})
console.log(test(1,2))
console.log(new test(1,2))
