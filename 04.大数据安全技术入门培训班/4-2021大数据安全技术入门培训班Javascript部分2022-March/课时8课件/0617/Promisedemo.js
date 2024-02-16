function f1(resolve, reject) {
  // 异步代码...
    setTimeout(resolve, 1000, 'resolve');
    //setTimeout(reject, 1000, 'reject');
}
function f2(value){
    console.log(value)
    //return value
    throw new Error("123")
}

var p1 = new Promise(f1);
p1.then(f2).then(f2).catch((error)=>console.log(error))


// var p1 = new Promise(function (resolve, reject) {
//   resolve('成功');
// });
// //p1.then().then().then(console.log, console.error);
// p1.then(function f2(){
//     return "123123"
// }()).then(function (v){
//     console.log("1",v)
// }).then(console.log, console.error);
//
// var p2 = new Promise(function (resolve, reject) {
//   reject(new Error('失败'));
// });
// p2.then().then().then(console.log, console.error);

// const promise = new Promise(function(resolve, reject) {
//   // ... some code
//
//   if (false){
//     resolve("success");
//   } else {
//     reject("error");
//   }
// });
//
// promise.then(function(value) {
//     console.log(value)
//   // success
// }, function(error) {
//   // failure
//     console.log(error)
// });