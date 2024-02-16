// var temp1 = 1
// var temp2 = "123"
// var temp3 = true
// var temp4 = undefined
// var temp5 = null
// var temp6 = {};
// var temp7 = function (){};
// var temp8 = [];
//
// console.log(typeof temp1)
// console.log(typeof temp2)
// console.log(typeof temp3)
// console.log(typeof temp4)
// console.log(typeof temp5)
// console.log(typeof temp6, temp6 instanceof Array)
// console.log(typeof temp7, temp7.name)
// console.log(typeof temp8, temp8 instanceof Array)

// if([]){
//     console.log(1)
// }

// console.log(0.1+0.2 === 0.3)

// console.log(Number.MAX_SAFE_INTEGER)
// console.log(Math.pow(2,53))
// console.log(90071992547409921)


// console.log(0x11)
// console.log(0o11)
// console.log(0b11)
//
// console.log(parseInt("11",8))
// console.log(parseFloat("0.123"))

// var b = "123"
// var a = "hello";
// a[0] = "b"
// console.log(a)
// console.log(a[0])
// console.log(a.length)

// var f\u006F\u006F = 'abc';
// console.log(foo)

// var b64encode = Buffer.from('JavaScript').toString('base64');
// var b64decode = Buffer.from(b64encode,'base64').toString();
// console.log(b64encode)
// console.log(b64decode)

// var a ={
//     b: 123,
//     1: 1,
//     obj:{
//         obja:1
//     },
// };
// var b = a;
// b = {}
// b.b = 0
// a.c = "c"
// console.log(a["b"])
// console.log(a["1"])
// console.log(a.obj.obja)
// console.log(a.c)

// var a= 1;
// b = a;
// b = 3
// console.log(a)

// var obj = {
//     "a":123,
//     "b":"123",
//     "c":true
// }
// delete obj.a
//
// console.log(Object.keys(obj));
// console.log(obj.toString())
// console.log("a" in obj)
//
// console.log(obj.hasOwnProperty("toString"))
//
// var navigator = {
//     "a":123,
//     "b":"123",
//     "c":true
// }
// for (var navigatorKey in navigator) {
//     if(navigator.hasOwnProperty(navigatorKey)){
//         console.log(navigatorKey)
//     }
// }


// function a(){}
// var b = function (){}
// var c = new Function("a","b","return a+b");
// console.log(c(1,2))

//
// function fib(num) {
//   if (num === 0) return 0;
//   if (num === 1) return 1;
//   return fib(num - 2) + fib(num - 1);
// }
// console.log(fib(6)) // 8

// function a(func){
//     return func(100)
// }
// a(function (value){
//     console.log(value)
// })

// function b(c,d){
//     console.log(a);
//     var a = 100
// }
// b(123,12312)
// console.log(b.name,b.length,b.toString())

var a= 1;
function f2(){
    console.log(a)
}
function f(obj){
    console.log(Array.prototype.slice.call(arguments),arguments.length)
    obj.a = 222
    var a = 2;
    function f3(){
        console.log(a);
    }
    return f3;
}
var obj = {
    "a":111
}
f(obj,213,234123,523);

console.log(obj)