// var a = 1;
// var b = 3
// function f1(){
//     var b = 2;
//     function f2(){
//         console.log(a,b)
//     }
//     f2()
// }
// f1()

// function f() {
//     var count=0;
//     function add() {
//         count++
//         console.log(count)
//     }
//     return add
// }
// var f2 = f()
// f2()
// f2()
// f2()

// (function (){
//     console.log("i am test")
// }())
// var a = 2;
// var e = eval;
// (function (){
//     var a =3;
//     e("console.log(a); a++")
// })()
// console.log(a)


// var array = [1,"asd",true,{},[],function (){},,689798];
// array.name123 = "name123";
// console.log(Object.keys(array))
// console.log(array.length)
// // array.length = 0
// // console.log(array)
//
// // for (var arrayKey in array) {
// //     console.log(array[arrayKey])
// // }
//
// array.forEach(function (value,key){
//     console.log(key,value)
// })

// var str="hello world"
// Array.prototype.forEach.call(str, function(value){
//     console.log(value)
// });

// var a = 123;
// console.log(typeof a)
// console.log(typeof Number(a))
// console.log(typeof String(a))
// console.log(Boolean([]))


// var obj = {
//     "toString":function () {
//         console.log("toString")
//         return "obj"
//     },
//     "valueOf":function () {
//         console.log("valueOf")
//         return "123"
//     }
// }
// //console.log(Number(obj))
// console.log(String(obj))

// function b(){
//     var error = new Error("b function");
//     try{
//         throw error
//     }catch (e){
//         console.log(e.name)
//         console.log(e.message)
//         console.log(e.stack)
//         return
//     }finally {
//         console.log("finally")
//     }
//     console.log("i am running")
// }
// b()

if(false) {

    console.log(123)
    console.log(456)
}










