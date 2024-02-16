function Navigator(){}
Navigator.prototype.constructor.toString = function (){
    return "function Navigator() { [native code] }"
}
var oldtostr = Function.prototype.toString
Function.prototype.toString = function(){
    var res = oldtostr.call(this);
    if (this.name === "Navigator"){
        console.log(this.name,res)
        return "function Navigator() { [native code] }"
    }
    return res;
}
var navigator = new Navigator();
// navigator.constructor = {
//     toString: function (){
//         return "function Navigator() { [native code] }"
//     }
// }

function checknavigator(){
    return  navigator.constructor.toString() === Function.prototype.toString.call(navigator.constructor)
    // return navigator.constructor.toString() === "function Navigator() { [native code] }"
}
console.log(checknavigator())
// var Navigtor = {};
// var navigtor = Object.setPrototypeOf({},Navigtor)
// console.log(navigtor)

// var d = new Date();
// var gettime = d.getTime;
// console.log(gettime.call(d))