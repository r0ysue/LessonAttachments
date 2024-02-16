/*
题目要求:
使用对象的知识 使之输出结果如下
JS改变了这个元素
JS也改变了这个元素
localhost:63342
3
false
*/

var first = document.getElementById("first");
var last = document.getElementsByClassName("last");
first.innerHTML = "JS改变了这个元素";
last[0].innerHTML = "JS也改变了这个元素";
var host = document.location.host;
var length = navigator.plugins.length;
var isPrototypeOf = navigator.userActivation.isPrototypeOf;

console.log(first.innerHTML)
console.log(last[0].innerHTML)
console.log(host)
console.log(length)
console.log(isPrototypeOf())


