/*
题目要求：使之在nodejs中输出结果与浏览器一致（需要用到点函数的知识）
 */
var str = "转码";
str = encodeURIComponent(str);
var b64encode = btoa(str);
var b64decode = atob(b64encode);
b64decode = decodeURIComponent(b64decode)

console.log(b64encode);
console.log(b64decode);