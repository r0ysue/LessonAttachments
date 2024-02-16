// setTimeout((x,y,z,u,v)=>{
//     console.log(x,y,z,u,v)
// }, 1000,1,2,3,4,5);

// var x = 1;
// var obj = {
//   x: 2,
//   y: function () {
//     console.log(this.x);
//   },
// };
//setTimeout(obj.y, 1000) // 1
//setTimeout(function(){obj.y()}, 1000) // 1
// setTimeout(obj.y.bind(obj), 1000) // 1


var i = 1;
var arg = setTimeout(function f() {-
  console.log(123)
  setTimeout(f, 2000);
}, 2000);
console.log(arg)
