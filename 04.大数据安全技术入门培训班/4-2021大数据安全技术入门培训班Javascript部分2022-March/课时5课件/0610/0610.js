// const company= 'dta';
// const team= {company};
// console.log(team)
//
// const team = {
//   dowork() {
//     return "work!";
//   },
// };


// let a = 10;
// var b = 20;
// console.log(global.a)
// console.log(global.b)
// const c = "c"
// c = "d"
// for (var i = 0; i < 5 ; i++) {
//     console.log(i)
// }
// console.log(i)
// var boss = "r0ysue";
// console.log(`boss is ${boss}`)

// const arr = [1, 2, 3, 4];
// const [first, second] = arr;
// console.log(first, second)

// function getFullName(obj) {
//   const { firstName, lastName } = obj;
//   console.log(firstName, lastName)
// }
// getFullName({
//     firstName: "chen",
//     lastName: "guilin"
// })

// function processInput() {
//     let [a,b,c,d] = ["1","2","3","4"]
//     return { a, b, c, d};
// }
// console.log(processInput())

// (function (){console.log("Welcome to the DTA.")})();
//
// (() => {
//   console.log('Welcome to the DTA.');
// })();

// function Timer() {
//   this.s1 = 0;
//   this.s2 = 0;
//   // 箭头函数
//   setInterval(() => this.s1++, 1000);
//   // 普通函数
//   setInterval(function () {
//     this.s2++;
//   }, 1000);
// }
//
// var timer = new Timer();
//
// setTimeout(() => console.log('s1: ', timer.s1), 3100);
// setTimeout(() => console.log('s2: ', timer.s2), 3100);

// var newarr = [1,2,3].map((value)=>{
//     console.log(value)
//     return value * 2
// })
// console.log(newarr)

let boss = 'DTA Boss';

const DTA = {
  'employee': 'bxl',
  [boss]: 'r0ysue',
  ['do'+'work'](){
    return 'work';
    },
    'room':{
      'floor':{
          'L':'3'
      }
    }
};

console.log(DTA['employee']) // "bxl"
console.log(DTA[boss]) // 'r0ysue'
console.log(DTA['DTA Boss']) // 'r0ysue'
console.log(DTA.dowork())
const NewDTA = {...DTA}
console.log(NewDTA?.room?.floor?.L ?? '1')



// function DTA(boss, employee) {
//   this.employee= employee;
//   this.boss= boss;
// }
// DTA.prototype.toString = function () {
//   return '(' + this.employee+ ', ' + this.boss+ ')';
// };
// var dta= new DTA('r0ysue', 'bxl');
// console.log(dta.toString())

// class DTA{
//   constructor(boss, employee) {
//     this.employee= employee;
//     this.boss= boss;
//   }
//   toString(){
//     return '(' + this.employee+ ', ' + this.boss+ ')';
//   }
//   get boss(){
//       return "r1ysue"
//   }
//   set boss(value){
//       console.log(value)
//   }
// }
// var dta= new DTA('r0ysue', 'bxl');
// console.log(dta.boss)
// dta.boss = "r2ysue"


// class Navigator{
//
// }
// //Navigator.prototype.platform = "Android"
// var navigator = new Navigator();
//
// function decect (r, e) {
//     var i = [];
//     Object["getOwnPropertyDescriptor"] && i["push"](Object["getOwnPropertyDescriptor"](r, e));
//     Object["getOwnPropertyDescriptors"] && i["push"](!!Object["getOwnPropertyDescriptors"](r)[e]);
//
//     for (var a = 0; a < i["length"]; a++) if (i[a]) return true;
//
//     return false;
// }
// console.log(decect(navigator,"platform"))


// class r0ysue{
//   constructor(x, y,) {
//     this.x = x;
//     this.y = y
//   }
// }
//
// class r1ysue extends r0ysue{
//   constructor(x, y) {
//     super(x, y); // 调用父类的constructor(x, y)
//   }
// }
// var boss = new r1ysue("x", "y")
// console.log(boss)
