// a = {}
// Object.defineProperty(a,"dta", {
//     value:function (){console.log("dta")},
//     writable:true,
//     configurable:false,
// })
// a.dta = function (){console.log("hook dta")}
// a.dta()

let String_hook_Array = Object.getOwnPropertyDescriptors(String)
let String_prototype_hook_Array = Object.getOwnPropertyDescriptors(String.prototype)

for (const stringHookArrayKey in String_hook_Array) {
    let value = String_hook_Array[stringHookArrayKey]
    if(value["writable"]
        && typeof value.value === "function"){
        console.log(stringHookArrayKey)
        value.value.hook(String)
    }
}

for (const stringPrototypeHookArrayKey in String_prototype_hook_Array) {
    let value = String_prototype_hook_Array[stringPrototypeHookArrayKey]
    if(value["writable"]
        && typeof value.value === "function"
        && stringPrototypeHookArrayKey !== "toString"
        && stringPrototypeHookArrayKey !== "concat"
    ){
        console.log(stringPrototypeHookArrayKey)
        value.value.hook(String.prototype)
    }
}
console.log("enum hook start")
