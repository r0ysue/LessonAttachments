// 需要在最早时机进行注入

// hook 定时器函数 替换debugger
_setInterval = setInterval
setInterval = function setInterval(code, time){
    console.log(code, time)
    code = code.toString().replace(/debugger/, "").replace(/function ()/, "function aaa")
    return window._setInterval(new Function(code) , time)
}
_setTimeout = setTimeout
setTimeout = function setTimeout(code, time){
    console.log(code, time)
    code = code.toString().replace(/debugger/, "").replace(/function ()/, "function aaa")
    return window._setTimeout(new Function(code), time)
}

// 防止console中的方法被修改
var console_key = Object.getOwnPropertyNames(console)
for (let i = 0; i < console_key.length; i++) {
    if(Object.getOwnPropertyDescriptor(console,console_key[i]).writable
        && Object.getOwnPropertyDescriptor(console,console_key[i]).configurable){
        Object.defineProperty(console, console_key[i], {
        value: console[console_key[i]],
        configurable: false,
        writable: false,
        enumerable: true
    })
    }
}

// 保护伪造函数toString
(() => {
    const $toString = Function.toString
    const myFunction_toString_symbol = Symbol('('.concat('', ')_', (Math.random()) + '').toString(36))
    const myToString = function (){
        return typeof this === 'function' && this[myFunction_toString_symbol] || $toString.call(this)
    }
    function set_native(func, key, value){
        Object.defineProperty(func, key, {
            enumerable: false,
            configurable: true,
            writable: true,
            value: value
        })
    }
    delete Function.prototype.toString
    set_native(Function.prototype, "toString", myToString)
    set_native(Function.prototype.toString, myFunction_toString_symbol, "function toString() { [native code] }")
    globalThis.func_set_native = (func) => {
        myFunction_toString_symbol
        set_native(func, myFunction_toString_symbol, `function ${func.name || ''}() { [native code] }`)
    }
}).call(this)

func_set_native(setInterval)
func_set_native(setTimeout)

