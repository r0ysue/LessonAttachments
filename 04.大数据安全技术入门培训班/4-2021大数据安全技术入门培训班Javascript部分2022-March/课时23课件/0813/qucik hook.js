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
        set_native(func, myFunction_toString_symbol, `function ${func.name || ''}() { [native code] }`)
    }
}).call(this)

window.dta = {}
Function.prototype.hook = function(context, Funcname, onEnter, onLeave){
    if (!onEnter){
        onEnter = function (warpper, FuncName){
            var args = warpper.args;
            console.log(FuncName, "onEnter -> this: ", this, "args: ",args)
        }
    }
    if (!onLeave){
        onLeave = function (retval, FuncName){
            console.log(FuncName, "onLeave -> this: ", this, "retval: ", retval)
        }
    }

    // btoa.hook()
    var _context = context || window;
    var FuncName = this.name || Funcname;
    if (!FuncName){
        console.error("hook function name is empty!")
        return false
    }
    window.dta[FuncName] = this;


    _context[FuncName] = function (){
        var args = Array.prototype.slice.call(arguments,0)
        var _this = this
        var warpper = {
            args
        }

        onEnter.call(_this, warpper, FuncName)
        // this -> window
        var retval = window.dta[FuncName].apply(_this, warpper.args)

        var hook_retval = onLeave.call(_this, retval, FuncName)
        if (hook_retval){
            return hook_retval
        }

        return retval
    }
    Object.defineProperty(_context[FuncName], "name", {
        get: function (){
            return FuncName
        }
    })
    func_set_native(_context[FuncName])
}

console.log("quick hook start")
