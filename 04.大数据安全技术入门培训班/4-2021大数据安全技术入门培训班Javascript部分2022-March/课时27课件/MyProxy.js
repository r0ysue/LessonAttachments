// let rawindexof = String.prototype.indexOf
// String.prototype.indexOf = function (str) {
//     var res = rawindexof.call(this, str)
//     console.log(`[String] "${this}" is indexof "${str}", res is ${res}`)
//     return res
// }

dta = {}
dta.listeners = {}

var EventTarget = function() {
};

EventTarget.prototype.listeners = null;
EventTarget.prototype.addEventListener = function(type, callback) {
  if(!(type in dta.listeners)) {
    dta.listeners[type] = [];
  }
  dta.listeners[type].push(callback);
};

EventTarget.prototype.removeEventListener = function(type, callback) {
  if(!(type in dta.listeners)) {
    return;
  }
  var stack = dta.listeners[type];
  for(var i = 0, l = stack.length; i < l; i++) {
    if(stack[i] === callback){
      stack.splice(i, 1);
      return this.removeEventListener(type, callback);
    }
  }
};

EventTarget.prototype.dispatchEvent = function(event) {
  if(!(event.type in dta.listeners)) {
    return;
  }
  var stack = dta.listeners[event.type];
  event.target = this;
  for(var i = 0, l = stack.length; i < l; i++) {
      stack[i].call(this, event);
  }
};
dta.sliderDiv = {
    className:"slide-verify-slider-mask-item"
}
Object.setPrototypeOf(dta.sliderDiv , EventTarget.prototype)
dta.slideMaskItem = {
    style: {}
}
Object.setPrototypeOf(dta.slideMaskItem , EventTarget.prototype)

dta.verifyBlock = {
    style: {}
}
Object.setPrototypeOf(dta.verifyBlock , EventTarget.prototype)
dta.slideMask = {
    style: {}
}
Object.setPrototypeOf(dta.slideMask , EventTarget.prototype)


var Document = function Document(){}
Object.defineProperties(Document.prototype,{
    [Symbol.toStringTag]: {
        value:"Document"
    },
    // [Symbol.hasInstance]: {
    //     get:function (){
    //         console.log("hook")
    //         return true
    //     }
    // }

})
var HTMLDocument = function HTMLDocument(){}
Object.defineProperties(HTMLDocument.prototype,{
    [Symbol.toStringTag]: {
        value:"HTMLDocument"
    }
})
Object.setPrototypeOf(HTMLDocument.prototype, Document.prototype)
let mydocument = {
    "head": {},
    "documentElement": {
        "getAttribute": function () {
        }
    },
    "readyState": "complete",
    "addEventListener": function () {
    },
    "createElement": function () {
        return {}
    },
    "getElementsByTagName": function (str) {
        console.log(str)
        if (str === "meta") {
            let metaRes = []
            metaRes["meta-pro"] = {
                "content": {
                    "length": 6
                }
            }
            return metaRes
        }
    },
    "querySelector": function (selectors){
{
        if (selectors === "#slideVerify > div > div > div"){
           return new Proxy(dta.sliderDiv, getObjhandler(selectors));
        }
        else if (selectors === ".slide-verify-slider-mask-item"){
          return new Proxy(dta.slideMaskItem, getObjhandler(selectors));
        }else if (selectors === ".slide-verify-block"){
          return new Proxy(dta.verifyBlock, getObjhandler(selectors));
        }else if (selectors === ".slide-verify-slider-mask"){
          return new Proxy(dta.slideMask, getObjhandler(selectors));
        }
    }
    }
}
Object.setPrototypeOf(mydocument,HTMLDocument.prototype)


let mynavigator = Object.create({
    userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36",
    platform: "Linux x86_64",
    appCodeName: "Mozilla",
    languages: ["en-US", "en"],
    cookieEnabled: true,
    webdriver: false,
});
Object.defineProperties(mynavigator,{
    [Symbol.toStringTag]: {
        value:"Navigator"
    }
})
let mysrceen = Object.create({
    height: 852,
    width: 1918,
    colorDepth: 24,
});
let mylocation = {
    "protocol": "https:",
    "href": "http://www.dtasecurity.cn/flightlist",
    "pathname": "/flightlist",
    "host": "www.dtasecurity.cn",
    "hostname": "www.dtasecurity.cn",
    "reload": function (){},
}
let mywindow = {
    XMLHttpRequest: function () {
    },
    sessionStorage: {},
    localStorage: {},
    navigator: mynavigator,
    scrollTo: function () {
    },
    addEventListener: function () {
    },
    attachEvent: function () {
    },
    screen: mysrceen,
    location: mylocation,
    chrome: {},
    document: mydocument,
};
Object.defineProperties(global,{
    [Symbol.toStringTag]: {
        value:"Window"
    }
})
let Image = function () {
};
let rawstringify = JSON.stringify;
JSON.stringify = function (Object) {
    if ((Object?.value ?? Object) === global) {
        return "global"
    } else {
        return rawstringify(Object)
    }
}

function checkproxy() {
    //Object.keys(window)
    window.a = {
        "b": {
            "c": {
                "d": 123
            }
        }
    }
    window.a.b.c.d = 456
    window.a.b
    window.btoa("123")
    window.atob.name
    "c" in window.a
    delete window.a.b
    Object.defineProperty(window, "b", {
        value: "bbb"
    })
    Object.getOwnPropertyDescriptor(window, "b")
    Object.getPrototypeOf(window)
    Object.setPrototypeOf(window, {"dta": "dta"})
    // for (let windowKey in window) {
    //     windowKey
    // }
    Object.preventExtensions(window)
    Object.isExtensible(window)
}

function getMethodHandler(WatchName) {
    let methodhandler = {
        apply(target, thisArg, argArray) {
            let result = Reflect.apply(target, thisArg, argArray)
            console.log(`[${WatchName}] apply function name is [${target.name}], argArray is [${argArray}], result is [${result}].`)
            return result
        },
        construct(target, argArray, newTarget) {
            var result = Reflect.construct(target, argArray, newTarget)
            console.log(`[${WatchName}] construct function name is [${target.name}], argArray is [${argArray}], result is [${JSON.stringify(result)}].`)
            return result;
        }
    }
    return methodhandler
}

function getObjhandler(WatchName) {
    let handler = {
        get(target, propKey, receiver) {
            let result = Reflect.get(target, propKey, receiver)
            if (result instanceof Object) {
                if (typeof result === "function") {
                    console.log(`[${WatchName}] getting propKey is [${propKey}] , it is function`)
                    //return new Proxy(result,getMethodHandler(WatchName))
                } else {
                    console.log(`[${WatchName}] getting propKey is [${propKey}], result is [${result}]`);
                }
                return new Proxy(result, getObjhandler(`${WatchName}.${propKey}`))
            }
            console.log(`[${WatchName}] getting propKey is [${propKey?.description ?? propKey}], result is [${result}]`);
            return result;
        },
        set(target, propKey, value, receiver) {
            if (value instanceof Object) {
                console.log(`[${WatchName}] setting propKey is [${propKey}], value is [${value}]`);
            } else {
                console.log(`[${WatchName}] setting propKey is [${propKey}], value is [${value}]`);
            }
            return Reflect.set(target, propKey, value, receiver);
        },
        has(target, propKey) {
            var result = Reflect.has(target, propKey);
            console.log(`[${WatchName}] has propKey [${propKey}], result is [${result}]`)
            return result;
        },
        deleteProperty(target, propKey) {
            var result = Reflect.deleteProperty(target, propKey);
            console.log(`[${WatchName}] delete propKey [${propKey}], result is [${result}]`)
            return result;
        },
        getOwnPropertyDescriptor(target, propKey) {
            var result = Reflect.getOwnPropertyDescriptor(target, propKey);
            console.log(`[${WatchName}] getOwnPropertyDescriptor  propKey [${propKey}] result is [${result}]`)
            return result;
        },
        defineProperty(target, propKey, attributes) {
            var result = Reflect.defineProperty(target, propKey, attributes);
            console.log(`[${WatchName}] defineProperty propKey [${propKey}] attributes is [${attributes}], result is [${result}]`)
            return result
        },
        getPrototypeOf(target) {
            var result = Reflect.getPrototypeOf(target)
            console.log(`[${WatchName}] getPrototypeOf result is [${result}]`)
            return result;
        },
        setPrototypeOf(target, proto) {
            console.log(`[${WatchName}] setPrototypeOf proto is [${proto}]`)
            return Reflect.setPrototypeOf(target, proto);
        },
        preventExtensions(target) {
            console.log(`[${WatchName}] preventExtensions`)
            return Reflect.preventExtensions(target);
        },
        isExtensible(target) {
            var result = Reflect.isExtensible(target)
            console.log(`[${WatchName}] isExtensible, result is [${result}]`)
            return result;
        },
        ownKeys(target) {
            var result = Reflect.ownKeys(target)
            console.log(`[${WatchName}] invoke ownkeys, result is [${result}]`)
            return result
        },
        apply(target, thisArg, argArray) {
            let result = Reflect.apply(target, thisArg, argArray)
            console.log(`[${WatchName}] apply function name is [${target.name}], argArray is [${argArray}], result is [${result}].`)
            return result
        },
        construct(target, argArray, newTarget) {
            var result = Reflect.construct(target, argArray, newTarget)
            console.log(`[${WatchName}] construct function name is [${target.name}], argArray is [${argArray}], result is [${JSON.stringify(result)}].`)
            return result;
        }
    }
    return handler;
}

const navigator = new Proxy(mynavigator, getObjhandler("navigator"));
const screen = new Proxy(mysrceen, getObjhandler("screen"));
const location = new Proxy(mylocation, getObjhandler("location"));
const document = new Proxy(mydocument, getObjhandler("document"));
const window = new Proxy(Object.assign(global, mywindow), getObjhandler("window"));
window.verify = function (e){
  console.log(e)
}
//checkproxy()
module.exports = {
    window,
    navigator,
    screen,
    location,
    String,
    Image,
    document,
    Document,
}
