var CONTEXT = null;

function getObjClassName(obj) {
    if (!jclazz) {
        var jclazz = Java.use("java.lang.Class");
    }
    if (!jobj) {
        var jobj = Java.use("java.lang.Object");
    }
    return jclazz.getName.call(jobj.getClass.call(obj));
}

function hookReturn() {
    Java.perform(function () {
        Java.use("com.kanxue.pediy1.VVVVV").VVVV.implementation = function (context, str) {
            var result = this.VVVV(context, str)
            console.log("context,str,result => ", context, str, result);
            console.log("context className is => ", getObjClassName(context));
            CONTEXT = context;
            return true;
        }

    })
}
function invoke() {
    Java.perform(function () {
        //console.log("CONTEXT IS => ",CONTEXT)
        var MainActivity = null;
        Java.choose("com.kanxue.pediy1.MainActivity", {
            onMatch: function (instance) {
                MainActivity = instance;
            },
            onComplete: function () { }
        })


        var CONTEXT2 = Java.use("com.kanxue.pediy1.MainActivity$1").$new(MainActivity);
        var javaString = Java.use("java.lang.String").$new("12345");
        for (var x = 0; x < (99999 + 1); x++) {
            var result = Java.use("com.kanxue.pediy1.VVVVV").VVVV(CONTEXT2, String(x));
            console.log("now x is => ", String(x))
            if (result) {
                console.log("found result is => ", String(x))
                break;
            }
        }
    })
}



function replaceKill(){
    var kill_addr = Module.findExportByName("libc.so", "kill");
    // var kill = new NativeFunction(kill_addr,"int",['int','int']);
    Interceptor.replace(kill_addr,new NativeCallback(function(arg0,arg1){
        console.log("arg0=> ",arg0)
        console.log("arg1=> ",arg1)

    },"int",['int','int']))
}



function invoke2() {
    Java.perform(function () {
        // console.log("CONTEXT IS => ",CONTEXT)
        var MainActivity = null;
        Java.choose("com.kanxue.pediy1.MainActivity",{
            onMatch:function(instance){
                MainActivity = instance;
            },
            onComplete:function(){}
        })


        // var CONTEXT2 = Java.use("com.kanxue.pediy1.MainActivity$1").$new(MainActivity);

        var loader1 = null;
        var loader2 = null;

        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    if (loader.findClass("com.kanxue.pediy1.VVVVV")) {
                        console.log("Successfully found loader")
                        console.log(loader);
                        loader2 = loader;
                        Java.classFactory.loader = loader2;
                    }else if(loader.findClass("com.kanxue.pediy1.MainActivity")){console.log("Successfully found loader")
                        console.log(loader);
                        loader1 = loader;
                    }else{

                    }

                }
                catch (error) {
                    console.log("find error:" + error)
                }
            },
            onComplete: function () {
                console.log("end1")
            }
        })
 
        var javaString = Java.use("java.lang.String").$new("12345");
        for (var x = 0; x < (99999 + 1); x++) {
            var result1 = MainActivity.stringFromJNI(String(100000 - x));

            var result2 = Java.use("com.kanxue.pediy1.VVVVV").VVVV(String(result1));          
            console.log("now x is => ", String(x))
            if (result2) {
                console.log("found result2 is => ", String(100000 - x))
                break;
            }
        }
    })
}

function main() {
    //hookReturn()
    replaceKill();
}
setImmediate(main)




