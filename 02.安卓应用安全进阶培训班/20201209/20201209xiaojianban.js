
// var MainActivity = null;

// Java.perform(function () {
//     Java.choose("com.xiaojianbang.app.MainActivity", {
//         onMatch: function (instanse) {
//             MainActivity = instanse;
//             console.log("found instance => ", MainActivity);
//         }, onComplete: function () {
//             console.log("search completed!")
//         }
//     })
// })
function showToast(string) {
    Java.perform(function () {
        var Toast = Java.use('android.widget.Toast');
        var currentApplication = Java.use('android.app.ActivityThread').currentApplication();
        var context = currentApplication.getApplicationContext();

        Java.scheduleOnMainThread(function () {
            Toast.makeText(context, string, Toast.LENGTH_LONG.value).show();
        })
    })


}

function invokeNormal() {
    Java.perform(function () {

        var javaString = Java.use("java.lang.String")
        var MoneyInnerClass = Java.use("com.xiaojianbang.app.Money$innerClass").$new(javaString.$new("r0ysue"), 666).outPrint();
        console.log("result =>", MoneyInnerClass)
        showToast(javaString.$new(MoneyInnerClass))
    })
}

function invokeInit() {
    Java.perform(function () {
        var javaString = Java.use("java.lang.String")
        var MoneyName = Java.use("com.xiaojianbang.app.Money").$new().name();
        showToast(javaString.$new(MoneyName))
    })
}

function invokeOverload() {
    Java.perform(function () {
        var result = Java.use("com.xiaojianbang.app.Utils").test(666);
        console.log("invoke overload result is => ", result);
    })
}


function invokeObject() {
    Java.perform(function () {
        var javaString = Java.use("java.lang.String")
        var newMoney = Java.use("com.xiaojianbang.app.Money").$new(javaString.$new("dollar"), 200);
        var result = Java.use("com.xiaojianbang.app.Utils").test(newMoney);
        showToast(javaString.$new(result))


        var StringArray = Java.array("java.lang.String", [javaString.$new("r0ysue  "), javaString.$new("you are the "), javaString.$new("best ")])
        var result = Java.use("com.xiaojianbang.app.Utils").$new().myPrint(StringArray);
        showToast(javaString.$new(result))

    })
}

function invokeNative() {
    Java.perform(function () {
        var javaString = Java.use("java.lang.String")
        var result = Java.use("com.xiaojianbang.app.NativeHelper").helloFromC();
        showToast(javaString.$new(result));

        result = Java.use("com.xiaojianbang.app.NativeHelper").add(100, 200, 300);
        showToast(javaString.$new(String(result)));


    })
}

function hookMD5() {
    Java.perform(function () {


        var targetClassMethod = "java.security.MessageDigest.getInstance"
        var delim = targetClassMethod.lastIndexOf(".");
        if (delim === -1) return;
        var targetClass = targetClassMethod.slice(0, delim)
        var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)
        var hook = Java.use(targetClass);
        var overloadCount = hook[targetMethod].overloads.length;
        var overloadCount = hook[targetMethod].overloads.length;
        for (var i = 0; i < overloadCount; i++) {
            hook[targetMethod].overloads[i].implementation = function () {
                console.warn("\n*** entered " + targetClassMethod);

                // print args
                if (arguments.length >= 0) {
                    for (var j = 0; j < arguments.length; j++) {
                        console.log("arg[" + j + "]: " + arguments[j]);

                    }


                }
                var retval = this[targetMethod].apply(this, arguments);
                console.log("\nretval: " + retval);
                console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
                return retval;
            }
        }

    })
}

function main() {
    // invokeNormal()
    // invokeInit()
    // invokeOverload()
    // invokeObject()
    // invokeNative()
    hookMD5()
}
setImmediate(main)