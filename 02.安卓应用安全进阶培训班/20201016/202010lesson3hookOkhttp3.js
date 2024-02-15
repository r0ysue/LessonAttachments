function hook_okhttp3(classLoader) {
    console.log("START");
    Java.perform(function () {
        // 加载包含logging-interceptor拦截器的DEX
        classLoader.openClassFile("/data/local/tmp/okhttplogging.dex").load();
        var MyInterceptor = classLoader.use("com.r0ysue.learnokhttp.okhttp3Logging");
         // 加载包含CurlInterceptor拦截器的DEX
        classLoader.openClassFile("/data/local/tmp/myok2curl.dex").load();
        console.log("loading dex successful!")

        
        const curlInterceptor =  classLoader.use("com.moczul.ok2curl.CurlInterceptor");
        const loggable = classLoader.use("com.moczul.ok2curl.logger.Loggable");
        var Log = classLoader.use("android.util.Log");
        var TAG = "okhttpGETcurl";

        //注册类————一个实现了所需接口的类
        var MyLogClass = Java.registerClass({
            name: "okhttp3.MyLogClass",
            implements: [loggable],
            methods: {
                log: function (MyMessage) {
                    Log.v(TAG, MyMessage);
                }}
        });

        var MyInterceptorObj = MyInterceptor.$new();
        const mylog = MyLogClass.$new();
        // 得到所需拦截器对象
        var curlInter = curlInterceptor.$new(mylog);

        var Builder = Java.use("okhttp3.OkHttpClient$Builder");
        Builder.build.implementation = function () {
            this.networkInterceptors().add(MyInterceptorObj);
            this.networkInterceptors().add(curlInter);
            return this.build();
        };

        console.log("hook_okhttp3...");
    });
}

function main(){
    Java.perform(function() {
        console.log("Entering")
        var application = Java.use("android.app.Application");
        application.attach.overload('android.content.Context').implementation = function(context) {
            this.attach(context); // 先执行原来的attach方法
             // 获取classloader
            Java.classFactory.loader = context.getClassLoader();
            hook_okhttp3(Java.classFactory);
        }
    });
}


function searchClient(){
    Java.perform(function(){
        //Java.openClassFile("/data/local/tmp/r0gson.dex").load();
        //const gson = Java.use('com.r0ysue.gson.Gson');
        var gson2 = Java.use('com.google.gson.Gson');

        // 加载包含CurlInterceptor拦截器的DEX
        Java.openClassFile("/data/local/tmp/myok2curl.dex").load();
        console.log("loading dex successful!")
        const curlInterceptor =  Java.use("com.moczul.ok2curl.CurlInterceptor");
        const loggable = Java.use("com.moczul.ok2curl.logger.Loggable");
        var Log = Java.use("android.util.Log");
        var TAG = "okhttpGETcurl";
        //注册类————一个实现了所需接口的类
        var MyLogClass = Java.registerClass({
            name: "okhttp3.MyLogClass",
            implements: [loggable],
            methods: {
                log: function (MyMessage) {
                    Log.v(TAG, MyMessage);
                }}
        });        
        const mylog = MyLogClass.$new();
        // 得到所需拦截器对象
        var curlInter = curlInterceptor.$new(mylog);


        // 加载包含logging-interceptor拦截器的DEX
        Java.openClassFile("/data/local/tmp/okhttplogging.dex").load();
        var MyInterceptor = Java.use("com.r0ysue.learnokhttp.okhttp3Logging");
        var MyInterceptorObj = MyInterceptor.$new();        

        Java.choose("okhttp3.OkHttpClient",{
            onMatch:function(instance){
                console.log("1. found instance:",instance)
                console.log("2. instance.interceptors():",instance.interceptors().$className)
                console.log("3. instance._interceptors:",instance._interceptors.value.$className)
                //console.log("4. interceptors:",gson2.$new().toJson(instance.interceptors())) 
                console.log("5. interceptors:",Java.use("java.util.Arrays").toString(instance.interceptors().toArray()))
                var newInter = Java.use("java.util.ArrayList").$new();
                newInter.addAll(instance.interceptors());
                console.log("6. interceptors:",Java.use("java.util.Arrays").toString(newInter.toArray()));
                console.log("7. interceptors:",newInter.$className);
                newInter.add(MyInterceptorObj);
                newInter.add(curlInter);
                instance._interceptors.value = newInter;
                
            },onComplete:function(){
                console.log("Search complete!")
            }
        })
        
    })

}



function searchClientMOOC(){
    Java.perform(function(){
        /*
        //Java.openClassFile("/data/local/tmp/r0gson.dex").load();
        //const gson = Java.use('com.r0ysue.gson.Gson');
        //var gson2 = Java.use('com.google.gson.Gson');

        // 加载包含CurlInterceptor拦截器的DEX
        Java.openClassFile("/data/local/tmp/myok2curl.dex").load();
        console.log("loading dex successful!")
        const curlInterceptor =  Java.use("com.moczul.ok2curl.CurlInterceptor");
        const loggable = Java.use("com.moczul.ok2curl.logger.Loggable");
        var Log = Java.use("android.util.Log");
        var TAG = "okhttpGETcurl";
        //注册类————一个实现了所需接口的类
        var MyLogClass = Java.registerClass({
            name: "okhttp3.MyLogClass",
            implements: [loggable],
            methods: {
                log: function (MyMessage) {
                    Log.v(TAG, MyMessage);
                }}
        });        
        const mylog = MyLogClass.$new();
        // 得到所需拦截器对象
        var curlInter = curlInterceptor.$new(mylog);
        */

        // 加载包含logging-interceptor拦截器的DEX
        Java.openClassFile("/data/local/tmp/okhttp-4.8.1.jar.dex").load();
        Java.openClassFile("/data/local/tmp/okhttplogging.dex").load();
        var MyInterceptor = Java.use("com.r0ysue.learnokhttp.okhttp3Logging");
        var MyInterceptorObj = MyInterceptor.$new();        
        

        Java.choose("okhttp3.O0000ooO",{
            onMatch:function(instance){
                console.log("1. found instance:",instance)
                console.log("2. instance.interceptors():",instance.O0000o0().$className)
                //console.log("3. instance._interceptors:",instance._O0000o0.value.$className)
                
                //console.log("4. interceptors:",gson2.$new().toJson(instance.interceptors())) 
                console.log("5. interceptors:",Java.use("java.util.Arrays").toString(instance.O0000o0().toArray()))
                var newInter = Java.use("java.util.ArrayList").$new();
                newInter.addAll(instance.O0000o0());
                console.log("6. interceptors:",Java.use("java.util.Arrays").toString(newInter.toArray()));
                console.log("7. interceptors:",newInter.$className);
                newInter.add(MyInterceptorObj);
                instance._O0000Oo.value = newInter;
                
            },onComplete:function(){
                console.log("Search complete!")
            }
        })
    })

}


function searchClientSuper(){
      
    
    Java.perform(function(){
        //Java.openClassFile("/data/local/tmp/r0gson.dex").load();
        //const gson = Java.use('com.r0ysue.gson.Gson');
        //var gson2 = Java.use('com.google.gson.Gson');
        /*

        // 加载包含CurlInterceptor拦截器的DEX
        Java.openClassFile("/data/local/tmp/myok2curl.dex").load();
        console.log("loading dex successful!")
        const curlInterceptor =  Java.use("com.moczul.ok2curl.CurlInterceptor");
        const loggable = Java.use("com.moczul.ok2curl.logger.Loggable");
        var Log = Java.use("android.util.Log");
        var TAG = "okhttpGETcurl";
        //注册类————一个实现了所需接口的类
        var MyLogClass = Java.registerClass({
            name: "okhttp3.MyLogClass",
            implements: [loggable],
            methods: {
                log: function (MyMessage) {
                    Log.v(TAG, MyMessage);
                }}
        });        
        const mylog = MyLogClass.$new();
        // 得到所需拦截器对象
        var curlInter = curlInterceptor.$new(mylog);
        */

        
        
        // 加载包含logging-interceptor拦截器的DEX
        Java.openClassFile("/data/local/tmp/okio-2.8.0.jar.dex").load();
        Java.openClassFile("/data/local/tmp/okhttp-4.8.1.jar.dex").load();
        console.log( Java.openClassFile("/data/local/tmp/classes.dex").getClassNames().toString());
        Java.openClassFile("/data/local/tmp/classes.dex").load();
        
        const MyInterceptor = Java.use("com.r0ysue.learnokhttp.okhttp3Logging");
        var MyInterceptorObj = MyInterceptor.$new();    
        
        
        var dexclassloader = Java.use("dalvik.system.DexClassLoader");
        var stringClass = Java.use("java.lang.String");

        var loader = dexclassloader.$new(stringClass.$new("/data/local/tmp/okhttplogging.dex"),null,null,dexclassloader.getSystemClassLoader().getParent());
        var ok3httploggingClass = loader.loadClass(stringClass.$new("com.r0ysue.learnokhttp.okhttp3Logging"))
        var MyInterceptorObj = ok3httploggingClass.$new();   
        

        Java.choose("فمضﺝ.ﻙﺫتك",{
            onMatch:function(instance){
                console.log("1. found instance:",instance)
                //console.log("2. instance.interceptors():",instance.interceptors().$className)
                console.log("3. instance._interceptors:",instance.ﻭﻍﺫﻉ.value.$className)
                
                //console.log("4. interceptors:",gson2.$new().toJson(instance.interceptors())) 
                console.log("5. interceptors:",Java.use("java.util.Arrays").toString(instance.ﻭﻍﺫﻉ.value.toArray()))
                /*
                var newInter = Java.use("java.util.ArrayList").$new();
                newInter.addAll(instance.interceptors());
                console.log("6. interceptors:",Java.use("java.util.Arrays").toString(newInter.toArray()));
                console.log("7. interceptors:",newInter.$className);
                newInter.add(MyInterceptorObj);
                newInter.add(curlInter);
                instance._interceptors.value = newInter;
                */
                
            },onComplete:function(){
                console.log("Search complete!")
            }
        })
        
    })

}


setImmediate(searchClient)