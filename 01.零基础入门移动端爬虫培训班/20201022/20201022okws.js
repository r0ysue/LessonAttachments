function hook_okhttp3() {
    // 1. frida Hook java层的代码必须包裹在Java.perform中，Java.perform会将Hook Java相关API准备就绪。
    Java.perform(function () {

        Java.openClassFile("/data/local/tmp/okhttp3logging.dex.dex").load();
        // 只修改了这一句，换句话说，只是使用不同的拦截器对象。
        var MyInterceptor = Java.use("com.roysue.octolesson2ok3.okhttp3Logging");

        var MyInterceptorObj = MyInterceptor.$new();
        var Builder = Java.use("okhttp3.OkHttpClient$Builder");
        console.log(Builder);
        Builder.build.implementation = function () {
            this.networkInterceptors().add(MyInterceptorObj);
            console.log("hook Build.build successfully !")
            return this.build();
        };
        console.log("hooking_okhttp3...");
    });
}



function EnumerateClient(){
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

function main(){
    hook_okhttp3();
    EnumerateClient();    
}

setImmediate(main)