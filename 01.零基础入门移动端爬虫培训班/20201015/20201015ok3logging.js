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

hook_okhttp3();