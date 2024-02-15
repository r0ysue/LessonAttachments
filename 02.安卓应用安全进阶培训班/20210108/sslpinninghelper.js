
// (agent) [90m[5208352434982] [39mArguments [32mjava.io.File[39m.[92mFile[39m([31m"<instance: java.io.File>", "ab1f3027.0"[39m
// (agent) [90m[5208352434982] [39mArguments [32mjava.io.File[39m.[92mFile[39m([31m"<instance: java.io.File>", "ac1595c4.0"[39m)
// (agent) [90m[5208352434982] [39mArguments [32mjava.io.File[39m.[92mFile[39m([31m"<instance: java.io.File>", "ab1f3027.0"[39m)
// (agent) [90m[5208352434982] [39mArguments [32mjava.io.File[39m.[92mFile[39m([31m"<instance: java.io.File>", "35105088.1"[39m)


setImmediate(function(){
    Java.perform(function(){
        Java.use("java.io.File").$init.overload('java.io.File', 'java.lang.String').implementation = function(file,cert){
            var result = this.$init(file,cert)
            var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
            
            if(file.getPath().indexOf("cacert")>0 && stack.indexOf("X509TrustManagerExtensions.checkServerTrusted")> 0){
                console.log("path,cart",file.getPath(), cert)
                console.log(stack);

            }
            return result;
        }
    })
})