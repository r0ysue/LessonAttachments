function hook_KeyStore_load() {
    Java.perform(function () {
        var ByteString = Java.use("com.android.okhttp.okio.ByteString");
        var myArray=new Array(1024);
        var i = 0
        for (i = 0; i < myArray.length; i++) {
            myArray[i]= 0x0;
         }
        var buffer = Java.array('byte',myArray);
        
        var StringClass = Java.use("java.lang.String");
        var KeyStore = Java.use("java.security.KeyStore");
        KeyStore.load.overload('java.security.KeyStore$LoadStoreParameter').implementation = function (arg0) {
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));

            console.log("KeyStore.load1:", arg0);
            this.load(arg0);
        };
        KeyStore.load.overload('java.io.InputStream', '[C').implementation = function (arg0, arg1) {
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));

            console.log("KeyStore.load2:", arg0, arg1 ? StringClass.$new(arg1) : null);
            if (arg0){
                var file =  Java.use("java.io.File").$new("/sdcard/Download/"+ String(arg0)+".p12");
                var out = Java.use("java.io.FileOutputStream").$new(file);
                var r;
                while( (r = arg0.read(buffer)) > 0){
                    out.write(buffer,0,r)
                }
                console.log("save success!")
                out.close()
            }
            this.load(arg0, arg1);
        };

        console.log("hook_KeyStore_load...");
    });
}

function hook_ssl() {
    Java.perform(function() {
        var ClassName = "com.android.org.conscrypt.Platform";
        var Platform = Java.use(ClassName);
        var targetMethod = "checkServerTrusted";
        var len = Platform[targetMethod].overloads.length;
        console.log(len);
        for(var i = 0; i < len; ++i) {
            Platform[targetMethod].overloads[i].implementation = function () {
                console.log("class:", ClassName, "target:", targetMethod, " i:", i, arguments);
                //printStack(ClassName + "." + targetMethod);
            }
        }
    });
}


function replaceKill(){
    console.log("Preventing from killing ...")
    var kill_addr = Module.findExportByName("libc.so", "kill");
    // var kill = new NativeFunction(kill_addr,"int",['int','int']);
    Interceptor.replace(kill_addr,new NativeCallback(function(arg0,arg1){
        console.log("arg0=> ",arg0)
        console.log("arg1=> ",arg1)

    },"int",['int','int']))
}

function killCertificatePinner(){
    Java.perform(function(){
        console.log("Beginning killCertificatePinner !...")
        Java.use("z1.g").a.implementation = function(str,list){
            console.log("called z1.g.a ~")
            return ;
        }
    })
}


function main(){
    // replaceKill()
    // hook_KeyStore_load()
    // hook_ssl()
    killCertificatePinner();
    
}
setImmediate(main);