function writeSomething(path, contents) {
    var fopen_addr = Module.findExportByName("libc.so", "fopen");
    var fputs_addr = Module.findExportByName("libc.so", "fputs");
    var fclose_addr = Module.findExportByName("libc.so", "fclose");

    //console.log("fopen=>",fopen_addr,"  fputs=>",fputs_addr,"  fclose=>",fclose_addr);

    var fopen = new NativeFunction(fopen_addr, "pointer", ["pointer", "pointer"])
    var fputs = new NativeFunction(fputs_addr, "int", ["pointer", "pointer"])
    var fclose = new NativeFunction(fclose_addr, "int", ["pointer"])

    //console.log(path,contents)

    var fileName = Memory.allocUtf8String(path);
    var mode = Memory.allocUtf8String("a+");

    var fp = fopen(fileName, mode);

    var contentHello = Memory.allocUtf8String(contents);
    var ret = fputs(contentHello, fp)

    fclose(fp);
}

function traceNativeExport(){

    var modules = Process.enumerateModules();
    for(var i = 0;i<modules.length;i++){
        var module = modules[i];

        if(module.name.indexOf("libc.so")<0){
            continue;
        }

        var exports = module.enumerateExports();
        for(var j = 0;j<exports.length;j++){
            //console.log("module name is =>",module.name," symbol name is =>",exports[j].name)
            //var path = "/sdcard/Download/so/"+module.name+".txt"
            // var path = "/data/data/com.roysue.d0so2/cache/"+module.name+".txt"
            // writeSomething(path,"type: "+exports[j].type+" function name :"+exports[j].name+" address : "+exports[j].address+" offset => 0x"+ ( exports[j].address.sub(modules[i].base) )+"\n")
            // if(exports[j].name.indexOf("strto")>=0)continue;
            // if(exports[j].name.indexOf("strco")>=0)continue;
            // if(exports[j].name.indexOf("_l")>=0)continue;
            // if(exports[j].name.indexOf("pthread")>=0)continue;
            
            
            // if(exports[j].name.indexOf("socket")>=0){
            //     attach(exports[j].name,exports[j].address);
            // }
            if(exports[j].name.indexOf("pthread_create")>=0){
                attach(exports[j].name,exports[j].address);
            }
            // if(exports[j].name.indexOf("read")>=0){
            //     attach(exports[j].name,exports[j].address);
            // }
            // if(exports[j].name.indexOf("write")>=0){
            //     attach(exports[j].name,exports[j].address);
            // }
            // if(exports[j].name.indexOf("send")>=0){
            //     attach(exports[j].name,exports[j].address);
            // }
            // if(exports[j].name.indexOf("recv")>=0){
            //     attach(exports[j].name,exports[j].address);
            // }

        }
    }
}

function attach(name,address){
    console.log("attaching ",name);
    Interceptor.attach(address,{
        onEnter:function(args){
            console.log("Entering => " ,name)
            // console.log("args[0] => ",args[0].readCString() )
            // console.log("args[1] => ",args[1].readCString())
            // console.log( hexdump(args[1]))
            
            console.log("args[2] => ",args[2])
            // console.log('R0YSUE called from:\n' +
        // Thread.backtrace(this.context, Backtracer.ACCURATE)
        // .map(DebugSymbol.fromAddress).join('\n') + '\n');

        },onLeave:function(retval){
            console.log("exit => ",name)
            // console.log("retval is => ",retval.readCString())
        }
    })

}

function traceNativeSymbol(){
    var modules = Process.enumerateModules();

    // console.log(JSON.stringify(modules))

    for(var i = 0;i<modules.length;i++){
        var module = modules[i];
        // console.log(JSON.stringify(modules))

        // if(module.name.indexOf("linker64")<0){
        //     continue;
        // }

        var exports = module.enumerateSymbols();
        // console.log(JSON.stringify(exports))
        for(var j = 0;j<exports.length;j++){
            
            // console.log("module name is =>",module.name," symbol name is =>",exports[j].name)
            var path = "/data/data/com.roysue.d0so2/cache/"+module.name+"Symbol.txt"
            writeSomething(path,"type: "+exports[j].type+" function name :"+exports[j].name+" address : "+exports[j].address+" offset => 0x"+ ( exports[j].address.sub(modules[i].base) )+"\n")
            

        }
    }
}



function main(){
    console.log("Entering main")
    traceNativeExport();
    // traceNativeSymbol();

}
setImmediate(main)