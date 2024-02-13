function hook_native(){
    var libnative_addr =  Module.findBaseAddress('libnative-lib.so');
    console.log("libnative_addr is => ",libnative_addr)
    var stringfromJNI3 = libnative_addr.add(0xf454);
    console.log("stringfromJNI3 address is =>",stringfromJNI3);

    var stringfromJNI3_2 = Module.findExportByName('libnative-lib.so', "_Z14stringFromJNI3P7_JNIEnvP7_jclassP8_jstring")
    console.log("stringfromJNI3_2 address is =>",stringfromJNI3_2);

    Interceptor.attach(stringfromJNI3_2,{
        onEnter:function(args){

            console.log("jnienv pointer =>",args[0])
            console.log("jobj pointer =>",args[1])
            console.log("jstring pointer=>",Java.vm.getEnv().getStringUtfChars(args[2], null).readCString() )

        },onLeave:function(retval){
            console.log("retval is =>",Java.vm.getEnv().getStringUtfChars(retval, null).readCString())
            console.log("=================")

        }
    })

}
function main(){
    hook_native()
}
setImmediate(main)