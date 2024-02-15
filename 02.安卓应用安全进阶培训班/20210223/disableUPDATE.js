function jhexdump(array) {
    var ptr = Memory.alloc(array.length);
    for(var i = 0; i < array.length; ++i){

        Memory.writeS8(ptr.add(i), array[i]);
        // if(array[i]=='0x34'){
        //     console.log("found 3");
        //     if(array.length - i > 4){
        //         if(array[i+1] == '0x2e' && array[i+2] == '0x31' &&  array[i+3] == '0x2e' &&  array[i+4] == '0x30' ){
        //             console.log("finally found 4.1.0!")
        //         }
        //     }
            // 34 2e 31 2e 30
        // }
    }
        
    console.log(hexdump(ptr, { offset: 0, length: array.length, header: false, ansi: false }));
}

setTimeout(main,1000)
// setImmediate(function(){
    
// })

function hookVIP(){
    Java.perform(function(){
        Java.use("com.chanson.business.model.BasicUserInfoBean").isVip.implementation = function(){
            console.log("Calling isVIP ")
            return true;
        }
        Java.use("com.chanson.common.base.BaseResponse").getErrorCode.implementation = function(){
            console.log("Calling getErrorCode ")
            return 10001;
        }
        Java.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream").write.overload('[B', 'int', 'int').implementation = function (bytearry, int1, int2) {
            for(var i = 0; i < bytearry.length; ++i){
                // Memory.writeS8(ptr.add(i), array[i]);
                if(bytearry[i]=='0x34'){
                    console.log("found 4");
                    if(bytearry.length - i > 4){
                        if(bytearry[i+1] == '0x2e' && bytearry[i+2] == '0x31' &&  bytearry[i+3] == '0x2e' &&  bytearry[i+4] == '0x30' ){
                            bytearry[i+2] = 50
                            console.log("finally change to 4.2.0!")
                        }
                    }
                    // 34 2e 31 2e 30
                }
            }
            var result = this.write(bytearry, int1, int2);
            jhexdump(bytearry)
        
            // var trafficstring = StringClass.$new(bytearry).replace(StringClass.$new("4.1.0"),StringClass.$new("4.2.0"))
            // console.log("write => ",trafficstring)
            // Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()).toString();
            // var result = this.write(trafficstring.getBytes(), int1, int2);
            return result;
        }
        // Java.perform(function(){
        //     Java.use("org.json.JSONObject").put.overload('java.lang.String', 'java.lang.Object').implementation = function(str1,str2){
        //         var newString = str2;
        //         // if( (str2 != null) && (str2.toString().indexOf("4.1.0")>=0)){
        //         //     newString=Java.use("java.lang.String").$new("4.2.0")
        //         // }
        //         if(str1.toString.equals("appver")>=0){
        //             console.log("")
        //             newString= Java.cast(Java.use("java.lang.String").$new("4.2.0"),Java.use('java.lang.Object'))
        //         }
        //         // if(str1.indexOf("app_version_code")>=0){
        //         //     newString=Java.use("java.lang.String").$new("4200")
        //         // }
        //         console.log("JSON.put => ",str1," ",newString)
        //         return this.put(str1,newString);
        //     }
    
        // })
    })
    
}

function disableUPDATE(){
    Java.perform(function(){
        Java.choose("com.chanson.business.widget.ConfirmDialogFragment",{
            onMatch:function(ins){
                console.log("found ins => ",ins);
                ins.onDestroyView()
            },
            onComplete:function(){
                console.log("Search completed!")
            }
        })
    })
}
function main(){
    console.log("Start hook")
    hookVIP()
}
// setImmediate(main)
