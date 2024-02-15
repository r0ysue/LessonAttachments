function guid() {
    function S4() {
      return (((1+Math.random())*0x10000)|0).toString(16).substring(1);
    }
    return (S4()+S4()+"-"+S4()+"-"+S4()+"-"+S4()+"-"+S4()+S4()+S4());
  }
function hookq0(){
    Java.perform(function(){
        Java.choose("com.ilulutv.fulao2.film.l",{
            onMatch:function(ins){
                if(ins.e0.value){

                    ins.q0.value = true
                    /*
                    if(ins.e0.value.toString().indexOf("宝宝睡")>0){
                        console.log("e0 value is :", ins.e0.value); 
                        //ins.q0.value = Java.use("java.lang.Boolean").$new("true");
                        //ins.q0.value = true
                    }
                    */
                }
                
            },onComplete:function(){
                console.log("search complete!")
            }
        })
    })
}
function hookImageByteCiphered(){
    Java.perform(function(){
        Java.use("android.util.Base64").encodeToString.overload('[B', 'int').implementation = function(bytearray,int){
            var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            console.log("IMAGE DATA:bytearray,int=>",ByteString.of(bytearray).hex(),int)
            var result = this.encodeToString(bytearray,int)
            return result;
        }
    })
}

function hookImage(){
    Java.perform(function(){
        Java.use("android.graphics.BitmapFactory").decodeByteArray.overload('[B', 'int', 'int', 'android.graphics.BitmapFactory$Options') .implementation = function(data, offset, length, opts){
            var result = this.decodeByteArray(data, offset, length, opts);
            var ByteString = Java.use("com.android.okhttp.okio.ByteString");

            //var gson = Java.use('com.google.gson.Gson')


            send(data)


            //send(gson.$new().toJson(data))
            //console.log("data, offset, length, opts=>",data, offset, length, opts)
            //console.log("IMAGE DATA:bytearray,int=>",ByteString.of(data).hex())

            /*
            var path = "/sdcard/Download/tmp/"+guid()+".jpg"
            console.log("path=> ",path)
            var file = Java.use("java.io.File").$new(path)
            var fos = Java.use("java.io.FileOutputStream").$new(file);
            fos.write(data);
            fos.close();
            fos.close();
            */

            return result;
        }
    })
}


function main(){
    //hookq0();
    //hookImageByteCiphered();
    //hook_SSLsocketandroid8();
    hookImage();
}
setImmediate(main)



function hook_Address(){
    Java.perform(function(){
        Java.use("java.net.InetSocketAddress").$init.overload('java.net.InetAddress', 'int').implementation = function(addr,int){
            var result = this.$init(addr,int)
            if(addr.isSiteLocalAddress()){
                console.log("Local address => ",addr.toString()," port is => ",int)
            }else{
                console.log("Server address => ",addr.toString()," port is => ",int)
            }
            
            return result;
        }
        
    })
}

function hook_socket(){
    Java.perform(function(){
        console.log("hook_socket;")
        
        Java.use("java.net.SocketOutputStream").write.overload('[B', 'int', 'int').implementation = function(bytearry,int1,int2){
            var result = this.write(bytearry,int1,int2);
            console.log("HTTP write result,bytearry,int1,int2=>",result,bytearry,int1,int2)
            var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            //console.log("bytearray contents=>", ByteString.of(bytearry).hex())
            //console.log(jhexdump(bytearry,int1,int2));
            console.log(jhexdump(bytearry));
            return result;
        }
        
        Java.use("java.net.SocketInputStream").read.overload('[B', 'int', 'int').implementation = function(bytearry,int1,int2){
            var result = this.read(bytearry,int1,int2);
            console.log("HTTP read result,bytearry,int1,int2=>",result,bytearry,int1,int2)
            var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            //console.log("bytearray contents=>", ByteString.of(bytearry).hex())
            //console.log(jhexdump(bytearry,int1,int2));
            console.log(jhexdump(bytearry));
            return result;
        }

    })
}


function hook_SSLsocketandroid8(){
    Java.perform(function(){
        console.log("hook_SSLsocket")
        
        Java.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream").write.overload('[B', 'int', 'int').implementation = function(bytearry,int1,int2){
            var result = this.write(bytearry,int1,int2);
            console.log("HTTPS write result,bytearry,int1,int2=>",result,bytearry,int1,int2)
            var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            console.log("HTTPS bytearray contents=>", ByteString.of(bytearry).hex())
            //console.log(jhexdump(bytearry,int1,int2));
            console.log(jhexdump(bytearry));
            return result;
        }
                
        Java.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream").read.overload('[B', 'int', 'int').implementation = function(bytearry,int1,int2){
            var result = this.read(bytearry,int1,int2);
            console.log("HTTPS read result,bytearry,int1,int2=>",result,bytearry,int1,int2)
            var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            console.log("HTTPS bytearray contents=>", ByteString.of(bytearry).hex())
            //console.log(jhexdump(bytearry,int1,int2));
            //console.log(jhexdump(bytearry));
            return result;
        }
        

    })
}