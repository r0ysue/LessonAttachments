function hook_socket(){
    Java.perform(function(){
        console.log("hook_socket;")
        

        Java.use("java.net.SocketOutputStream").write.overload('[B', 'int', 'int').implementation = function(bytearry,int1,int2){
            var result = this.write(bytearry,int1,int2);
            console.log("HTTP write result,bytearry,int1,int2=>",result,bytearry,int1,int2)
            var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            console.log("bytearray contents=>", ByteString.of(bytearry).hex())
            return result;
        }
        

        Java.use("java.net.SocketInputStream").read.overload('[B', 'int', 'int').implementation = function(bytearry,int1,int2){
            var result = this.read(bytearry,int1,int2);
            console.log("HTTP read result,bytearry,int1,int2=>",result,bytearry,int1,int2)
            var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            console.log("bytearray contents=>", ByteString.of(bytearry).hex())
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
            console.log("bytearray contents=>", ByteString.of(bytearry).hex())
            return result;
        }
        

        
        Java.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream").read.overload('[B', 'int', 'int').implementation = function(bytearry,int1,int2){
            var result = this.read(bytearry,int1,int2);
            console.log("HTTPS read result,bytearry,int1,int2=>",result,bytearry,int1,int2)
            var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            console.log("bytearray contents=>", ByteString.of(bytearry).hex())
            return result;
        }
        

    })
}


function hook_SSLsocket2android10(){
    Java.perform(function(){
        console.log(" hook_SSLsocket2")
        var ByteString = Java.use("com.android.okhttp.okio.ByteString");
        Java.use("com.android.org.conscrypt.NativeCrypto").SSL_write.implementation = function(long,NS,fd,NC,bytearray,int1,int2,int3){
            var result = this .SSL_write(long,NS,fd,NC,bytearray,int1,int2,int3);
            console.log("SSL_write(long,NS,fd,NC,bytearray,int1,int2,int3),result=>",long,NS,fd,NC,bytearray,int1,int2,int3,result)
            console.log(ByteString.of(bytearray).hex());
            return result;
        }
        Java.use("com.android.org.conscrypt.NativeCrypto").SSL_read.implementation = function(long,NS,fd,NC,bytearray,int1,int2,int3){
            var result = this .SSL_read(long,NS,fd,NC,bytearray,int1,int2,int3);
            console.log("SSL_read(long,NS,fd,NC,bytearray,int1,int2,int3),result=>",long,NS,fd,NC,bytearray,int1,int2,int3,result)
            console.log(ByteString.of(bytearray).hex());
            return result;
        }      
    })
}

function main(){
    console.log("Main")
    hook_socket();
    hook_SSLsocketandroid8();
    //hook_SSLsocket2android10();
}
setImmediate(main)