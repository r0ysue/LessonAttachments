
function hook_socket(){
    Java.perform(function(){
        var ByteString = Java.use("com.android.okhttp.okio.ByteString");
        
        Java.use("java.net.SocketOutputStream").socketWrite0.implementation = function(fd,bytearray,int1,int2){
            var result = this.socketWrite0(fd,bytearray,int1,int2);
            console.log("socketWrite0 fd,bytearray,int1,int2,result => ",fd,bytearray,int1,int2,result)
//            console.log(ByteString.of(bytearray).hex());
            return result;
        }
        Java.use("java.net.SocketInputStream").socketRead0.implementation = function(fd,bytearray,int1,int2,int3){
            var result = this.socketRead0(fd,bytearray,int1,int2,int3)
            console.log("socketRead0 fd,bytearray,int1,int2,int3,result =>",fd,bytearray,int1,int2,int3,result)
            console.log(ByteString.of(bytearray).hex());
            return result;
        }
    })
}

function hook_sslsocket(){
    Java.perform(function(){
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

setImmediate(hook_sslsocket)