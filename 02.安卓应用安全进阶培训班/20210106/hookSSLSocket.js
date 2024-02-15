// com.android.org.conscrypt.SslWrapper.write(java.io.FileDescriptor, [B, int, int, int)
// com.android.org.conscrypt.SslWrapper.read(java.io.FileDescriptor, [B, int, int, int)
// com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream.read([B, int, int)
// com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream.write([B, int, int)



function jhexdump(array,off,len) {
    var ptr = Memory.alloc(array.length);
    for(var i = 0; i < array.length; ++i)
        Memory.writeS8(ptr.add(i), array[i]);
    console.log(hexdump(ptr, { offset: off, length: len, header: false, ansi: false }));
    // console.log(hexdump(ptr, { offset: 0, length: array.length, header: false, ansi: false }));
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
            // console.log(jhexdump(bytearry));
            
            console.log(this.socket.value.getLocalAddress().toString())
            console.log(this.socket.value.getLocalPort())
            console.log(this.socket.value.getRemoteSocketAddress().toString())
            console.log(this.socket.value.getPort())
            
            return result;
        }
        

        Java.use("java.net.SocketInputStream").read.overload('[B', 'int', 'int').implementation = function(bytearry,int1,int2){
            var result = this.read(bytearry,int1,int2);
            console.log("HTTP read result,bytearry,int1,int2=>",result,bytearry,int1,int2)
            var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            //console.log("bytearray contents=>", ByteString.of(bytearry).hex())
            //console.log(jhexdump(bytearry,int1,int2));
            // console.log(jhexdump(bytearry));

            console.log(this.socket.value.getLocalAddress().toString())
            console.log(this.socket.value.getLocalPort())
            console.log(this.socket.value.getRemoteSocketAddress().toString())
            console.log(this.socket.value.getPort())

            console.log(this.socket.value.getImpl());



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
            // var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            //console.log("bytearray contents=>", ByteString.of(bytearry).hex())
            //console.log(jhexdump(bytearry,int1,int2));
            // console.log(jhexdump(bytearry,int1,int2));
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
            return result;
        }
        
        Java.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream").read.overload('[B', 'int', 'int').implementation = function(bytearry,int1,int2){
            var result = this.read(bytearry,int1,int2);
            console.log("HTTPS read result,bytearry,int1,int2=>",result,bytearry,int1,int2)
            // var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            //console.log("bytearray contents=>", ByteString.of(bytearry).hex())
            //console.log(jhexdump(bytearry,int1,int2));
            // console.log(jhexdump(bytearry,0,result));
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
            return result;
        }
    })
}


function main(){
    console.log("Main")
    // hook_socket();
    hook_SSLsocketandroid8();
    
}
setImmediate(main)