
function jhexdump(array,off,len) {
    var ptr = Memory.alloc(array.length);
    for(var i = 0; i < array.length; ++i)
        Memory.writeS8(ptr.add(i), array[i]);
    //console.log(hexdump(ptr, { offset: off, length: len, header: false, ansi: false }));
    console.log(hexdump(ptr, { offset: 0, length: array.length, header: false, ansi: false }));
}

/*
HTTP
java.net.InetSocketAddress.InetSocketAddress(www.baidu.com/180.101.49.12, 80)
java.net.InetSocketAddress$InetSocketAddressHolder.InetSocketAddress$InetSocketAddressHolder((none), www.baidu.com/180.101.49.12, 80, (none))
java.net.InetSocketAddress.InetSocketAddress(/192.168.0.2, 43066)
java.net.InetSocketAddress$InetSocketAddressHolder.InetSocketAddress$InetSocketAddressHolder((none), /192.168.0.2, 43066, (none))
java.net.SocketInputStream.SocketInputStream(Socket[addr=www.baidu.com/180.101.49.12,port=80,localport=43066])
java.net.SocketOutputStream.SocketOutputStream(Socket[addr=www.baidu.com/180.101.49.12,port=80,localport=43066])
HTTPS
java.net.InetSocketAddress.InetSocketAddress(www.baidu.com/180.101.49.12, 443)
java.net.Socket$2.Socket$2(Socket[address=www.baidu.com/180.101.49.12,port=443,localPort=44405]) 
java.net.SocketInputStream.SocketInputStream(Socket[addr=www.baidu.com/180.101.49.12,port=443,localport=44405])
java.net.SocketOutputStream.SocketOutputStream(Socket[addr=www.baidu.com/180.101.49.12,port=443,localport=44405])
com.android.org.conscrypt.ConscryptFileDescriptorSocket.ConscryptFileDescriptorSocket(Socket[address=www.baidu.com/180.101.49.12,port=443,localPort=44405], www.baidu.com, 443, true, com.android.org.conscrypt.SSLParametersImpl@2ccad02)
com.android.org.conscrypt.OpenSSLSocketImpl.OpenSSLSocketImpl(Socket[address=www.baidu.com/180.101.49.12,port=443,localPort=44405], www.baidu.com, 443, true)
com.android.org.conscrypt.AbstractConscryptSocket.AbstractConscryptSocket(Socket[address=www.baidu.com/180.101.49.12,port=443,localPort=44405], www.baidu.com, 443, true)   
com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream.ConscryptFileDescriptorSocket$SSLOutputStream(SSL socket over Socket[address=www.baidu.com/180.101.49.12,port=443,localPort=44405])
com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream.ConscryptFileDescriptorSocket$SSLInputStream(SSL socket over Socket[address=www.baidu.com/180.101.49.12,port=443,localPort=44405])
*/

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
            //console.log("bytearray contents=>", ByteString.of(bytearry).hex())
            //console.log(jhexdump(bytearry,int1,int2));
            console.log(jhexdump(bytearry));
            return result;
        }
                
        Java.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream").read.overload('[B', 'int', 'int').implementation = function(bytearry,int1,int2){
            var result = this.read(bytearry,int1,int2);
            console.log("HTTPS read result,bytearry,int1,int2=>",result,bytearry,int1,int2)
            var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            //console.log("bytearray contents=>", ByteString.of(bytearry).hex())
            //console.log(jhexdump(bytearry,int1,int2));
            console.log(jhexdump(bytearry));
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
    hook_Address()
    hook_socket();
    hook_SSLsocketandroid8();
    //hook_SSLsocket2android10();
}
setImmediate(main)