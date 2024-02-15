var MainActivityHandle = null;
Java.perform(function(){
    var javaString = Java.use("java.lang.String")
    Java.choose("com.example.demoso1.MainActivity",{
        onMatch:function(instance){
            MainActivityHandle = instance;
        },onComplete(){}
    })
    console.log("MainActivityHandle is => ",MainActivityHandle)
}) 

function getRealClassName(object) {
    const objClass = Java.use("java.lang.Object").getClass.apply(object);
    return Java.use("java.lang.Class").getName.apply(objClass)
}

function hook(){
    Java.perform(function(){
        var MainActivity = Java.use("com.example.demoso1.MainActivity");
        MainActivity.method01.implementation = function(str){
            
            // > 写主动调用之前先hook，hook时就是一个主动调动
            // > 写hook时的主动调用，1000%是成功的！
            // > 如果其他时候的主动调用失败了？？那就去康康hook时的主动调用咋写
            var result = this.method01(str);
            console.log("result,str=> ",str,result);
            //console.log("str=> ",Object.getOwnPropertyNames(str));
            //console.log("result=> ",Object.getOwnPropertyNames(result));
            //console.log("str=> ",getRealClassName(str));
            //console.log("result=> ",getRealClassName(result));
            return result;
        }
    })
}

function fridamethod01(plaintext){
    var result;
    Java.perform(function(){
        var MainActivity = Java.use("com.example.demoso1.MainActivity");
        var javaString = Java.use("java.lang.String")
        result = MainActivity.method01(javaString.$new(plaintext))
    }) 
    return result;
}


function fridamethod02(ciphertext){
    var result;
    Java.perform(function(){
        var javaString = Java.use("java.lang.String")
        result = MainActivityHandle.method02(javaString.$new(ciphertext))   
    })
    return result;
}


function main(){
    //hook()
    
    console.log("fridamethod01 result is => ", fridamethod01("roysueiloveyou"))
    console.log("fridamethod02 result is => ", fridamethod02("05d98b7ba02009564b98f5fa11df140e"))
}
setImmediate(main)


rpc.exports={
    fridamethod01:fridamethod01,
    fridamethod02:fridamethod02,
}