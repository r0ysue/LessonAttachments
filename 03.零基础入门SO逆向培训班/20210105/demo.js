setImmediate(function(){
    Java.perform(function(){
        Java.use("com.roysue.easyso1.MainActivity").onCreate.implementation = function(x){
            console.log("Entering onCreate!");
            return this.onCreate(x);
        }
        Java.use("com.roysue.easyso1.MainActivity").stringFromJNI.implementation = function(){
            var result = this.stringFromJNI();
            console.log("return value of stringFromJNI is => ",result);
            return result;
        }
    })
})