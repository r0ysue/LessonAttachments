function main() {
    Java.perform(function () {//只要是java的代码都要跑在Java.perform里面
        console.log("Entering Hook!")
        Java.use("com.example.junior.util.Utils").dip2px.implementation = function (context, float) {
            //return null;
            var result = this.dip2px(context, 100)
            console.log("context,float,result  ==> ", context, float, result);
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
            return 26;
        }
    })
}

function Screen() {
    Java.perform(function () {
        Java.use("android.widget.TextView").setText.overload('java.lang.CharSequence').implementation = function (text) {

            var javaString = Java.use("java.lang.String");
            var newString = javaString.$new("roysue")

            var result = null;
            var realText = String(text);
            console.log("real text is ==> ",realText);
            if (realText.indexOf("junior") >= 0) {
                var result = this.setText(newString);
                console.log("text,result ==> ", newString, result);
            } else {
                var result = this.setText(text);
                console.log("text,result ==> ", text, result);
            }

            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
            return result;
        }
    })
}

function Equals(){
    Java.perform(function(){
        Java.use("java.lang.String").equals.implementation = function(obj){
            var result = this.equals(obj);
            console.log("obj,result ==> ",obj,result);
            return result;
        }
    })
}

function sub(){
    Java.perform(function(){
        Java.use("com.example.junior.util.Arith").sub.overload('java.lang.String', 'java.lang.String').implementation = function(str1,str2){
            
            var javaString = Java.use("java.lang.String")
            var result = this.sub(str1,javaString.$new("2"));
            console.log("str1,str2,result==>",str1,str2,result)
            return javaString.$new("10");
        }
    })
}

setImmediate(sub)