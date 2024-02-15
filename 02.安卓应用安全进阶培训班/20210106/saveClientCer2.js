/*
 // 合成p12证书
    public static void storeP12(PrivateKey pri, String p7, String p12Path, String p12Password) throws Exception {

        CertificateFactory factory = CertificateFactory.getInstance("X509");
        //初始化证书链
        X509Certificate p7X509 = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(p7.getBytes()));
        Certificate[] chain = new Certificate[]{p7X509};
        // 生成一个空的p12证书
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, null);
        // 将服务器返回的证书导入到p12中去
        ks.setKeyEntry("client", pri, p12Password.toCharArray(), chain);
        // 加密保存p12证书
        FileOutputStream fOut = new FileOutputStream(p12Path);
        ks.store(fOut, p12Password.toCharArray());
    }
*/


// function dumpP12(privateKey,cert,certPath,certPasspord){
//     var String = Java.use("java.lang.String");
//     JavacertPasspord = String.$new(certPasspord);
//     Java.perform(function(){
//         var KeyStore = Java.use("java.security.KeyStore");

//     })
// }


// setImmediate(function(){
//     Java.perform(function(){
//         console.log("Begin!")
//         Java.use("java.security.KeyStore$PrivateKeyEntry").getCertificateChain.implementation = function(){
//             console.log("Inside java.security.KeyStore$PrivateKeyEntry is => ",this.toString())
//             console.log("Inside java.security.KeyStore$PrivateKeyEntry.getPrivateKey() is => ",this.getPrivateKey().toString())

//             return this.getCertificateChain();            
//         }
//     })
// })


setImmediate(function(){
    Java.perform(function(){
        console.log("Begin!")
        Java.use("java.security.KeyStore$PrivateKeyEntry").$init.overload('java.security.PrivateKey', '[Ljava.security.cert.Certificate;').implementation = function(p,c){
            console.log("Inside java.security.KeyStore$PrivateKeyEntry is => ",this.toString())
            // console.log("Inside java.security.KeyStore$PrivateKeyEntry.getPrivateKey() is => ",this.getPrivateKey().toString())

            return this.$init(p,c);            
        }
        Java.use("java.security.KeyStore$PrivateKeyEntry").$init.overload('java.security.PrivateKey', '[Ljava.security.cert.Certificate;', 'java.util.Set').implementation = function(p,c,s){
            console.log("Inside java.security.KeyStore$PrivateKeyEntry is => ",this.toString())
            // console.log("Inside java.security.KeyStore$PrivateKeyEntry.getPrivateKey() is => ",this.getPrivateKey().toString())

            return this.$init(p,c,s);            
        }
    })
})