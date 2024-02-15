setImmediate(function () {
    Java.perform(function () {
        console.log("Entering")
        Java.use("java.security.KeyStore$PrivateKeyEntry").getPrivateKey.implementation = function () {
            console.log("Calling java.security.KeyStore$PrivateKeyEntry.getPrivateKey method ")
            var result = this.getPrivateKey()
            console.log("toString result is => ", result.toString())
            storeP12(this.getPrivateKey(),this.getCertificate(),'/data/local/tmp/soul'+uuid(10,16)+'.p12','hello');
            return result;
        }
        Java.use("java.security.KeyStore$PrivateKeyEntry").getCertificateChain.implementation = function () {
            console.log("Calling java.security.KeyStore$PrivateKeyEntry.getCertificateChain method ")
            var result = this.getCertificateChain()
            storeP12(this.getPrivateKey(),this.getCertificate(),'/data/local/tmp/soul'+uuid(10,16)+'.p12','hello');
            return result;
        }
    })
})

function storeP12(pri, p7, p12Path, p12Password) {
    var X509Certificate = Java.use("java.security.cert.X509Certificate")
    var p7X509 = Java.cast(p7, X509Certificate);
    var chain = Java.array("java.security.cert.X509Certificate", [p7X509])
    var ks = Java.use("java.security.KeyStore").getInstance("PKCS12", "BC");
    ks.load(null, null);
    ks.setKeyEntry("client", pri, Java.use('java.lang.String').$new(p12Password).toCharArray(), chain);
    try {
        var out = Java.use("java.io.FileOutputStream").$new(p12Path);
        ks.store(out, Java.use('java.lang.String').$new(p12Password).toCharArray())
    } catch (exp) {
        console.log(exp)
    }
}

// // 合成p12证书
// public static void storeP12(PrivateKey pri, String p7, String p12Path, String p12Password) throws Exception {
//     CertificateFactory factory = CertificateFactory.getInstance("X509");
//     //初始化证书链
//     X509Certificate p7X509 = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(p7.getBytes()));
//     Certificate[] chain = new Certificate[]{p7X509};
//     // 生成一个空的p12证书
//     KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
//     ks.load(null, null);
//     // 将服务器返回的证书导入到p12中去
//     ks.setKeyEntry("client", pri, p12Password.toCharArray(), chain);
//     // 加密保存p12证书
//     FileOutputStream fOut = new FileOutputStream(p12Path);
//     ks.store(fOut, p12Password.toCharArray());
// }
function uuid(len, radix) {
    var chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.split('');
    var uuid = [], i;
    radix = radix || chars.length;

    if (len) {
        // Compact form
        for (i = 0; i < len; i++) uuid[i] = chars[0 | Math.random() * radix];
    } else {
        // rfc4122, version 4 form
        var r;

        // rfc4122 requires these characters
        uuid[8] = uuid[13] = uuid[18] = uuid[23] = '-';
        uuid[14] = '4';

        // Fill in random data. At i==19 set the high bits of clock sequence as
        // per rfc4122, sec. 4.1.5
        for (i = 0; i < 36; i++) {
            if (!uuid[i]) {
                r = 0 | Math.random() * 16;
                uuid[i] = chars[(i == 19) ? (r & 0x3) | 0x8 : r];
            }
        }
    }

    return uuid.join('');
}