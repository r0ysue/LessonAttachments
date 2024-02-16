(function() {
    'use strict';
    !function () {
        'use strict';
        var source = ['alert','decodeData','String.fromCharCode',
            'fromCharCode','base64decode','md5','decode','btoa','JSON.stringify',
            'MD5','RSA','AES','CryptoJS','encrypt',
            'strdecode',"encode",'decodeURIComponent','_t'];
        console.log("开始测试是否有解密函数");
        let realCtx, realName;
        function getRealCtx(ctx, funcName) {
            let parts = funcName.split(".");
            let realCtx = ctx;
            for(let i = 0; i < parts.length - 1; i++) {
                realCtx = realCtx[parts[i]];
            }
            return realCtx;
        }
        function getRealName(funcName) {
            let parts = funcName.split(".");
            return parts[parts.length - 1];
        }
        function test(ctx) {
            for(let i = 0; i < source.length; i++) {
                let f = source[i];
                let realCtx = getRealCtx(ctx, f);
                let realName = getRealName(f);
                let chars = realCtx[realName];
                if (chars != undefined){
                    console.log("发现可疑函数：", f);
                    console.log(chars);
                    console.log("---------------------");
                }else{
                    console.log("未发现：", f);
                }
            }
        }
        test(window);
    }();
})();
