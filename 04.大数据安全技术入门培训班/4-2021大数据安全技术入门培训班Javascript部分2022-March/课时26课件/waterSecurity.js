var WaterSecurity = function() {
    this.init()
};
WaterSecurity.prototype = {
    version: "2.1",
    init: function() {
        String.prototype.gblen = function() {
            for (var r = 0, e = 0; e < this.length; e++)
                this.charCodeAt(e) > 127 || 94 == this.charCodeAt(e) ? r += 2 : r++;
            return r
        }
    },
    encode: function(r) {
        if (this.print(r),
        "" == (r += ""))
            return "";
        (r = encodeURI(r).replace(/\+/g, "%2B")).gblen() % 2 != 0 && (r += "*"),
        this.print(r),
        r = this.parityTransposition(r),
        this.print(r);
        var e = this.version + this.utf16to8(this.base64encode(r));
        return this.print(e),
        e
    },
    print: function(r) {},
    parityTransposition: function(r) {
        for (var e = [], t = 0; t < r.length; t += 2)
            e.push(r[t + 1]),
            e.push(r[t]);
        return e = e.join("")
    },
    decode: function(r) {
        if (r += "",
        this.print(r),
        "" == r || "null" == r)
            return "[]";
        if (this.version) {
            if (r.substring(0, 3) !== this.version)
                return alert("加解密版本不一致！");
            r = r.substring(3, r.length)
        }
        var e = r.substring(r.length - 4)
          , t = r.substring(r.indexOf(e))
          , s = new Array;
        t = t.substring(4, t.length - 4);
        for (var h = {}, i = 0; 4 * i < t.length; i++) {
            o = t.substr(4 * i, 4);
            s[i] = o,
            h[o] = null
        }
        for (var n = this.getTagsPosition(r, s), a = 0, i = 0; i < n.length; i++) {
            var o, c = r.substring(a, n[i]);
            h[o = r.substr(n[i], 4)] = c,
            a = n[i] + 4
        }
        for (var u = [], i = 0; i < s.length; i++)
            u.push(h[s[i]]);
        return u = u.join(""),
        u = this.utf8to16(this.base64decode(u))
    },
    getTagsPosition: function(r, e) {
        var t = new Array;
        for (i = 0; i < e.length; i++)
            t[i] = r.indexOf(e[i]);
        return t.sort(function(r, e) {
            return r > e ? 1 : -1
        })
    },
    base64EncodeChars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    base64DecodeChars: new Array(-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1),
    base64encode: function(r) {
        var e, t, s, h, i, n;
        for (s = r.length,
        t = 0,
        e = []; t < s; ) {
            if (h = 255 & r.charCodeAt(t++),
            t == s) {
                e.push(this.base64EncodeChars.charAt(h >> 2)),
                e.push(this.base64EncodeChars.charAt((3 & h) << 4)),
                e.push("==");
                break
            }
            if (i = r.charCodeAt(t++),
            t == s) {
                e.push(this.base64EncodeChars.charAt(h >> 2)),
                e.push(this.base64EncodeChars.charAt((3 & h) << 4 | (240 & i) >> 4)),
                e.push(this.base64EncodeChars.charAt((15 & i) << 2)),
                e.push("=");
                break
            }
            n = r.charCodeAt(t++),
            e.push(this.base64EncodeChars.charAt(h >> 2)),
            e.push(this.base64EncodeChars.charAt((3 & h) << 4 | (240 & i) >> 4)),
            e.push(this.base64EncodeChars.charAt((15 & i) << 2 | (192 & n) >> 6)),
            e.push(this.base64EncodeChars.charAt(63 & n))
        }
        return e.join("")
    },
    base64decode: function(r) {
        var e, t, s, h, i, n, a;
        for (n = r.length,
        i = 0,
        a = []; i < n; ) {
            do {
                e = this.base64DecodeChars[255 & r.charCodeAt(i++)]
            } while (i < n && -1 == e);
            if (-1 == e)
                break;
            do {
                t = this.base64DecodeChars[255 & r.charCodeAt(i++)]
            } while (i < n && -1 == t);
            if (-1 == t)
                break;
            a.push(String.fromCharCode(e << 2 | (48 & t) >> 4));
            do {
                if (61 == (s = 255 & r.charCodeAt(i++)))
                    return a.join("");
                s = this.base64DecodeChars[s]
            } while (i < n && -1 == s);
            if (-1 == s)
                break;
            a.push(String.fromCharCode((15 & t) << 4 | (60 & s) >> 2));
            do {
                if (61 == (h = 255 & r.charCodeAt(i++)))
                    return a.join("");
                h = this.base64DecodeChars[h]
            } while (i < n && -1 == h);
            if (-1 == h)
                break;
            a.push(String.fromCharCode((3 & s) << 6 | h))
        }
        return a.join("")
    },
    utf16to8: function(r) {
        var e, t, s, h;
        for (e = [],
        s = r.length,
        t = 0; t < s; t++)
            (h = r.charCodeAt(t)) >= 1 && h <= 127 ? e.push(r.charAt(t)) : h > 2047 ? (e.push(String.fromCharCode(224 | h >> 12 & 15)),
            e.push(String.fromCharCode(128 | h >> 6 & 63)),
            e.push(String.fromCharCode(128 | h >> 0 & 63))) : (e.push(String.fromCharCode(192 | h >> 6 & 31)),
            e.push(String.fromCharCode(128 | h >> 0 & 63)));
        return e.join("")
    },
    utf8to16: function(r) {
        var e, t, s, h, i, n;
        for (e = [],
        s = r.length,
        t = 0; t < s; )
            switch ((h = r.charCodeAt(t++)) >> 4) {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
                e.push(r.charAt(t - 1));
                break;
            case 12:
            case 13:
                i = r.charCodeAt(t++),
                e.push(String.fromCharCode((31 & h) << 6 | 63 & i));
                break;
            case 14:
                i = r.charCodeAt(t++),
                n = r.charCodeAt(t++),
                e.push(String.fromCharCode((15 & h) << 12 | (63 & i) << 6 | (63 & n) << 0))
            }
        return e.join("")
    }
};
var waterSecurity = new WaterSecurity;

function decoderesult(r){
    var result = waterSecurity.decode(r)
    return result
}

function encodeparams(m){
    m = JSON.parse(m)
    for (const mKey in m) {
        m[mKey] || (m[mKey] = ""),
        "" == m[mKey] && 0 != m[mKey] || (m[mKey] = waterSecurity.encode(m[mKey]));
    }
    m.waterEncode = waterSecurity.encode("true")
    m.random = Math.random()
    return JSON.stringify(m)
}
