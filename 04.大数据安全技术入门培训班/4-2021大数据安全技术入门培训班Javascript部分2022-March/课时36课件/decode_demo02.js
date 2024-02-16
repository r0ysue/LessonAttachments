function _IilII1Ii() {
  var _oOoOOQ0O = document.head.getElementsByTagName("script");

  var _00OOooOQ = _oOoOOQ0O[_oOoOOQ0O.length - 1].src;

  var _ii1Iiil1 = new XMLHttpRequest();

  _ii1Iiil1.onreadystatechange = function () {
    if (_ii1Iiil1.readyState === 4 && _ii1Iiil1.status === 200) {
      var _oQoOQ0O0 = _ii1Iiil1.responseText;

      var _i1iliIi1 = CryptoJS.MD5(_oQoOQ0O0).toString().toUpperCase();

      window.ckjs = _i1iliIi1;
    }
  };

  _ii1Iiil1.open("GET", _00OOooOQ, !![]);

  _ii1Iiil1.send();
}

function _Il1lIIII() {
  var _OQOOQOQO = function (_o0Q0QO0Q, _OOQOQQOQ) {
    return _o0Q0QO0Q + _OOQOQQOQ;
  }(+new Date(), "");

  var _i1Ii1III = "";

  for (var _0QQQQOOo = 0; _0QQQQOOo < _OQOOQOQO.length - 1; _0QQQQOOo++) {
    _i1Ii1III += String.fromCharCode(_OQOOQOQO[_0QQQQOOo] + _OQOOQOQO[_0QQQQOOo + 1] ^ 30);
  }

  var _QQQQO000 = {};
  _QQQQO000.defaultStr = "unknown";
  _QQQQO000.defaultNum = -1;

  _QQQQO000.ab = function () {
    try {
      return !!window["localStorage"];
    } catch (_oO0OoQQQ) {
      return !![];
    }
  };

  _QQQQO000.adb = function () {
    var _Oo0OQQ0Q = document["createElement"]("div");

    _Oo0OQQ0Q["innerHTML"] = "&nbsp;", _Oo0OQQ0Q["className"] = "adsbox";

    var _1IIIIii1 = ![];

    try {
      document.body.appendChild(_Oo0OQQ0Q), _1IIIIii1 = 0 === document.getElementsByClassName("adsbox")[0]["offsetHeight"], document["body"].removeChild(_Oo0OQQ0Q);
    } catch (_ooQO0O0O) {
      _1IIIIii1 = ![];
    }

    return _1IIIIii1;
  };

  _QQQQO000.ar = function () {
    return [screen.availWidth || 0, screen.availHeight || 0]["join"](";");
  };

  _QQQQO000.can = function () {
    var _QQQQQQoo = document["createElement"]("canvas"),
        _lI1ilI1i = !(!_QQQQQQoo["getContext"] || !_QQQQQQoo.getContext("2d"));

    return _lI1ilI1i ? function () {
      var _IIiiiIli = "Path",
          _QOQ0OQQ0 = [],
          _1II1liIl = _QQQQQQoo["getContext"]("2d");

      return _QQQQQQoo.width = 2000, _QQQQQQoo["height"] = 200, _QQQQQQoo.style.display = "inline", _1II1liIl["rect"](0, 0, 10, 10), _1II1liIl.rect(2, 2, 6, 6), _QOQ0OQQ0.push("canvas winding:" + (![] === _1II1liIl.isPointInPath(5, 5, "evenodd") ? "yes" : "no")), _1II1liIl.textBaseline = "alphabetic", _1II1liIl["fillStyle"] = "#f60", _1II1liIl["fillRect"](125, 1, 62, 20), _1II1liIl.fillStyle = "#069", _1II1liIl["font"] = "11pt no-real-font-123", _1II1liIl["fillText"]("Cwm fjordbank glyphs vext quiz, ὠ3", 2, 15), _1II1liIl["fillStyle"] = "rgba(102, 204, 0, 0.2)", _1II1liIl.font = "18pt Arial", _1II1liIl["fillText"]("Cwm fjordbank glyphs vext quiz, ὠ3", 4, 45), _1II1liIl["globalCompositeOperation"] = "multiply", _1II1liIl.fillStyle = "rgb(255,0,255)", _1II1liIl.beginPath(), _1II1liIl.arc(50, 50, 50, 0, Math["PI"] * 2, true), _1II1liIl["closePath"](), _1II1liIl.fill(), _1II1liIl["fillStyle"] = "rgb(0,255,255)", _1II1liIl["beginPath"](), _1II1liIl["arc"](100, 50, 50, 0, Math.PI * 2, true), _1II1liIl["closePath"](), _1II1liIl["fill"](), _1II1liIl["fillStyle"] = "rgb(255,255,0)", _1II1liIl.beginPath(), _1II1liIl["arc"](75, 100, 50, 0, Math.PI * 2, true), _1II1liIl["closePath"](), _1II1liIl.fill(), _1II1liIl["fillStyle"] = "rgb(255,0,255)", _1II1liIl["arc"](75, 75, 75, 0, 2 * Math.PI, true), _1II1liIl["arc"](75, 75, 25, 0, 2 * Math["PI"], true), _1II1liIl["fill"]("evenodd"), _QQQQQQoo.toDataURL && _QOQ0OQQ0.push("canvas fp:" + _QQQQQQoo["toDataURL"]()), _QOQ0OQQ0["join"]("~");
    }() : _QQQQO000["defaultStr"];
  };

  _QQQQO000.cc = function () {
    return navigator["cpuClass"] || _QQQQO000.defaultStr;
  };

  _QQQQO000.cd = function () {
    return screen.colorDepth || _QQQQO000.defaultNum;
  };

  _QQQQO000.ce = function () {
    return "boolean" == typeof navigator["cookieEnabled"] ? navigator["cookieEnabled"] ? 1 : 0 : _QQQQO000.defaultNum;
  };

  _QQQQO000.cl = function () {
    return (document["cookie"] || "").split(";")["length"];
  };

  _QQQQO000.cpt = function () {
    var _IlliiiIl = ["video/mp4", "video/webm", "video/ogg", "video/3gpp\t", "video/x-matroska", "audio/mp4", "audio/mpeg", "audio/webm", "audio/ogg", "audio/wav", "audio/3gpp"],
        _II1i1i1l = document.createElement("video");

    return _II1i1i1l && _II1i1i1l.canPlayType ? _IlliiiIl.map(function (_Il1I1ii1) {
      return _II1i1i1l.canPlayType(_Il1I1ii1) || "";
    }).join(";") : _QQQQO000["defaultStr"];
  };

  _QQQQO000.dm = function () {
    return navigator["deviceMemory"] === undefined ? _QQQQO000["defaultNum"] : navigator["deviceMemory"];
  };

  _QQQQO000.hc = function () {
    return navigator.hardwareConcurrency || _QQQQO000.defaultNum;
  };

  _QQQQO000.hlb = function () {
    var _QQQQOQ0Q = {
      "getMatchValue": function () {
        for (var _iiIIIiII = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "", _QQoOO0OO = arguments[1], _QOQ0OQQO = 0; _QOQ0OQQO < _QQoOO0OO["length"]; _QOQ0OQQO++) {
          var _1ilIiilI = _QQoOO0OO[_QOQ0OQQO],
              _lIi11I11 = _1ilIiilI[0],
              _li1iIlIi = _1ilIiilI[1];

          for (var _Q000Q0OO = 0; _Q000Q0OO < _li1iIlIi.length; _Q000Q0OO++) if (_iiIIIiII["indexOf"](_li1iIlIi[_Q000Q0OO]) > -1) return _lIi11I11;
        }
      }
    };
    m = navigator["userAgent"].toLowerCase(), S = navigator.productSub;
    if (new RegExp("mobile", "i").test(m)) return ![];

    var _iIl1iIIi = (0, _QQQQOQ0Q["getMatchValue"])(m, [["Firefox", ["firefox", "fxios"]], ["Opera", ["opera", "opr"]], ["Chrome", ["chrome", "crios"]], ["Safari", "safari"], ["IE", "trident"]]) || "Other";

    if (new RegExp("^(Chrome|Safari|Opera)$")["test"](_iIl1iIIi) && "20030107" !== S) return !![];
    var _IIIiIlii = eval.toString()["length"];
    if (_IIIiIlii === 37 && !new RegExp("^(Safari|Firefox|Other)$")["test"](_iIl1iIIi)) return !![];
    if (_IIIiIlii === 39 && !new RegExp("^(IE|Other)$").test(_iIl1iIIi)) return !![];
    if (33 === _IIIiIlii && !new RegExp("^(Chrome|Opera|Other)$").test(_iIl1iIIi)) return !![];

    var _oQOo0OOQ = void 0;

    try {
      throw "a";
    } catch (_Q0OQQQQO) {
      try {
        _Q0OQQQQO.toSource(), _oQOo0OOQ = !![];
      } catch (_11il1i1i) {
        _oQOo0OOQ = ![];
      }
    }

    return !(!_oQOo0OOQ || new RegExp("^(Firefox|Other)$").test(_iIl1iIIi));
  };

  _QQQQO000.hlo = function () {
    var _QQQ0Oo0O = {
      "getMatchValue": function () {
        for (var _QQ0QoQoo = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "", _QQQQ0OQQ = arguments[1], _IIl1iIiI = 0; _IIl1iIiI < _QQQQ0OQQ["length"]; _IIl1iIiI++) {
          var _0QoOQQ00 = _QQQQ0OQQ[_IIl1iIiI],
              _OQOOOoQQ = _0QoOQQ00[0],
              _0QQOOOO0 = _0QoOQQ00[1];

          for (var _l1iIiIII = 0; _l1iIiIII < _0QQOOOO0.length; _l1iIiIII++) if (_QQ0QoQoo["indexOf"](_0QQOOOO0[_l1iIiIII]) > -1) return _OQOOOoQQ;
        }
      }
    };

    var _1iiliiIi = navigator["userAgent"]["toLowerCase"](),
        _O0OOoOQ0 = navigator["oscpu"],
        _0OO0oQQo = navigator["platform"]["toLowerCase"](),
        _IIiIi1i1 = (0, _QQQ0Oo0O["getMatchValue"])(_1iiliiIi, [["WindowsPhone", "windows phone"], ["Windows", "win"], ["Android", "android"], ["Linux", "linux"], ["iOS", ["iphone", "ipad"]], ["Mac", "mac"]]) || "Other";

    0;
    if (("ontouchstart" in window || navigator.maxTouchPoints > 0 || navigator.msMaxTouchPoints > 0) && !![] && !new RegExp("^(WindowsPhone|Android|iOS|Other)$").test(_IIiIi1i1)) return !![];

    if (void 0 !== _O0OOoOQ0) {
      if ((_O0OOoOQ0 = _O0OOoOQ0.toLowerCase()).indexOf("win") >= 0 && _IIiIi1i1 !== "Windows" && "WindowsPhone" !== _IIiIi1i1) return !![];
      if (_O0OOoOQ0.indexOf("linux") >= 0 && "Linux" !== _IIiIi1i1 && _IIiIi1i1 !== "Android") return !![];
      if (_O0OOoOQ0.indexOf("mac") >= 0 && _IIiIi1i1 !== "Mac" && "iOS" !== _IIiIi1i1) return !![];
      if ((-1 === _O0OOoOQ0.indexOf("win") && -1 === _O0OOoOQ0["indexOf"]("linux") && _O0OOoOQ0["indexOf"]("mac") === -1) != ("Other" === _IIiIi1i1)) return !![];
    }

    return _0OO0oQQo["indexOf"]("win") >= 0 && _IIiIi1i1 !== "Windows" && _IIiIi1i1 !== "WindowsPhone" || (_0OO0oQQo["indexOf"]("linux") >= 0 || _0OO0oQQo.indexOf("android") >= 0 || _0OO0oQQo["indexOf"]("pike") >= 0) && "Linux" !== _IIiIi1i1 && _IIiIi1i1 !== "Android" || ((_0OO0oQQo.indexOf("mac") >= 0 || _0OO0oQQo["indexOf"]("ipad") >= 0 || _0OO0oQQo.indexOf("ipod") >= 0 || _0OO0oQQo["indexOf"]("iphone") >= 0) && _IIiIi1i1 !== "Mac" && "iOS" !== _IIiIi1i1 ? !![] : (-1 === _0OO0oQQo["indexOf"]("win") && -1 === _0OO0oQQo.indexOf("linux") && -1 === _0OO0oQQo["indexOf"]("mac")) != (_IIiIi1i1 === "Other") || "undefined" == typeof navigator["plugins"] && _IIiIi1i1 !== "Windows" && "Windows Phone" !== _IIiIi1i1 && !![]);
  };

  _QQQQO000.hll = function () {
    if ("undefined" != typeof navigator["languages"]) try {
      if (navigator.languages[0].substr(0, 2) !== navigator["language"].substr(0, 2)) return !![];
    } catch (_iiiIIIIi) {
      return !![];
    }
    return ![];
  };

  _QQQQO000.hlr = function () {
    return window["screen"]["width"] < window.screen.availWidth || window["screen"]["height"] < window.screen.availHeight;
  };

  _QQQQO000.ind = function () {
    try {
      return !!window.indexedDB;
    } catch (_II11llil) {
      return !![];
    }
  }() ? 1 : 0;
  _QQQQO000.ls = function () {
    try {
      return !!window["localStorage"];
    } catch (_1IIlIIIl) {
      return !![];
    }
  }() ? 1 : 0;

  _QQQQO000.mts = function () {
    var _QOQQQoOQ = {};

    _QOQQQoOQ.map = function (_lilii1iI, _IIilIilI) {
      for (var _QQQ0oOQO = [], _o00Q00O0 = 0; _o00Q00O0 < _lilii1iI["length"]; _o00Q00O0++) _QQQ0oOQO.push(_IIilIilI(_lilii1iI[_o00Q00O0], _o00Q00O0, _lilii1iI));

      return _QQQ0oOQO;
    };

    return navigator["mimeTypes"] && navigator["mimeTypes"].length ? (0, _QOQQQoOQ["map"])(navigator.mimeTypes, function (_ooOQOO0O) {
      return _ooOQOO0O.type + ":" + _ooOQOO0O.suffixes;
    })["join"](";") : _QQQQO000.defaultStr;
  };

  _QQQQO000.np = navigator.platform || _QQQQO000.defaultStr;
  _QQQQO000.od = window["openDatabase"] ? 1 : 0;
  _QQQQO000.pr = window.devicePixelRatio || _QQQQO000["defaultNum"];
  _QQQQO000.res = [screen.width || 0, screen["height"] || 0]["join"](";");
  _QQQQO000.ss = function () {
    try {
      return !!window["sessionStorage"];
    } catch (_1I111IIi) {
      return !![];
    }
  }() ? 1 : 0;

  _QQQQO000.to = function () {
    return new Date().getTimezoneOffset();
  };

  _QQQQO000.ts = function () {
    var _ilIIii1l = 0,
        _11iIIii1 = ![];

    "undefined" != typeof navigator["maxTouchPoints"] ? _ilIIii1l = navigator.maxTouchPoints : "undefined" != typeof navigator["msMaxTouchPoints"] && (_ilIIii1l = navigator["msMaxTouchPoints"]);

    try {
      document["createEvent"]("TouchEvent"), _11iIIii1 = !![];
    } catch (_iilIi1i1) {}

    return [_ilIIii1l, _11iIIii1, "ontouchstart" in window].join(";");
  };

  _QQQQO000.ua = navigator["userAgent"] || _QQQQO000["defaultStr"];
  _QQQQO000.web = function () {
    var _iIIiIlil = document["createElement"]("canvas"),
        _QQ0oQQQQ = !(!_iIIiIlil.getContext || !_iIIiIlil["getContext"]("2d"));

    if (!_QQ0oQQQQ) return ![];

    function _OoQOQ0QO() {
      var _OQ0Oo0Qo = document["createElement"]("canvas"),
          _i1Iiil11 = null;

      try {
        _i1Iiil11 = _OQ0Oo0Qo["getContext"]("webgl") || _OQ0Oo0Qo["getContext"]("experimental-webgl");
      } catch (_iiiiliII) {}

      return _i1Iiil11 || (_i1Iiil11 = null), _i1Iiil11;
    }

    var _iI11IlIi = _OoQOQ0QO();

    return !!window["WebGLRenderingContext"] && !!_iI11IlIi;
  }() ? function () {
    var _OQQoOOoO = void 0,
        _11i1lIli = function (_Qo0OQOOO) {
      var _O0oQQQQQ = "DEPTH_TE";
      return _OQQoOOoO.clearColor(0, 0, 0, 1), _OQQoOOoO.enable(_OQQoOOoO["DEPTH_TEST"]), _OQQoOOoO["depthFunc"](_OQQoOOoO.LEQUAL), _OQQoOOoO["clear"](_OQQoOOoO["COLOR_BUFFER_BIT"] | _OQQoOOoO["DEPTH_BUFFER_BIT"]), "[" + _Qo0OQOOO[0] + ", " + _Qo0OQOOO[1] + "]";
    };

    function _O0OQ0oOO() {
      var _iIIlliil = document["createElement"]("canvas"),
          _OooQ00Oo = null;

      try {
        _OooQ00Oo = _iIIlliil["getContext"]("webgl") || _iIIlliil["getContext"]("experimental-webgl");
      } catch (_II1iiII1) {}

      return _OooQ00Oo || (_OooQ00Oo = null), _OooQ00Oo;
    }

    if (!(_OQQoOOoO = _O0OQ0oOO())) return "unknown";

    var _QQ0OoOQQ = [],
        _OQQQoOOO = "attribute vec2 attrVertex;varying vec2 varyinTexCoordinate;uniform vec2 uniformOffset;void main(){varyinTexCoordinate=attrVertex+uniformOffset;gl_Position=vec4(attrVertex,0,1);}",
        _iilii1ii = "precision mediump float;varying vec2 varyinTexCoordinate;void main() {gl_FragColor=vec4(varyinTexCoordinate,0,1);}",
        _oQOOQO0O = _OQQoOOoO.createBuffer();

    _OQQoOOoO.bindBuffer(_OQQoOOoO["ARRAY_BUFFER"], _oQOOQO0O);

    var _OQOOOQoQ = new Float32Array([-0, -0, 0, 0.4, -0.26, 0, 0, 0.732134444, 0]);

    _OQQoOOoO["bufferData"](_OQQoOOoO["ARRAY_BUFFER"], _OQOOOQoQ, _OQQoOOoO.STATIC_DRAW), _oQOOQO0O.itemSize = 3, _oQOOQO0O["numItems"] = 3;

    var _oQOOQQOQ = _OQQoOOoO.createProgram(),
        _111II1iI = _OQQoOOoO.createShader(_OQQoOOoO.VERTEX_SHADER);

    _OQQoOOoO.shaderSource(_111II1iI, _OQQQoOOO), _OQQoOOoO.compileShader(_111II1iI);

    var _liIiIi1i = _OQQoOOoO["createShader"](_OQQoOOoO.FRAGMENT_SHADER);

    _OQQoOOoO["shaderSource"](_liIiIi1i, _iilii1ii), _OQQoOOoO["compileShader"](_liIiIi1i), _OQQoOOoO.attachShader(_oQOOQQOQ, _111II1iI), _OQQoOOoO.attachShader(_oQOOQQOQ, _liIiIi1i), _OQQoOOoO["linkProgram"](_oQOOQQOQ), _OQQoOOoO["useProgram"](_oQOOQQOQ), _oQOOQQOQ["vertexPosAttrib"] = _OQQoOOoO["getAttribLocation"](_oQOOQQOQ, "attrVertex"), _oQOOQQOQ.offsetUniform = _OQQoOOoO.getUniformLocation(_oQOOQQOQ, "uniformOffset"), _OQQoOOoO["enableVertexAttribArray"](_oQOOQQOQ["vertexPosArray"]), _OQQoOOoO["vertexAttribPointer"](_oQOOQQOQ["vertexPosAttrib"], _oQOOQO0O["itemSize"], _OQQoOOoO["FLOAT"], ![], 0, 0), _OQQoOOoO["uniform2f"](_oQOOQQOQ.offsetUniform, 1, 1), _OQQoOOoO["drawArrays"](_OQQoOOoO.TRIANGLE_STRIP, 0, _oQOOQO0O["numItems"]);

    try {
      _QQ0OoOQQ["push"](_OQQoOOoO.canvas.toDataURL());
    } catch (_I1IiiIiI) {}

    _QQ0OoOQQ.push("extensions:" + (_OQQoOOoO.getSupportedExtensions() || [])["join"](";")), _QQ0OoOQQ.push("webgl aliased line width range:" + _11i1lIli(_OQQoOOoO["getParameter"](_OQQoOOoO.ALIASED_LINE_WIDTH_RANGE))), _QQ0OoOQQ["push"]("webgl aliased point size range:" + _11i1lIli(_OQQoOOoO.getParameter(_OQQoOOoO["ALIASED_POINT_SIZE_RANGE"]))), _QQ0OoOQQ["push"]("webgl alpha bits:" + _OQQoOOoO["getParameter"](_OQQoOOoO.ALPHA_BITS)), _QQ0OoOQQ["push"]("webgl antialiasing:" + (_OQQoOOoO["getContextAttributes"]()["antialias"] ? "yes" : "no")), _QQ0OoOQQ["push"]("webgl blue bits:" + _OQQoOOoO["getParameter"](_OQQoOOoO.BLUE_BITS)), _QQ0OoOQQ["push"]("webgl depth bits:" + _OQQoOOoO.getParameter(_OQQoOOoO["DEPTH_BITS"])), _QQ0OoOQQ["push"]("webgl green bits:" + _OQQoOOoO.getParameter(_OQQoOOoO.GREEN_BITS)), _QQ0OoOQQ["push"]("webgl max anisotropy:" + function (_oQ0oOO0O) {
      var _Ilil1lli = _oQ0oOO0O.getExtension("EXT_texture_filter_anisotropic") || _oQ0oOO0O.getExtension("WEBKIT_EXT_texture_filter_anisotropic") || _oQ0oOO0O["getExtension"]("MOZ_EXT_texture_filter_anisotropic");

      if (_Ilil1lli) {
        var _QQO0Q0oO = _oQ0oOO0O["getParameter"](_Ilil1lli.MAX_TEXTURE_MAX_ANISOTROPY_EXT);

        return 0 === _QQO0Q0oO && (_QQO0Q0oO = 2), _QQO0Q0oO;
      }

      return null;
    }(_OQQoOOoO)), _QQ0OoOQQ["push"]("webgl max combined texture image units:" + _OQQoOOoO.getParameter(_OQQoOOoO["MAX_COMBINED_TEXTURE_IMAGE_UNITS"])), _QQ0OoOQQ["push"]("webgl max cube map texture size:" + _OQQoOOoO["getParameter"](_OQQoOOoO.MAX_CUBE_MAP_TEXTURE_SIZE)), _QQ0OoOQQ.push("webgl max fragment uniform vectors:" + _OQQoOOoO.getParameter(_OQQoOOoO.MAX_FRAGMENT_UNIFORM_VECTORS)), _QQ0OoOQQ["push"]("webgl max render buffer size:" + _OQQoOOoO.getParameter(_OQQoOOoO["MAX_RENDERBUFFER_SIZE"])), _QQ0OoOQQ.push("webgl max texture image units:" + _OQQoOOoO["getParameter"](_OQQoOOoO.MAX_TEXTURE_IMAGE_UNITS)), _QQ0OoOQQ["push"]("webgl max texture size:" + _OQQoOOoO.getParameter(_OQQoOOoO.MAX_TEXTURE_SIZE)), _QQ0OoOQQ["push"]("webgl max varying vectors:" + _OQQoOOoO.getParameter(_OQQoOOoO.MAX_VARYING_VECTORS)), _QQ0OoOQQ["push"]("webgl max vertex attribs:" + _OQQoOOoO.getParameter(_OQQoOOoO["MAX_VERTEX_ATTRIBS"])), _QQ0OoOQQ["push"]("webgl max vertex texture image units:" + _OQQoOOoO["getParameter"](_OQQoOOoO["MAX_VERTEX_TEXTURE_IMAGE_UNITS"])), _QQ0OoOQQ.push("webgl max vertex uniform vectors:" + _OQQoOOoO.getParameter(_OQQoOOoO.MAX_VERTEX_UNIFORM_VECTORS)), _QQ0OoOQQ.push("webgl max viewport dims:" + _11i1lIli(_OQQoOOoO["getParameter"](_OQQoOOoO.MAX_VIEWPORT_DIMS))), _QQ0OoOQQ.push("webgl red bits:" + _OQQoOOoO["getParameter"](_OQQoOOoO.RED_BITS)), _QQ0OoOQQ["push"]("webgl renderer:" + _OQQoOOoO["getParameter"](_OQQoOOoO.RENDERER)), _QQ0OoOQQ.push("webgl shading language version:" + _OQQoOOoO["getParameter"](_OQQoOOoO.SHADING_LANGUAGE_VERSION)), _QQ0OoOQQ["push"]("webgl stencil bits:" + _OQQoOOoO["getParameter"](_OQQoOOoO["STENCIL_BITS"])), _QQ0OoOQQ.push("webgl vendor:" + _OQQoOOoO.getParameter(_OQQoOOoO["VENDOR"])), _QQ0OoOQQ.push("webgl version:" + _OQQoOOoO.getParameter(_OQQoOOoO["VERSION"]));

    try {
      var _ii1I1iil = _OQQoOOoO.getExtension("WEBGL_debug_renderer_info");

      _ii1I1iil && (_QQ0OoOQQ.push("webgl unmasked vendor:" + _OQQoOOoO.getParameter(_ii1I1iil["UNMASKED_VENDOR_WEBGL"])), _QQ0OoOQQ.push("webgl unmasked renderer:" + _OQQoOOoO.getParameter(_ii1I1iil.UNMASKED_RENDERER_WEBGL)));
    } catch (_QOOQOQQO) {}

    return _OQQoOOoO["getShaderPrecisionFormat"] ? (["FLOAT", "INT"].forEach(function (_OOoO0QoO) {
      ["VERTEX", "FRAGMENT"].forEach(function (_QO0QQOQO) {
        var _1IliI1II = "M";
        ["HIGH", "MEDIUM", "LOW"].forEach(function (_Oo0QOOOo) {
          var _oOOoOQQO = "則剧",
              _QOOoQ0o0 = "&@";
          ["precision", "rangeMin", "rangeMax"].forEach(function (_lIIliIIi) {
            var _O00QOoOo = _OQQoOOoO.getShaderPrecisionFormat(_OQQoOOoO[_QO0QQOQO + "_SHADER"], _OQQoOOoO[_Oo0QOOOo + "_" + _OOoO0QoO])[_lIIliIIi];

            "precision" !== _lIIliIIi && (_lIIliIIi = "precision " + _lIIliIIi);
            var _IlIIli1i = ["webgl ", _QO0QQOQO.toLowerCase(), " shader ", _Oo0QOOOo["toLowerCase"](), " ", _OOoO0QoO["toLowerCase"](), " ", _lIIliIIi, ":", _O00QOoOo];

            _QQ0OoOQQ["push"](_IlIIli1i["join"](""));
          });
        });
      });
    }), _QQ0OoOQQ["join"]("~")) : _QQ0OoOQQ["join"]("~");
  } : _QQQQO000.defaultStr;

  _QQQQO000.gi = function () {
    function _1ilIIii1() {
      var _iiIIiilI = document["createElement"]("canvas"),
          _1I11Il1l = null;

      try {
        _1I11Il1l = _iiIIiilI["getContext"]("webgl") || _iiIIiilI["getContext"]("experimental-webgl");
      } catch (_liI1ilii) {}

      return _1I11Il1l || (_1I11Il1l = null), _1I11Il1l;
    }

    var _lIIII11l = _1ilIIii1();

    if (!_lIIII11l) return _QQQQO000.defaultStr;

    var _oO00Qo0Q = _lIIII11l["getExtension"]("WEBGL_debug_renderer_info");

    return [_lIIII11l.getParameter(_oO00Qo0Q["UNMASKED_VENDOR_WEBGL"]), _lIIII11l["getParameter"](_oO00Qo0Q.UNMASKED_RENDERER_WEBGL)].join(";");
  };

  _QQQQO000.hl = history.length || 0;

  _QQQQO000.vs = function () {
    var _iil1IlIl = document.documentElement || document.body;

    return [window["innerWidth"] || (_iil1IlIl ? _iil1IlIl.clientWidth : 0), window["innerHeight"] || (_iil1IlIl ? _iil1IlIl["clientHeight"] : 0)].join(";");
  };

  _QQQQO000.ws = function () {
    return [window["outerWidth"], window["outerHeight"]]["join"](";");
  };

  localStorage["sign"] = btoa(_i1Ii1III);
  var _OQoQoQ0O = {
    ab: _QQQQO000.ab(),
    adb: _QQQQO000.adb(),
    ar: _QQQQO000.ar(),
    can: _QQQQO000.can(),
    cc: _QQQQO000.cc(),
    cd: _QQQQO000.cd(),
    ce: _QQQQO000.ce(),
    cl: _QQQQO000.cl(),
    cpt: _QQQQO000.cpt(),
    dm: _QQQQO000.dm(),
    hc: _QQQQO000.hc(),
    hlb: _QQQQO000.hlb(),
    hlo: _QQQQO000.hlo(),
    hll: _QQQQO000.hll(),
    hlr: _QQQQO000.hlr(),
    ind: _QQQQO000.ind,
    ls: _QQQQO000.ls,
    mts: _QQQQO000.mts(),
    np: _QQQQO000.np,
    od: _QQQQO000.od,
    pr: _QQQQO000.pr,
    res: _QQQQO000.res,
    ss: _QQQQO000.ss,
    to: _QQQQO000.to(),
    ts: _QQQQO000.ts(),
    ua: _QQQQO000.ua,
    web: _QQQQO000.web(),
    gi: _QQQQO000.gi(),
    hl: _QQQQO000.hl,
    vs: _QQQQO000.vs(),
    ws: _QQQQO000.ws(),
    t: _OQOOQOQO,
    ckjs: window.ckjs
  };
  zlib.gzip(JSON.stringify(_OQoQoQ0O), function (_ililiIli, _iliIIIIi) {
    window._signature = _iliIIIIi.toString("base64");
  });
}

function m() {
  _Il1lIIII();

  _IilII1Ii();
}

setInterval(m, 3000);