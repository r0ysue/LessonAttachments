function _iIlllIII() {
  var _lIilIiiI = "YKycP1MsbDwFpVlE8r4u69aBI2veiNHCQ5LWnU0G";
  var _lIii1IiI = "6XgdS3YAN7hwbGlH";

  var _1IiIIiii = window["CryptoJS"]["enc"]["Utf8"]["parse"](_lIii1IiI);

  _lIilIiiI = window["CryptoJS"]["enc"]["Utf8"]["parse"](_lIilIiiI);

  var _Ii11IliI = window["CryptoJS"]["AES"]["encrypt"](_lIilIiiI, _1IiIIiii, {
    "mode": window["CryptoJS"]["mode"]["ECB"],
    "padding": window["CryptoJS"]["pad"]["Pkcs7"]
  });

  window["localStorage"]["authorization"] = _Ii11IliI["toString"]();
}

var _QQQ00o0Q = document["querySelector"]("#app > div > div > button");

if (_QQQ00o0Q && _QQQ00o0Q["textContent"] === "请求") {
  _iIlllIII();

  window["location"]["reload"]();
}