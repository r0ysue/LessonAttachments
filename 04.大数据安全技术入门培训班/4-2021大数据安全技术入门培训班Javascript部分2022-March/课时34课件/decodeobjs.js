var DTASlider = function DTASlider() {};

DTASlider["prototype"]['_0x371e68'] = new Date()["getTime"]();

DTASlider["prototype"]["reload"] = function () {
  this["_tl"] = [];
  this["_0xb8687a"] = ![];
};

DTASlider['prototype']["start"] = function () {
  this["_tl"] = [];
  this["_0xb8687a"] = ![];
  this["bindEvents"]();
};

DTASlider["prototype"]['process'] = function () {
  let _0x5834b3 = []["slice"]["call"](arguments),
      _0x648b37 = this['_0x24c517']();

  this["_tl"]["push"](_0x648b37(encodeURIComponent(_0x5834b3["join"](','))));
};

DTASlider["prototype"]['_0x8ac94c'] = function (_0xcfd4c9) {
  return String["fromCharCode"]["call"](String, _0xcfd4c9 + 100);
};

DTASlider["prototype"]["app"] = function () {
  const _0x1a0ab9 = "DTA2021#" + this['_tl']["join"]('*');

  window["verify"](_0x1a0ab9);
};

DTASlider["prototype"]["_0x24c517"] = function () {
  return function (_0x59e12a) {
    let _0x430729 = {
      '_0x64ddc': "XmYj3u1PnvisIZUF8ThR/a6DfO+kW4JHrCELycAzSxleoQp02MtwV9Nd57qGgbKB=",
      'encode': function (_0x7b546a) {
        if (!_0x7b546a) return !1;

        var _0x200f40 = '',
            _0x45946f,
            _0x3a3f7a,
            _0x5d70e9,
            _0x55d3d7,
            _0x40145f,
            _0x5ca8f1,
            _0x3b82a0,
            _0x588eb4 = 0;

        do {
          const _0x1e9472 = "3|2|8|7|4|6|0|5|1"["split"]('|');

          let _0xb09342 = 0;

          while (!![]) {
            switch (_0x1e9472[_0xb09342++]) {
              case '0':
                _0x3b82a0 = 63 & _0x5d70e9;
                continue;

              case '1':
                _0x200f40 += this['_0x64ddc']["charAt"](_0x55d3d7) + this["_0x64ddc"]["charAt"](_0x40145f) + this['_0x64ddc']["charAt"](_0x5ca8f1) + this['_0x64ddc']["charAt"](_0x3b82a0);
                continue;

              case '2':
                _0x3a3f7a = _0x7b546a["charCodeAt"](_0x588eb4++);
                continue;

              case '3':
                _0x45946f = _0x7b546a["charCodeAt"](_0x588eb4++);
                continue;

              case '4':
                _0x40145f = (3 & _0x45946f) << 4 | _0x3a3f7a >> 4;
                continue;

              case '5':
                if (isNaN(_0x3a3f7a)) _0x5ca8f1 = _0x3b82a0 = 64;else {
                  if (isNaN(_0x5d70e9)) _0x3b82a0 = 64;
                }
                continue;

              case '6':
                _0x5ca8f1 = (15 & _0x3a3f7a) << 2 | _0x5d70e9 >> 6;
                continue;

              case '7':
                _0x55d3d7 = _0x45946f >> 2;
                continue;

              case '8':
                _0x5d70e9 = _0x7b546a["charCodeAt"](_0x588eb4++);
                continue;
            }

            break;
          }
        } while (_0x588eb4 < _0x7b546a["length"]);

        return _0x200f40;
      },
      'decode': function (_0x400559) {
        {
          if (!_0x400559) return !1;
          _0x400559 = _0x400559["replace"](/[^A-Za-z0-9\+\/\=]/g, '');

          var _0x1c7989 = '',
              _0x3f0f7e,
              _0x472dcf,
              _0x2d485d,
              _0x4c703c,
              _0xc6d1cb = 0;

          do {
            this["_0x49f4fe"] = [];
            this["_0xb8687a"] = ![];
            this["_0x1b2ad1"]();
            {
              const _0x5e634c = "5|3|2|6|0|1|4"["split"]('|');

              let _0x15c51b = 0;

              while (!![]) {
                switch (_0x5e634c[_0x15c51b++]) {
                  case '0':
                    _0x1c7989 += String["fromCharCode"](_0x3f0f7e << 2 | _0x472dcf >> 4);
                    continue;

                  case '1':
                    if (64 != _0x2d485d) _0x1c7989 += String["fromCharCode"]((15 & _0x472dcf) << 4 | _0x2d485d >> 2);
                    continue;

                  case '2':
                    _0x2d485d = this["_0x64ddc"]['indexOf'](_0x400559['charAt'](_0xc6d1cb++));
                    continue;

                  case '3':
                    _0x472dcf = this["_0x64ddc"]['indexOf'](_0x400559["charAt"](_0xc6d1cb++));
                    continue;

                  case '4':
                    if (64 != _0x4c703c) _0x1c7989 += String["fromCharCode"]((3 & _0x2d485d) << 6 | _0x4c703c);
                    continue;

                  case '5':
                    _0x3f0f7e = this["_0x64ddc"]["indexOf"](_0x400559["charAt"](_0xc6d1cb++));
                    continue;

                  case '6':
                    _0x4c703c = this['_0x64ddc']["indexOf"](_0x400559["charAt"](_0xc6d1cb++));
                    continue;
                }

                break;
              }
            }
          } while (_0xc6d1cb < _0x400559["length"]);

          return _0x1c7989;
        }
      }
    };
    return _0x430729['encode'](_0x59e12a);
  };
};

DTASlider['prototype']["bindEvents"] = function () {
  document["querySelector"]("#slideVerify > div > div > div")["addEventListener"]('mousemove', _0x1b7074 => {
    if (!this["_0xb8687a"]) return ![];

    const _0x623857 = parseInt(_0x1b7074["clientX"] - this["_0x29f896"]),
          _0x44a94d = parseInt(_0x1b7074['clientY'] - this["_0x422805"]),
          _0x2f4f5e = new Date()["getTime"]() - this["_0x371e68"],
          _0x33a72f = _0x1b7074["target"]["className"];

    if (_0x623857 < 0 || _0x623857 + 38 >= this['w']) return ![];
    document["querySelector"](".slide-verify-slider-mask-item")["style"]["left"] = _0x623857 + 'px';
    document["querySelector"](".slide-verify-block")["style"]["left"] = _0x623857 + 'px';
    document["querySelector"](".slide-verify-slider-mask")["style"]["width"] = _0x623857 + 'px';
    this["process"](this["_0x8ac94c"](_0x623857), this["_0x8ac94c"](_0x44a94d), this['_0x8ac94c'](_0x2f4f5e), _0x33a72f);
  });
  document["querySelector"]("#slideVerify > div > div > div")["addEventListener"]("mouseup", _0x1b9bf6 => {
    if (!this["_0xb8687a"]) return ![];
    this["_0xb8687a"] = ![];
    if (_0x1b9bf6["clientX"] === this["_0x29f896"]) return ![];
    this["app"]();
  });
  document["querySelector"]("#slideVerify > div > div > div")["addEventListener"]("mousedown", _0x4fbf69 => {
    {
      const _0x4d4aa2 = "2|0|1|4|3"['split']('|');

      let _0x5711d5 = 0;

      while (!![]) {
        switch (_0x4d4aa2[_0x5711d5++]) {
          case '0':
            this["_0x29f896"] = _0x4fbf69["clientX"];
            continue;

          case '1':
            this['_0x422805'] = _0x4fbf69['clientY'];
            continue;

          case '2':
            if (this["_0x5040ec"]) return;
            continue;

          case '3':
            this["_0x371e68"] = +new Date();
            continue;

          case '4':
            this['_0xb8687a'] = !![];
            continue;
        }

        break;
      }
    }
  });
  document["querySelector"]("#slideVerify > div > div > div")["addEventListener"]("touchstart", _0x391c45 => {
    {
      const _0x4fe9ee = "3|2|4|1|0"["split"]('|');

      let _0x109f0d = 0;

      while (!![]) {
        switch (_0x4fe9ee[_0x109f0d++]) {
          case '0':
            this['_0x371e68'] = +new Date();
            continue;

          case '1':
            this['_0xb8687a'] = !![];
            continue;

          case '2':
            this["_0x29f896"] = _0x391c45["changedTouches"][0]['pageX'];
            continue;

          case '3':
            if (this["_0x5040ec"]) return;
            continue;

          case '4':
            this["_0x422805"] = _0x391c45["changedTouches"][0]["pageY"];
            continue;
        }

        break;
      }
    }
  });
  document["querySelector"]("#slideVerify > div > div > div")["addEventListener"]("touchmove", _0x4ac6b6 => {
    {
      if (!this["_0xb8687a"]) return ![];

      const _0x36219b = parseInt(_0x4ac6b6["changedTouches"][0]["pageX"] - this["_0x29f896"]),
            _0x3d010b = parseInt(_0x4ac6b6["changedTouches"][0]["pageY"] - this["_0x422805"]),
            _0x3cb0ba = new Date()["getTime"]() - this['_0x371e68'],
            _0x3a0f26 = _0x4ac6b6["changedTouches"][0]["target"]['className'];

      if (_0x36219b < 0 || _0x36219b + 38 >= this['w']) return ![];
      document["querySelector"](".slide-verify-slider-mask-item")["style"]["left"] = _0x36219b + 'px';
      document["querySelector"](".slide-verify-block")["style"]["left"] = _0x36219b + 'px';
      document["querySelector"](".slide-verify-slider-mask")['style']["width"] = _0x36219b + 'px';
      this["process"](this["_0x8ac94c"](_0x36219b), this["_0x8ac94c"](_0x3d010b), this['_0x8ac94c'](_0x3cb0ba), _0x3a0f26);
    }
  });
  document["querySelector"]("#slideVerify > div > div > div")["addEventListener"]("touchend", _0x486e1c => {
    const _0x3c2913 = "4|2|5|0|1|3"["split"]('|');

    let _0x348a29 = 0;

    while (!![]) {
      switch (_0x3c2913[_0x348a29++]) {
        case '0':
          this["_0x256244"] = ![];
          continue;

        case '1':
          this["_0x371e68"] = +new Date() - this['_0x371e68'];
          continue;

        case '2':
          this["_0xb8687a"] = ![];
          continue;

        case '3':
          this["app"]();
          continue;

        case '4':
          if (!this["_0xb8687a"]) return ![];
          continue;

        case '5':
          if (_0x486e1c["changedTouches"][0]["pageX"] === this["_0x29f896"]) return ![];
          continue;
      }

      break;
    }
  });
};