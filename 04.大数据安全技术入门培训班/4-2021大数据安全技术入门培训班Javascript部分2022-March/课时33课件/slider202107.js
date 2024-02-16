function DTASlider(){}
DTASlider.prototype.tm = new Date().getTime()
DTASlider.prototype.reload = function (){
  this["_tl"] = []
  this.isMouseDown = false
}
DTASlider.prototype.start = function (){
  this["_tl"] = []
  this.isMouseDown = false
  this["bindEvents"]()
}
DTASlider.prototype.process = function (){
  let f = []["slice"]["call"](arguments);
  let bs = this.bs()
  this._tl.push(bs(encodeURIComponent(f.join(","))))
}
DTASlider.prototype.toStr = function (m){
  return String["fromCharCode"]["call"](String, (m + 100))
}
DTASlider.prototype.app = function (){
  const arr =  "DTA2021#" + this._tl.join('*')
  window.verify(arr)
}
DTASlider.prototype.bs = function (){
  return function (str){
      let Base64 = {
    base64: "XmYj3u1PnvisIZUF8ThR/a6DfO+kW4JHrCELycAzSxleoQp02MtwV9Nd57qGgbKB=",
    encode: function (t) {
        if (!t) return !1;
        var a = "";
        var o, e, r;
        var f, u, s, i;
        var n = 0;
        do {
            o = t.charCodeAt(n++);
            e = t.charCodeAt(n++);
            r = t.charCodeAt(n++);
            f = o >> 2;
            u = (3 & o) << 4 | e >> 4;
            s = (15 & e) << 2 | r >> 6;
            i = 63 & r;
            if (isNaN(e)) s = i = 64;
            else if (isNaN(r)) i = 64;
            a += this.base64.charAt(f) + this.base64.charAt(u) + this.base64.charAt(s) + this.base64.charAt(i);
        } while (n < t.length);
        return a;
    }, decode: function (t) {
        if (!t) return !1;
        t = t.replace(/[^A-Za-z0-9\+\/\=]/g, "");
        var r = "";
        var s, n, i, o;
        var e = 0;
        do {
            s = this.base64.indexOf(t.charAt(e++));
            n = this.base64.indexOf(t.charAt(e++));
            i = this.base64.indexOf(t.charAt(e++));
            o = this.base64.indexOf(t.charAt(e++));
            r += String.fromCharCode(s << 2 | n >> 4);
            if (64 != i) r += String.fromCharCode((15 & n) << 4 | i >> 2);
            if (64 != o) r += String.fromCharCode((3 & i) << 6 | o);
        } while (e < t.length);
        return r;
    }
}
      return Base64.encode(str)
  }
}
DTASlider.prototype.bindEvents = function (){
    document.querySelector("#slideVerify > div > div > div").addEventListener('mousemove', (e) => {
      if (!this.isMouseDown) return false
      const moveX = parseInt(e.clientX - this.originX)
      const moveY = parseInt(e.clientY - this.originY)
      const moveT = new Date().getTime() - this.tm
      const classname = e.target.className
      if (moveX < 0 || moveX + 38 >= this.w) return false

      document.querySelector(".slide-verify-slider-mask-item").style.left = moveX + 'px'
      document.querySelector(".slide-verify-block").style.left = moveX + 'px'
      document.querySelector(".slide-verify-slider-mask").style.width = moveX + 'px'
      this.process(
        this.toStr(moveX),
        this.toStr(moveY),
        this.toStr(moveT),
        classname
      )
    })
    document.querySelector("#slideVerify > div > div > div").addEventListener('mouseup', (e) => {
      if (!this.isMouseDown) return false
      this.isMouseDown = false
      if (e.clientX === this.originX) return false
      this.app()
    })
    document.querySelector("#slideVerify > div > div > div").addEventListener('mousedown', (event) => {
      if (this.success) return
      this.originX = event.clientX
      this.originY = event.clientY
      this.isMouseDown = true
      this.tm = +new Date()
    })
    document.querySelector("#slideVerify > div > div > div").addEventListener('touchstart', (e) => {
      if (this.success) return
      this.originX = e.changedTouches[0].pageX
      this.originY = e.changedTouches[0].pageY
      this.isMouseDown = true
      this.tm = +new Date()
    })
    document.querySelector("#slideVerify > div > div > div").addEventListener('touchmove', (e) => {
      if (!this.isMouseDown) return false
      const moveX = parseInt(e.changedTouches[0].pageX - this.originX)
      const moveY = parseInt(e.changedTouches[0].pageY - this.originY)
      const moveT = new Date().getTime() - this.tm
      const classname = e.changedTouches[0].target.className
      if (moveX < 0 || moveX + 38 >= this.w) return false
      document.querySelector(".slide-verify-slider-mask-item").style.left = moveX + 'px'
      document.querySelector(".slide-verify-block").style.left = moveX + 'px'
      document.querySelector(".slide-verify-slider-mask").style.width = moveX + 'px'
      let encrypt_trail = btoa(moveX + ',' + moveY + ',' + moveT)
      this.process(
        this.toStr(moveX),
        this.toStr(moveY),
        this.toStr(moveT),
        classname
      )
    })
    document.querySelector("#slideVerify > div > div > div").addEventListener('touchend', (e) => {
      if (!this.isMouseDown) return false
      this.isMouseDown = false
      if (e.changedTouches[0].pageX === this.originX) return false
      this.containerActive = false
      this.tm = +new Date() - this.tm
      this.app()
    })
  }
