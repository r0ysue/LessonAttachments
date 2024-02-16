var _push = Array.prototype.push
Array.prototype.push = function(){
    console.log(arguments)
    return _push.apply(this, arguments)
}
