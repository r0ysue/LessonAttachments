var inputstr = "123"
function encrypt(str){
    return str + Math.random()
}
var res = encrypt(inputstr)
console.log(res)
var key = inputstr + res
console.log(key)
