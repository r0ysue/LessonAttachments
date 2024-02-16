var now = new Date().getTime();
var timeArray = []
for (let i = 0; i < 100 ; i++) {
    timeArray.push(Math.random() * 1000)
}
//console.log(timeArray)

function huakuai(){
    var O = new Date().getTime()
    function slide(){
        console.log(new Date().getTime() - O)
    }
    return slide
}
var hk = huakuai()
function go(timeArray){
    for (let i = 0; i < timeArray.length; i++) {
        Date.prototype.getTime = function (){
            return now + timeArray[i]
        }
        hk()
    }
}
go(timeArray)