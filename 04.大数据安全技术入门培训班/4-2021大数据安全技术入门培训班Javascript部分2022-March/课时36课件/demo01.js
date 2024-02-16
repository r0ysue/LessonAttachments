for (let i = 0; i < 999999; i++) {
    var msg = i + ""
    while (msg.length < 6){
        msg = "0" + msg
    }
    if(window.check0801(msg)){
        console.log(msg)
        break
    }

}
