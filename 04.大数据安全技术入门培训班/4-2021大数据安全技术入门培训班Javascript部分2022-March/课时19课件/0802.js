function a(){
    try {
        throw new Error("123")
    }catch (e){
        console.log(e.stack)
    }
}
a()
    ["constructor"]("debu" + "gger")["apply"]("stateObject");
