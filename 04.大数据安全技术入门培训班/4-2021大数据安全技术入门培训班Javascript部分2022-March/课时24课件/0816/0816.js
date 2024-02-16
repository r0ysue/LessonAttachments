function batchHook(HookObj, BlackList, WhiteList){
    if(!BlackList){
        BlackList = []
    }
    if(!WhiteList){
        WhiteList = []
    }
    function startHook(Descriptors, HookObj){
        for (const descriptorsKey in Descriptors) {
            let value = Descriptors[descriptorsKey]
            let rawFunc = value["value"]
            if(typeof rawFunc === "function"
                && value["writable"]
                && !BlackList.includes(descriptorsKey)
                && (WhiteList.length ? WhiteList.includes(descriptorsKey) : true))
            {
                console.log(descriptorsKey)
                rawFunc.hook(HookObj)
            }
        }
    }


    let HookObjDescriptors = Object.getOwnPropertyDescriptors(HookObj)
    if(HookObj.prototype){
        let HookObjPrototypeDescriptors = Object.getOwnPropertyDescriptors(HookObj.prototype)
        startHook(HookObjPrototypeDescriptors, HookObj.prototype)
    }
    startHook(HookObjDescriptors, HookObj)

}

batchHook(String, ["toString", "concat"], ["fromCharCode"])
