// # (agent) [2xhzmmkxx1r] Called com.fanwe.live.common.CommonInterface.requestIndex(int, int, int, java.lang.String, com.fanwe.hybrid.http.AppRequestCallback)
// (agent) [2xhzmmkxx1r] Backtrace:                                                  
//         com.fanwe.live.common.CommonInterface.requestIndex(Native Method)
//         com.fanwe.live.appview.main.LiveTabHotView.requestData(LiveTabHotView.java:390)
//         com.fanwe.live.appview.main.LiveTabHotView.onLoopRun(LiveTabHotView.java:382)
//         com.fanwe.live.appview.main.LiveTabBaseView$1.run(LiveTabBaseView.java:116)
//         com.fanwe.lib.looper.impl.SDSimpleLooper$1.handleMessage(SDSimpleLooper.java:54)
//         android.os.Handler.dispatchMessage(Handler.java:106)
//         android.os.Looper.loop(Looper.java:164)
//         android.app.ActivityThread.main(ActivityThread.java:6494)
//         java.lang.reflect.Method.invoke(Native Method)
//         com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:438)
//         com.android.internal.os.ZygoteInit.main(ZygoteInit.java:807)

// (agent) [2xhzmmkxx1r] Arguments com.fanwe.live.common.CommonInterface.requestIndex(1, (none), (none), 热门, com.fanwe.live.appview.main.LiveTabHotView$4@89cbef4)
// (agent) [2xhzmmkxx1r] Return Value: (none)

function inspect(obj) {
    Java.perform(function () {
        const Class = Java.use("java.lang.Class");

        const obj_class = Java.cast(obj.getClass(), Class);
        const fields = obj_class.getDeclaredFields();
        const methods = obj_class.getMethods();
        console.log("Inspecting " + obj.getClass().toString());
        console.log("\tFields:");
        for (var i in fields){
            // console.log("\t\t" + fields[i].toString());
            var className = obj_class.toString().trim().split(" ")[1] ;
            // console.log("className is => ",className);
            var trim = fields[i].toString().split(className.concat(".")).pop() ; 
            console.log(trim + " => ",obj[trim].value);
            
        }
            
    
        console.log("\tMethods:");
        // for (var i in methods)
            // console.log("\t\t" + methods[i].toString());
    })
}



function hook() {
    Java.perform(function () {
        var JSON = Java.use("com.alibaba.fastjson.JSON")
        var Index_indexActModel = Java.use("com.fanwe.live.model.Index_indexActModel");
        var gson = Java.use("com.google.gson.Gson").$new();
        var LiveRoomModel = Java.use("com.fanwe.live.model.LiveRoomModel");
        Java.use("com.fanwe.live.appview.main.LiveTabHotView$4").onSuccess.implementation = function (resp) {
            console.log("Entering Room List Parser => ", resp)
            var result = resp.getDecryptedResult();
            var resultModel = JSON.parseObject(result, Index_indexActModel.class);
            var roomList = Java.cast(resultModel, Index_indexActModel).getList();
            console.log("size : ", roomList.size(), roomList.get(0))
            for (var i = 0; i < roomList.size(); i++) {
                var LiveRoomModelInfo = Java.cast(roomList.get(i), LiveRoomModel);
                console.log("roominfo: ", i, " ", gson.toJson(LiveRoomModelInfo));
            }
            return this.onSuccess(resp)
        }
    })
}



function hookROOMinfo() {
    Java.perform(function () {
        var JSON = Java.use("com.alibaba.fastjson.JSON")
        var gson = Java.use("com.google.gson.Gson").$new();
        var App_get_videoActModel = Java.use("com.fanwe.live.model.App_get_videoActModel");

        Java.use("com.fanwe.live.business.LiveBusiness$2").onSuccess.implementation = function (resp) {
            console.log("Enter LiveBusiness$2 ... ", resp)
            var result = resp.getDecryptedResult();
            var resultVideoModel = JSON.parseObject(result, App_get_videoActModel.class);
            var roomDetail = Java.cast(resultVideoModel, App_get_videoActModel);
            inspect(roomDetail);
            return this.onSuccess(resp);
        }
    })

}
function invoke() {

    Java.perform(function () {
        Java.choose("com.fanwe.live.appview.main.LiveTabHotView", {
            onMatch: function (ins) {
                console.log("found ins => ", ins)
                ins.requestData();
            }, onComplete: function () {
                console.log("Search completed!")
            }
        })
    })

}

function invokeROOMInfo(){
    Java.perform(function(){
        Java.choose("com.fanwe.live.business.LiveBusiness",{
            onMatch:function(ins){
                console.log("found ins => ",ins)
            },onComplete:function(){
                console.log("search completed!")
            }
        })
    })
}

function invokeROOMInfo2(){
    Java.perform(function(){
        var ILive = Java.use("com.fanwe.live.activity.room.ILiveActivity")

        const ILiveImpl = Java.registerClass({
            name: "com.fanwe.live.activity.room.ILiveActivityImpl",
            implements: [ILive],
            methods: {
                openSendMsg() {},
                getCreaterId(){},
                getGroupId(){},
                getRoomId(){},
                getRoomInfo(){},
                getSdkType(){},
                isAuctioning(){},
                isCreater(){},
                isPlayback(){},
                isPrivate(){}
            }
          });
        
        var LiveBusiness =  Java.use("com.fanwe.live.business.LiveBusiness").$new(Java.cast(ILiveImpl.$new,ILive) );
        console.log("invoke LiveBusiness resule => ",LiveBusiness.requestRoomInfo("12345"))
    })
}


var lastLiveBusiness = null;
console.log("Original lastLiveBusiness = > ",lastLiveBusiness)
function hookROOMInfo3(){
    Java.perform(function(){
        Java.use("com.fanwe.live.business.LiveBusiness").getLiveQualityData.implementation = function(){
            lastLiveBusiness = this;
            console.log("lastLiveBusiness => ",lastLiveBusiness)
            this.requestRoomInfo(Java.use("java.lang.String").$new("123454"));
            return this.getLiveQualityData()
        }

    })
}

function invokeROOMInfo3(){
    Java.perform(function(){
        var result = lastLiveBusiness.requestRoomInfo(Java.use("java.lang.String").$new("123454"));
        console.log("result is => ",result)
    })
}



function main() {
    // hook2()
    hookROOMinfo()
    // hookROOMInfo3()
    // invoke()
}

setImmediate(main)