navigator = {
    "platform":"123"
}
function decect (r, e) {
    var i = [];
    Object["getOwnPropertyDescriptor"] && i["push"](Object["getOwnPropertyDescriptor"](r, e));
    Object["getOwnPropertyDescriptors"] && i["push"](!!Object["getOwnPropertyDescriptors"](r)[e]);

    for (var a = 0; a < i["length"]; a++) if (i[a]) return true;

    return false;
}
console.log(decect(navigator,"platform"))
