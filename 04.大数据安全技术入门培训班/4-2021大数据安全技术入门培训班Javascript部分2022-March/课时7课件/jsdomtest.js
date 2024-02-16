const jsdom = require("jsdom");
const { JSDOM } = jsdom;

const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>大数据安全技术学习</title>
</head>
<style>
    #first{
        color: red;
    }
    .last{
        color: blue;
    }
</style>
<body>
<p id="first">大数据安全技术学习1</p>
<p>大数据安全技术学习2</p>
<p>大数据安全技术学习3</p>
<p class="last">大数据安全技术学习4</p>
</body>
</html>`
const dom = new JSDOM(html);
const { document } = (dom).window;
var first = document.getElementById("first");
var last = document.getElementsByClassName("last");
first.innerHTML = "我改变了大数据安全技术学习1";
last[0].innerHTML = "我也改变了大数据安全技术学习4"

var ptags = document.getElementsByTagName('p');
for (const ptagsKey in ptags) {
    console.log(ptags[ptagsKey].innerHTML)
}


