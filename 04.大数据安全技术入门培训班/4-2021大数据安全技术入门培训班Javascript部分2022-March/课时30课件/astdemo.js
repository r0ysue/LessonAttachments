const fs = require("fs")
const parser = require("@babel/parser")
const generator = require("@babel/generator").default
const traverse = require("@babel/traverse").default
const types = require("@babel/types")
const template = require("@babel/template")

const code = fs.readFileSync("./demo.js", {"encoding": "utf-8"})
const ast = parser.parse(code)

const splitStr = {
    "StringLiteral": function (path){
        let node = path.node
        let value =node.value
        if (value?.length <=3 ){
            return
        }
        let body = []
        while (value.length > 3){
            let RandomSplit = Math.floor(Math.random() * 2 + 1)
            let SplitStr = value.substr(0,RandomSplit)
            body.push(SplitStr)
            value = value.substr(RandomSplit)
        }
        if (value){
            body.push(value)
        }
        let source = ""
        body.forEach(value => {
            source += "'" + value + "'" + "+"
        })
        source = source.substr(0, source.length - 1)
        //path.replaceWithSourceString(source)
        const sourceNode = template.statement.ast(source);
        path.replaceInline(sourceNode);

    }
}

traverse(ast, splitStr);


function str2unicode(str){
    let result = ""
    for (let i = 0; i < str.length; i++) {
        let tmp = str.charCodeAt(i).toString(16)
        while (tmp.length < 4){
            tmp = "0" + tmp
        }
        result += "\\u" + tmp
    }
    return result
}
// str2unicode
const visitor = {
    "StringLiteral": function (path){
        let node = path.node
        let value =node.value
        let raw = node?.extra?.raw
        if (!raw){
            return
        }
        let unicodeValue = str2unicode(value)
        node.extra.raw = "'" + unicodeValue + "'"
    }
}

traverse(ast, visitor);


const output = generator(ast).code
fs.writeFileSync("decode_code.js", output, {"encoding": "utf-8"})
