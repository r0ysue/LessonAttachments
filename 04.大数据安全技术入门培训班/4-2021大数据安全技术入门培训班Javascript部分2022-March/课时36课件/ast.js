const fs = require("fs")
const parser = require("@babel/parser")
const generator = require("@babel/generator").default
const traverse = require("@babel/traverse").default
const types = require("@babel/types")
const template = require("@babel/template")

const code = fs.readFileSync("./demo02.js", {"encoding": "utf-8"})
const ast = parser.parse(code)
const visitor = {
    "StringLiteral": function (path){
        delete path.node.extra.raw
    },
    "BinaryExpression": function (path){
        const {confident, value} = path.evaluate()
        if(confident){
            path.replaceInline(types.valueToNode(value))
        }
    }
}

traverse(ast, visitor);

const output = generator(ast,{jsescOption:{minimal: true}}).code
fs.writeFileSync("decode_demo02.js", output, {"encoding": "utf-8"})
