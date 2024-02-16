const fs = require("fs")
const parser = require("@babel/parser")
const generator = require("@babel/generator").default
const traverse = require("@babel/traverse").default
const types = require("@babel/types")
const template = require("@babel/template")

const code = fs.readFileSync("./decode_code.js", {"encoding": "utf-8"})
const ast = parser.parse(code)




const visitor = {
    "StringLiteral": function (path){
        let node = path.node
        let raw = node?.extra?.raw
        if (!raw){
            return
        }
        delete node.extra.raw
    }
}

traverse(ast, visitor);


const visitor2 = {
    "BinaryExpression": {
        enter: function (path){
            const {confident, value} = path.evaluate()
            if(confident){
                path.replaceInline(types.valueToNode(value))
            }
            console.log(path.toString())
        }
    }

}

traverse(ast, visitor2);

const output = generator(ast,{jsescOption: {minimal: true}}).code
fs.writeFileSync("decodeCode.js", output, {"encoding": "utf-8"})
