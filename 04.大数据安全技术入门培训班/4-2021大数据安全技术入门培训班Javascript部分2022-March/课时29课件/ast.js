const fs = require("fs")
const parser = require("@babel/parser")
const generator = require("@babel/generator").default
const traverse = require("@babel/traverse").default
const types = require("@babel/types")
const code = fs.readFileSync("demo.js", {"encoding": "utf-8"})
const ast = parser.parse(code)

const visitor = {
    "BinaryExpression": function (path){
        path.node.operator = "-"
    },
    "VariableDeclarator": function (path){
        let init_path = path.get("init")
        let {id, init} = path.node
        let name = id.name
        if(name === "d"){
            return
        }
        if(!types.isNumericLiteral(init)){
            return;
        }
        let value = init.value + "";
        init_path.replaceInline(types.StringLiteral(value))
    }
}

traverse(ast, visitor);


const output = generator(ast).code
fs.writeFileSync("decode_code.js", output, {"encoding": "utf-8"})
