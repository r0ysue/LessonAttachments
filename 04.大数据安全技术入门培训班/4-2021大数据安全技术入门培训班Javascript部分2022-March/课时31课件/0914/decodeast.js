const fs = require("fs")
const parser = require("@babel/parser")
const generator = require("@babel/generator").default
const traverse = require("@babel/traverse").default
const types = require("@babel/types")
const template = require("@babel/template")

const code = fs.readFileSync("./ob.js", {"encoding": "utf-8"})
const ast = parser.parse(code)

const visitor = {
    // VariableDeclarator: function (path){
    //     let name = path.node.id.name
    //     let value = path.node.init.value
    //     let binding = path.scope.getBinding(name)
    //     if (!binding){
    //         return
    //     }
    //     let {constant, referencePaths} = binding
    //     if (!constant || !value){
    //         return
    //     }
    //     for (const referencePath of referencePaths) {
    //         // let VariableDeclaratorPath = referencePath.findParent(p=>p.isVariableDeclarator())
    //         // if(VariableDeclaratorPath){
    //         //     referencePath.replaceInline(types.valueToNode(value))
    //         // }
    //         referencePath.replaceInline(types.valueToNode(value))
    //     }
    // },
    CallExpression: function (path){
        const {confident, value} = path.evaluate()
        console.log(path.toString())
        if(confident){
            path.replaceInline(types.valueToNode(value))
        }
    }
}

traverse(ast, visitor);



const output = generator(ast).code
fs.writeFileSync("decodeob.js", output, {"encoding": "utf-8"})
