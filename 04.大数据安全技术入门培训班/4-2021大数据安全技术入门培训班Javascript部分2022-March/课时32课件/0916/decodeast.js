const fs = require("fs")
const parser = require("@babel/parser")
const generator = require("@babel/generator").default
const traverse = require("@babel/traverse").default
const types = require("@babel/types")
const template = require("@babel/template")

const code = fs.readFileSync("outputdemo.js", {"encoding": "utf-8"})
const ast = parser.parse(code)

const decodeArray = {
    "MemberExpression": function (path){
        let {object, property} = path.node
        let name = object.name
        if(!types.isNumericLiteral(property)){
            return
        }
        let value = property.value
        let binding = path.scope.getBinding(name)
        if(!binding.constant){
            return;
        }
        let ArrayNode = binding?.path?.node?.init?.elements
        if (!ArrayNode){
            return;
        }
        path.replaceInline(ArrayNode[value])
        path.scope.crawl()
    }
}
//traverse(ast, decodeArray);

const decodeArray2 = {
    "VariableDeclarator": function (path){
        let {id, init} = path.node
        if(!types.isArrayExpression(init) || init.elements.length === 0){
            return
        }
        let binding = path.scope.getBinding(id.name)
        if (!binding.constant){
            return
        }
        for (const referencePath of binding.referencePaths) {
            let memberPath = referencePath.findParent(function (path){
                if(path.isMemberExpression() && path.get("property").isNumericLiteral()){
                    return path
                }
            })
            memberPath.replaceInline(init.elements[memberPath.node.property.value])
        }
        path.scope.crawl()
    }
}
traverse(ast, decodeArray2);

const deleteUnusedVar = {
    "VariableDeclarator": function (path){
        let id = path.node?.id?.name
        if(!id){return}
        let binding = path.scope.getBinding(id)
        if(!binding.referenced){
            path.remove()
        }
    }

}
traverse(ast, deleteUnusedVar);


const output = generator(ast).code
fs.writeFileSync("decodeoutputdemo.js", output, {"encoding": "utf-8"})
