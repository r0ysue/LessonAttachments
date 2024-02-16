const fs = require("fs")
const parser = require("@babel/parser")
const generator = require("@babel/generator").default
const traverse = require("@babel/traverse").default
const types = require("@babel/types")
const template = require("@babel/template")

const code = fs.readFileSync("./demo03.js", {"encoding": "utf-8"})
const ast = parser.parse(code)
const visitor = {
    "StringLiteral": function (path){
        if(path?.node?.extra?.raw){
            delete path.node.extra.raw
        }
    },
    "BinaryExpression|UnaryExpression": function (path){
        const {confident, value} = path.evaluate()
        if(confident){
            path.replaceInline(types.valueToNode(value))
        }
    }
}

traverse(ast, visitor);

const deleteControlFlow = {
    WhileStatement: function (path){
        let {test, body} = path.node
        if(!types.isBooleanLiteral(test, {value: true}) || body?.body?.length !==2){
            return
        }
        let switchbody = body.body[0]
        let breakbody = body.body[1]
        if(!types.isSwitchStatement(switchbody) || !types.isBreakStatement(breakbody)){
            return
        }
        let {cases, discriminant} = switchbody
        if(!types.isMemberExpression(discriminant)){
            return;
        }
        let {object, property} = discriminant
        if (!types.isUpdateExpression(property)){
            return;
        }
        let objBinding = path.scope.getBinding(object.name)
        let obj_init_path = objBinding.path
        let propBinding = path.scope.getBinding(property.argument.name)
        let prop_init_path = propBinding.path


        let obj_value = eval(obj_init_path.get("init").toString())
        let prop_value = prop_init_path.node.init.value

        let result_body = []
        for (let i = prop_value; i < obj_value.length ; i++) {
            let nowCase = cases[obj_value[i]]
            let {consequent} = nowCase
            for (const consequentElement of consequent) {
                if(types.isContinueStatement(consequentElement)){
                    continue
                }
                result_body.push(consequentElement)
            }
        }

        path.replaceInline(result_body)
        obj_init_path.remove()
        prop_init_path.remove()

    }
}
traverse(ast, deleteControlFlow);

const output = generator(ast,{jsescOption:{minimal: true}}).code
fs.writeFileSync("decode_demo03.js", output, {"encoding": "utf-8"})
