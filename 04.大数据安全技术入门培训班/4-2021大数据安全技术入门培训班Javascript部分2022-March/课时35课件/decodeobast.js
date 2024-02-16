const fs = require("fs")
const parser = require("@babel/parser")
const generator = require("@babel/generator").default
const traverse = require("@babel/traverse").default
const types = require("@babel/types")
const template = require("@babel/template")

const code = fs.readFileSync("./objs.js", {"encoding": "utf-8"})
const ast = parser.parse(code)

const _0x57a7 = ['_0x2ddb76', '_0x449894', '172220xZeecZ', '_0x24c517', '_0x3f7bec', 'slice', 'target', 'bindEvents', '_0x3f10c4', 'call', '_0x4d474c', '_0x2d8905', 'width', '_0x18143d', '_0x1799b5', '_0x218cdb', '_0x556f16', '_0x16fbfc', '-mask-item', '_0x64ddc', '2|0|1|4|3', 'charAt', '_0x6f1942', '\x20div\x20>\x20div', '3|2|1|6|0|', '_0xcd72b6', 'prototype', '_0x1516fd', '_0x49f4fe', 'push', '2|4|3|1|5|', '_0x5040ec', 'length', 'left', 'gbKB=', 'SxleoQp02M', 'unSCU', '1641027OaimBY', '32RYWBRR', 'mouseup', '_0x29ef3c', 'stener', 'addEventLi', '_0x44c54d', '_0x41abe2', '_0xb8687a', '_0x4c5d03', '_0x10933c', 'MtYqS', '_0x256244', '_0x46ebc6', '_0x5127e8', 'pageY', '_0x8ac94c', '1483562UZXwAU', '_0xa33447', '5|4', '_0x5ba68e', '_0x44fdcf', '_0x1355cf', '_0x2ff68b', '_0x5d5817', 'start', 'twV9Nd57qG', 'reload', '_0x5ad6b2', '1nIenzm', 'PVhmC', '_0x3bc5ef', '_0x3e5db0', '_0x318e8e', '_0x441b2d', '_0x188357', '306107lOqHwE', 'JHrCELycAz', 'FliWd', 'ify-slider', 'tor', '658251ggaqoj', 'split', 'querySelec', 'className', '_0x3b0a57', '.slide-ver', '6|0|5|1', '_0x2c89b9', '_0x5a5a0e', '_0x288e71', 'clientX', '_0x39b26d', '_0x3fba9d', 'WvvVy', '_0x422805', '_0x433fd6', 'pageX', '_0x10753b', '_0x1a8dc3', '_0x12f7e4', '#slideVeri', 'replace', '3|2|8|7|4|', 'touchmove', 'verify', '_0x5c3eb5', '_0x30cac0', 'join', '_0x126db8', '_0x1b4b78', 'DTA2021#', 'process', 'XmYj3u1Pnv', '_0x3682ba', '_0x18a4c4', 'ches', 'qxHkG', 'indexOf', 'touchstart', '_0x371e68', 'mousedown', '_0x226d4c', '/a6DfO+kW4', 'changedTou', '_0x9f916a', 'charCodeAt', '_tl', '_0x475baa', '_0x1a58ad', '_0x543d00', '13602DISgjb', '_0x29f896', '_0x59330d', '_0x4fd937', '_0x1cefcc', 'ify-block', '_0x178335', '_0x4b3f22', '_0x287183', 'isIZUF8ThR', '-mask', '_0x4c0a00', '_0x1b2ad1', 'wcDSj', '543698QcDXFB', '2LumIyv', '1|4', 'NHBJk', 'fromCharCo', '6|0', 'app', '_0x1479a9', 'style', 'getTime', '_0x2ffaa9', '_0x447c96', 'touchend', '_0x4102cd', 'fy\x20>\x20div\x20>', '_0x35e0f1'];

function _0x3462(_0x48e4e, _0xe715a5) {
  return _0x3462 = function (_0x7f5512, _0x1a605c) {
    _0x7f5512 = _0x7f5512 - (0x1 * 0xaa2 + -0x2bb * -0x7 + -0x1c4b);
    let _0x2e3675 = _0x57a7[_0x7f5512];
    return _0x2e3675;
  }, _0x3462(_0x48e4e, _0xe715a5);
}

(function (_0x5d8f08, _0x215a76) {
  const _0x20fa16 = _0x3462;
  while (!![]) {
    try {
      const _0x346121 = -parseInt(_0x20fa16('0x195')) * -parseInt(_0x20fa16('0x1ed')) + -parseInt(_0x20fa16(0x1a6)) + parseInt(_0x20fa16('0x1f2')) + parseInt(_0x20fa16(0x1da)) + parseInt(_0x20fa16('0x1ca')) * parseInt(_0x20fa16(0x186)) + -parseInt(_0x20fa16('0x1c9')) + parseInt(_0x20fa16('0x194')) * -parseInt(_0x20fa16(0x1e6));
      if (_0x346121 === _0x215a76) break; else _0x5d8f08['push'](_0x5d8f08['shift']());
    } catch (_0x3e10d4) {
      _0x5d8f08['push'](_0x5d8f08['shift']());
    }
  }
}(_0x57a7, -0x87523 + 0x6d84a + 0xe5033));

const obfuncname = "_0x3462"

const standardIfStatement = {
    IfStatement: function (path){
        let consequent_path = path.get("consequent")
        let alternate_path = path.get("alternate")
        if(!consequent_path.isBlockStatement()){
            consequent_path.replaceInline(types.blockStatement([consequent_path.node]))
        }else if(!alternate_path.isBlockStatement()){
            alternate_path.replaceInline(types.blockStatement([alternate_path.node]))
        }
    }
}
traverse(ast, standardIfStatement);


const changeFunctoVar = {
    FunctionDeclaration: function (path){
        let id, init;
        id = path.node.id
        init = types.FunctionExpression(id,path.node.params,path.node.body)
        let declarations = [types.variableDeclarator(id, init)]
        path.replaceInline(types.variableDeclaration("var", declarations))
    }
}
traverse(ast, changeFunctoVar);


const renameFunc = {
    VariableDeclarator: function (path){
        let {id} = path.node
        path.scope.traverse(path.scope.block, {
            "VariableDeclarator": function (_path){
                if(types.isIdentifier(_path.node.init, {name: id.name})){
                    _path.scope.rename(_path.node.id.name, id.name)
                    _path.remove()
                    _path.scope.crawl()
                }
            }
        })
    }
}
traverse(ast, renameFunc);


const retCallExpression = {
    CallExpression: function (path){
        let {callee} = path.node
        if(callee.name !== obfuncname){
            return
        }
        try{
            let value = eval(path.toString())
            path.replaceInline(types.valueToNode(value))
        }catch{

        }
    }
}
traverse(ast, retCallExpression);


const constantFold = {
    "BinaryExpression|UnaryExpression": {
        enter: function (path){
            const {confident, value} = path.evaluate()
            if(confident){
                path.replaceInline(types.valueToNode(value))
            }
        }
    }

}
traverse(ast, constantFold);


const deleteSequenceExpression = {
    "SequenceExpression" : function (path){
        let {expressions} = path.node
        let Statement = path.getStatementParent()
        for (const expression of expressions) {
            Statement.insertBefore(types.ExpressionStatement(expression))
            path.scope.crawl()
        }
        path.remove()
    }
}
traverse(ast, deleteSequenceExpression);


const reductionObjectKV = {
    VariableDeclarator: function (path){
        let {id, init} = path.node
        if(!types.isObjectExpression(init)){
            return
        }
        let AllNextblings = path.parentPath.getAllNextSiblings()
        for (const Nextbling of AllNextblings) {
            if(!Nextbling.isExpressionStatement()){
                continue
            }
            let {expression} = Nextbling.node
            if(!types.isAssignmentExpression(expression)){
                continue
            }
            let {left, right} = expression
            if (!types.isMemberExpression(left)){
                continue
            }
            let objname = left.object.name
            if (objname !== id.name){
                continue
            }
            let obj = types.ObjectProperty(left.property,right)
            init.properties.push(obj)
            Nextbling.remove()
        }
        path.scope.crawl()
    }
}
traverse(ast, reductionObjectKV);


function saveObjectKV(Objmap, objProperties){
    for (const objProperty of objProperties) {
        let {key, value} = objProperty
        if (types.isStringLiteral(value)){
            Objmap.set(key.value, value.value)
        }else if(types.isFunctionExpression(value)){
            let body = value.body.body
            if (body.length!==1 || !types.isReturnStatement(body[0])){
                continue
            }
            let argument = body[0].argument
            if(types.isCallExpression(argument)){
                Objmap.set(key.value, "CallExpression")
            }else if(types.isBinaryExpression(argument)){
                Objmap.set(key.value, argument.operator)
            }else{
                console.log(generator(objProperty).code)
            }
        }

    }

}

function replaceObjectKV(newMap, referPaths, scope){
    for (const referPath of referPaths) {
        let {node, parent, parentPath} = referPath;
        let ancestorPath = parentPath.parentPath;
        if (!parentPath.isMemberExpression({object: node})) {
            continue;
        }
        let {property} = parent;
        let propKey = property.value;
        let propValue = newMap.get(propKey);
        if (!propValue) {
            continue;
        }
        if (ancestorPath.isCallExpression({callee: parent})) {
            let {arguments} = ancestorPath.node;
            switch (propValue) {
                case "CallExpression":
                    ancestorPath.replaceInline(types.CallExpression(arguments[0], [arguments[1]]))
                    break
                default:
                    ancestorPath.replaceInline(types.BinaryExpression(propValue, arguments[0], arguments[1]))
            }
        } else {
            parentPath.replaceInline(types.valueToNode(propValue))
        }
        scope.crawl()
    }
}

const decodeObject = {
    VariableDeclarator: function (path){
        let {id, init} = path.node
        if (!types.isObjectExpression(init)){
            return
        }
        let objname = id.name
        let scope = path.scope
        let Objmap = new Map()
        let objProperties = init.properties
        if (objProperties.length === 0){
            return;
        }
        let referPaths = scope.getBinding(objname).referencePaths
        saveObjectKV(Objmap, objProperties)
        if (Objmap.size !== objProperties.length){
            // console.log(path.toString())
            // return;
        }
        replaceObjectKV(Objmap, referPaths, scope)
    }
}
traverse(ast, decodeObject);

const deleteUnusedVar ={
    VariableDeclarator: function (path){
        let scope = path.scope
        let name = path.node.id.name
        let binding = scope.getBinding(name)
        if(!binding.referenced){
            path.remove()
        }
    }
}
traverse(ast, deleteUnusedVar);

const deleteUnusedIfStatement = {
    IfStatement: function (path){
        let test_path = path.get("test")
        let {consequent, alternate} = path.node
        const {confident, value} = test_path.evaluate()
        if(confident){
            if(value){
                path.replaceInline(consequent)
            }else{
                path.replaceInline(alternate)
            }
        }

    }
}
traverse(ast, deleteUnusedIfStatement);

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




const output = generator(ast).code
fs.writeFileSync("decodeobjs.js", output, {"encoding": "utf-8"})
