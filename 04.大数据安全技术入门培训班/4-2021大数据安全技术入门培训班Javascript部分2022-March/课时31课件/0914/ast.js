const fs = require("fs")
const parser = require("@babel/parser")
const generator = require("@babel/generator").default
const traverse = require("@babel/traverse").default
const types = require("@babel/types")
const template = require("@babel/template")

const code = fs.readFileSync("./demo.js", {"encoding": "utf-8"})
const ast = parser.parse(code)

// const visitor = {
//     VariableDeclarator: function (path){
//         let name = path.node.id.name
//         let value = path.node.init.value
//         let binding = path.scope.getBinding(name)
//         if (!binding){
//             return
//         }
//         let {constant, referencePaths} = binding
//         if (!constant || !value){
//             return
//         }
//         for (const referencePath of referencePaths) {
//             // let VariableDeclaratorPath = referencePath.findParent(p=>p.isVariableDeclarator())
//             // if(VariableDeclaratorPath){
//             //     referencePath.replaceInline(types.valueToNode(value))
//             // }
//             referencePath.replaceInline(types.valueToNode(value))
//         }
//     }
// }
//
// traverse(ast, visitor);

function getRandomName(len){
    function randomString(e) {
      e = e || 32;
      var t = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678",
      a = t.length,
      n = "_";
      for (var i = 0; i < e; i++) n += t.charAt(Math.floor(Math.random() * a));
      return n
    }
    return randomString(len);
}
const nameList = []

const confusionVar = {
    "VariableDeclarator|FunctionDeclaration|Identifier": function (path){
        let name = path?.node?.id?.name || path?.node?.name
        let newname;
        while (true){
            newname = getRandomName(8)
            if(nameList.indexOf(newname) !== -1){
                continue
            }else{
                nameList.push(newname)
                break
            }
        }
        path.scope.rename(name, newname)
    }
}

traverse(ast, confusionVar);


const output = generator(ast).code
fs.writeFileSync("outputdemo.js", output, {"encoding": "utf-8"})
