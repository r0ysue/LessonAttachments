const fs = require("fs")
const parser = require("@babel/parser")
const generator = require("@babel/generator").default
const traverse = require("@babel/traverse").default
const types = require("@babel/types")
const template = require("@babel/template")

const code = fs.readFileSync("./demo.js", {"encoding": "utf-8"})
const ast = parser.parse(code)
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
const ArrayName = getRandomName(8)
const ArrayNode = []
const getLiteralNode = {
    "Literal": function(path){
        ArrayNode.push(path.node)
        let object = types.Identifier(ArrayName)
        let index = ArrayNode.indexOf(path.node);
        let property = types.NumericLiteral(index)
        path.replaceInline(types.MemberExpression(object, property, true))
        path.skip()
    }
}

traverse(ast, getLiteralNode);

const AddArray = {
    "Program": function (path){
        let declarations = [types.VariableDeclarator(types.Identifier(ArrayName),types.ArrayExpression(ArrayNode))]
        let arrNode = types.VariableDeclaration("const", declarations)
        path.node.body.unshift(arrNode)
    }
}
traverse(ast, AddArray);

const output = generator(ast).code
fs.writeFileSync("outputdemo.js", output, {"encoding": "utf-8"})
