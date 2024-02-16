function request(page) {
    var xmlhttp;
    if (window.XMLHttpRequest) {// code for IE7+, Firefox, Chrome, Opera, Safari
        xmlhttp = new XMLHttpRequest();
    } else {// code for IE6, IE5
        xmlhttp = new ActiveXObject("Microsoft.XMLHTTP");
    }
    var timestamp = new Date().getTime().toString();
    var sign = b(a(timestamp),timestamp)
    xmlhttp.onreadystatechange = function () {
        if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
            // document.getElementById("myDiv").innerHTML = xmlhttp.responseText;
            var response = xmlhttp.responseText;
            try{
                response = JSON.parse(xmlhttp.responseText);
            }catch (e){
                alert("Request Error")
                return;
            }
            if(response.code !== 200){
                alert("Request Error")
                return;
            }
            var results = response.results;
            var items = []
            for (let i = 0; i < results.length ; i++) {
                let item = results[i];
                let data = {
                    id: item.id,
                    name: item.name,
                    alias: item.alias,
                    categories: item.categories,
                    cover: item.cover,
                    minute: item.minute,
                    published_at: item.published_at,
                    regions: item.regions,
                    score: item.score,
                }
                items.push(data)
            }
            //console.log(items)
            example2.items = items

        }
    }
    xmlhttp.open("POST", "http://localhost:5564/get_data", true);
    xmlhttp.setRequestHeader("Content-type","application/x-www-form-urlencoded");
    xmlhttp.send('timestamp='+timestamp+'&sign='+sign+'&page='+page);
}
var app = new Vue({
    el: '#app',
    data: {
        message: 'JS Web Demo'
    }
})
var example2 = new Vue({
      el: '#example-1',
      data: {
        parentMessage: 'Parent',
        items: []
      }
    })

// var app5 = new Vue({
//   el: '#app-5',
//   data: {
//     message: 'Hello Vue.js!'
//   },
//   methods: {
//     reverseMessage: function () {
//       this.message = this.message.split('').reverse().join('')
//     }
//   }
// })
//
// var app6 = new Vue({
//   el: '#app-6',
//   data: {
//     message: 'anonymous'
//   }
// })
//
// Vue.component('todo-item', {
//   props: ['todo'],
//   template: '<li>{{ todo.text }}</li>'
// })
//
// var app7 = new Vue({
//   el: '#app-7',
//   data: {
//     groceryList: [
//       { id: 0, text: 'test' },
//       { id: 1, text: 'test' },
//       { id: 2, text: 'test' }
//     ]
//   }
// })