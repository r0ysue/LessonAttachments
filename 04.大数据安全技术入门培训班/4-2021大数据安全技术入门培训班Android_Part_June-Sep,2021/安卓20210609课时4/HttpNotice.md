## HTTP协议

### 请求
GET /demo01/getNotice HTTP/1.1CRLF(\r\n)  //请求行
Host: www.dtasecurity.cn(\r\n)       //请求头
Connection: keep-alive(\r\n)
(\r\n)                                //请求空行




POST /demo01/getWallpaper HTTP/1.1
Host: www.dtasecurity.cn
Content-length: 21
Content-type: application/x-www-form-urlencoded

classify=yzmn&limit=1

### 响应
HTTP/1.1 200 OK
Content-type: application/json

data

HTTP/1.1 200(状态码) OK         //响应行
Content-Type: application/json
Transfer-Encoding: chunked
Date: Mon, 07 Jun 2021 08:53:34 GMT

82
{"title":"软件进入提示:","message":"欢迎大家报名学习大数据安全课程，当前系统时间:2021-06-07 08:53:34"}
0
