# 接口文档：
- HOST：http://www.dtasecurity.cn:18080
## 获取壁纸
- URL : /demo02/getWallpaper
- Method：POST/GET
- Body : 

|param|describe|necessary|
|:----:|:----:|:----:|
|classify|分类|是|
|pageNum|页数(默认为1)|是|
|limit|每页的数量(默认为20，上限20)|否|
|timestamp|时间戳|是|
|sign|md5(classify+pageNum+timestamp),大写|是|

- 参数classify取值:

|classify|describe|
|:----:|:----:|
| yzmn |颜值美女|
| dmdh |动漫动画|
| kamc |可爱萌宠|
| zrfg |自然风光|
| ydjs |运动健身|

- Response :
```json 
{"pageNum":1,"hasNext":false,"data":[{"id":30,"name":"XXX","classify":"XXX","smallPic":"XXX","bigPic":"XXX","extra":null,"createTime":"XXX"}],"limit":20,"classfiy":"XXX","message":null}
```

## 获取公告
- URL : /demo02/getNotice
- Method：GET
- Body : 无
- Response :
```json 
{"title":"XXX","message":"XXX"}
```