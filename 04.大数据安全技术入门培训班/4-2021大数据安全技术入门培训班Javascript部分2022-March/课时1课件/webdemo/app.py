import json
import random
import base64
from flask import Flask, request, render_template
from flask_cors import *
import hashlib
import time


app = Flask(__name__)
CORS(app, supports_credentials=True)


def md5(data):
    data = data.encode()
    m = hashlib.md5(data)
    return m.hexdigest()


with open("templates/myweb.html") as f:
    html = f.read()

with open("templates/md5.js") as f:
    md5js = f.read()

with open("templates/vue.js") as f:
    vue = f.read()

with open("templates/demo.js") as f:
    demo = f.read()


@app.route('/')
def index():
    return html


@app.route('/md5.js')
def index2():
    return md5js


@app.route('/vue.js')
def index3():
    return vue


@app.route('/demo.js')
def index4():
    return demo

namelist = ['霸王别姬', '这个杀手不太冷', '肖申克的救赎', '泰坦尼克号', '罗马假日', '唐伯虎点秋香', '乱世佳人', '喜剧之王', '楚门的世界', '狮子王']
aliaslist = ['Farewell My Concubine', 'Léon', 'The Shawshank Redemption', 'Titanic', 'Roman Holiday', 'Flirting Scholar', 'Gone with the Wind', 'The King of Comedy', 'The Truman Show', 'The Lion King']
categorieslist = [['剧情', '爱情'], ['剧情', '动作', '犯罪'], ['剧情', '犯罪'], ['剧情', '爱情', '灾难'], ['剧情', '喜剧', '爱情'], ['喜剧', '爱情', '古装'], ['剧情', '爱情', '历史', '战争'], ['剧情', '喜剧', '爱情'], ['剧情', '科幻'], ['动画', '歌舞', '冒险']]
publishedlist = ['1993-07-26', '1994-09-14', '1994-09-10', '1998-04-03', '1953-08-20', '1993-07-01', '1939-12-15', '1999-02-13', '1999-01-23', '1995-07-15']
minutelist = [171, 110, 142, 194, 118, 102, 238, 85, 103, 89]
scorelist = [9.5, 9.5, 9.5, 9.5, 9.5, 9.5, 9.5, 9.5, 9.0, 9.0]
regionslist = [['中国大陆', '中国香港'], ['法国'], ['美国'], ['美国'], ['美国'], ['中国香港'], ['美国'], ['中国香港'], ['美国'], ['美国']]
@app.route('/get_data', methods=["POST"])
def get_data():
    timestamp = request.form["timestamp"]
    sign = str(request.form["sign"])
    page = int(request.form["page"])
    print(timestamp, sign)
    md5result = str(md5(str(timestamp)))

    now_time = int(time.time() * 1000)
    if md5result == sign and now_time - int(timestamp) < 5000:
        data = []
        for p in range(10):
            i = random.randint(0,9)
            data.append({
                "id": p + (page-1)*10 + 1,
                "name": namelist[i],
                "alias": aliaslist[i],
                "categories": categorieslist[i],
                "published_at": publishedlist[i],
                "minute": minutelist[i],
                "score": scorelist[i],
                "regions": regionslist[i]
            })
        result = {"code": 200,
                  "results": data}
    else:
        result = {"code": 300, "results": []}

    return json.dumps(result, ensure_ascii=False)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5564")
