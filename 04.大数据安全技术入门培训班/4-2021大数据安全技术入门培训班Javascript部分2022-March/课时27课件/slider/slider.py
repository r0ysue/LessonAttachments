import base64
import json
import time
import execjs
import requests
from ImageHelper import format_slide_img, discern_gap
from trail import get_trail
from EventHelper import getMouseEvent
with open("dta.js") as f:
    jscode = f.read()
ctx = execjs.compile(jscode)
class slider:
    def __init__(self):
        self.session = requests.session()
        self.session.headers = {
            'Connection': 'keep-alive',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'sec-ch-ua': '" Not;A Brand";v="99", "Google Chrome";v="91", "Chromium";v="91"',
            'Accept': 'application/json, text/plain, */*',
            'sec-ch-ua-mobile': '?0',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36',
            'Origin': 'null',
            'Sec-Fetch-Site': 'cross-site',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        self.sid = ""
        self.session.verify=False

    def get_image(self):
        params = (
            ('w', '400'),
            ('h', '200'),
        )
        response = self.session.get('http://www.dtasecurity.cn:35555/picture', params=params, timeout=10)
        if response.status_code != 200:
            return None
        result = response.json()
        if not result.get("success"):
            return None
        p1: str = result.get("p1").replace("data:image/jpeg;base64,", "")
        p2: str = result.get("p2").replace("data:image/jpeg;base64,", "")
        c: str = result.get("c")
        self.sid: str = result.get("sid")
        y: int = result.get("y")
        decode_p1_img = base64.b64decode(p1)
        decode_p2_img = base64.b64decode(p2)
        with open("./p1.jpg", "wb") as f:
            f.write(decode_p1_img)
        with open("./p2.jpg", "wb") as f:
            f.write(decode_p2_img)
        format_list = [ord(i) ^ 66 for i in list(c)]
        right_order_img: bytes = format_slide_img(decode_p1_img, format_list)
        return right_order_img, decode_p2_img

    def slide(self, gap_img, slider_img):
        distance = discern_gap(gap_img, slider_img)
        raw_trail = get_trail(distance)
        MouseEvent = getMouseEvent(raw_trail)
        encrypt_trail = ctx.call("dtaslide", MouseEvent)
        data = {
            "sid": self.sid,
            "trail": encrypt_trail,
        }
        data = json.dumps(data, separators=(',', ':'))

        response = self.session.post('http://www.dtasecurity.cn:35555/20210703slide', data=data, verify=False, timeout=10)
        print(response.json())
        if response.json()["code"] == 200:
            return True
        return False

    def run(self):
        gap_img, slider_img = self.get_image()
        return self.slide(gap_img, slider_img)



if __name__ == '__main__':
    s = slider()
    total = 0
    success = 0
    for i in range(10):
        if s.run():
            success += 1
        total += 1
        print("准确率 %.2f 次数 %d" % ((success / total), total))
        time.sleep(0.5)
