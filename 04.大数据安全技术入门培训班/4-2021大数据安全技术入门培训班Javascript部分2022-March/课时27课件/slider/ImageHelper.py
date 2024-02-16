import io
import random
import time
import cv2 as cv
import numpy as np
from PIL import Image
from scipy import signal


# format_list = [0, 10, 16, 6, 13, 3, 9, 15, 11, 19, 14, 18, 4, 12, 2, 1, 8, 17, 7, 5]
# this.canvasCtx.drawImage(this.img,
# 30 * i,  开始剪切的 x 坐标位置。
# 0, 开始剪切的 y 坐标位置。
# 30, 被剪切图像的宽度。
# 400, 被剪切图像的高度。
# 30 * keylist[i] / 1.5, 	在画布上放置图像的 x 坐标位置
# 0,  在画布上放置图像的 y 坐标位置。
# offset / 1.5, 要使用的图像的宽度。（伸展或缩小图像）
# 200)  要使用的图像的高度。（伸展或缩小图像）
def format_slide_img(raw_img: bytes, format_list: list) -> bytes:
    fp = io.BytesIO(raw_img)
    img = Image.open(fp)
    image_dict = {}
    offset = 30
    for i in range(len(format_list)):
        box = (i * offset, 0, offset + (i * offset), 400)  # 左(起始),上(不变),右(宽),下(不变)
        image_dict[format_list[i]] = img.crop(box)
    image_list = []
    for i in sorted(image_dict):
        image_list.append(image_dict[i])
    image_num = len(image_list)
    image_size = image_list[0].size
    height = image_size[1]
    width = image_size[0]
    new_img = Image.new('RGB', (image_num * width, height), 255)
    x = y = 0
    for img in image_list:
        new_img.paste(img, (x, y))
        x += width
    box = (0, 0, 600, 400)
    new_img = new_img.crop(box)
    # 保存图片
    processClickImgIoFlow = io.BytesIO()

    new_img.save(processClickImgIoFlow, format="JPEG")
    return processClickImgIoFlow.getvalue()
    # with open("test.jpg", "wb") as f:
    #     f.write(processClickImgIoFlow.getvalue())

# 1
def discern_gap(gapImage: bytes, sliderImage: bytes, show=False):

    def edge_detection(rawimg):
        def tracebar(x):
            threshold1 = cv.getTrackbarPos('threshold1', 'Test')
            threshold2 = cv.getTrackbarPos('threshold2', 'Test')
            edged_img = cv.Canny(img_Gaussian, threshold1, threshold2)
            cv.imshow("edged_img", edged_img)

        image = np.asarray(bytearray(rawimg), dtype="uint8")
        img = cv.imdecode(image, cv.IMREAD_COLOR)
        grep_img = cv.cvtColor(img, cv.COLOR_BGR2GRAY)
        # 高斯滤波 高斯滤波是通过对输入数组的每个点与输入的高斯滤波模板执行卷积计算然后将这些结果一块组成了滤波后的输出数组，
        # 通俗的讲就是高斯滤波是对整幅图像进行加权平均的过程，每一个像素点的值都由其本身和邻域内的其他像素值经过加权平均后得到。
        # 高斯滤波的具体操作是：用一个模板（或称卷积、掩模）扫描图像中的每一个像素，用模板确定的邻域内像素的加权平均灰度值去替代模板中心像素点的值。
        img_Gaussian = cv.GaussianBlur(grep_img, (5, 5), 0)
        # 用于对图像的边缘检测
        edged_img = cv.Canny(img_Gaussian, 25, 45)
        if show:
            cv.namedWindow("Test")
            # cv.imshow('raw_img', img)
            # cv.imshow('grep_img', grep_img)
            cv.imshow('img_Gaussian', img_Gaussian)
            cv.createTrackbar("threshold1", "Test", 0, 255, tracebar)
            cv.createTrackbar("threshold2", "Test", 0, 255, tracebar)
            # cv.imshow('edged_img', edged_img)
            cv.waitKey()
            cv.destroyAllWindows()
        return edged_img

    def similarity_calculation(background, slider):
        result = cv.matchTemplate(background, slider, cv.TM_CCOEFF_NORMED)
        # 获取一个/组int类型的索引值在一个多维数组中的位置。
        # x, y = np.unravel_index(result.argmax(), result.shape)
        min_val, max_val, min_loc, max_loc = cv.minMaxLoc(result)
        return max_loc

    """计算滑动距离方法"""
    gap = edge_detection(gapImage)
    slider = edge_detection(sliderImage)
    x, y = similarity_calculation(gap, slider)
    print('需要滑动距离', x, y)
    return x / 1.5


def discern_gap2(gap_path, slider_path, save=False):
    def pic2grep(pic_path, type) -> np.ndarray:
        pic_path_rgb = cv.imread(pic_path)
        pic_path_gray = cv.cvtColor(pic_path_rgb, cv.COLOR_BGR2GRAY)
        if save:
            cv.imwrite(f"./{type}.jpg", pic_path_gray)
        return pic_path_gray

    def canny_edge(image_array: np.ndarray, show=False) -> np.ndarray:
        can = cv.Canny(image_array, threshold1=200, threshold2=300)
        if show:
            cv.imshow('candy', can)
            cv.waitKey()
            cv.destroyAllWindows()
        return can

    def clear_white(img: str, show=False) -> np.ndarray:
        img = cv.imread(img)
        rows, cols, channel = img.shape
        min_x = 255
        min_y = 255
        max_x = 0
        max_y = 0
        for x in range(1, rows):
            for y in range(1, cols):
                t = set(img[x, y])
                if len(t) >= 2:
                    if x <= min_x:
                        min_x = x
                    elif x >= max_x:
                        max_x = x

                    if y <= min_y:
                        min_y = y
                    elif y >= max_y:
                        max_y = y
        img1 = img[min_x:max_x, min_y:max_y]
        if show:
            cv.imshow('img1', img1)
            cv.waitKey()
            cv.destroyAllWindows()
        return img1

    def convolve2d(bg_array: np.ndarray, fillter: np.ndarray) -> np.ndarray:
        bg_h, bg_w = bg_array.shape[:2]
        fillter = fillter[::-1,::-1]
        fillter_h, fillter_w = fillter.shape[:2]
        c_full = signal.convolve2d(bg_array, fillter, mode="full")
        kr, kc = fillter_h // 2, fillter_w // 2
        c_same = c_full[
            fillter_h - kr - 1: bg_h + fillter_h - kr - 1,
            fillter_w - kc - 1: bg_w + fillter_w - kc - 1,
        ]
        return c_same

    def find_max_point(arrays: np.ndarray, search_on_horizontal_center=False) -> tuple:
        max_point = 0
        max_point_pos = None

        array_rows, array_cols = arrays.shape

        if search_on_horizontal_center:
            for col in range(array_cols):
                if arrays[array_rows // 2, col] > max_point:
                    max_point = arrays[array_rows // 2, col]
                    max_point_pos = col, array_rows // 2
        else:
            for row in range(array_rows):
                for col in range(array_cols):
                    if arrays[row, col] > max_point:
                        max_point = arrays[row, col]
                        max_point_pos = col, row
        return max_point_pos

    gap_grep = pic2grep(gap_path, "gap")
    gap_can = canny_edge(gap_grep, False)
    clear_slider = cv.imread(slider_path) # clear_white(slider_path, False)
    slider_can = canny_edge(clear_slider, False)
    convolve2d_result = convolve2d(gap_can, slider_can)
    result = find_max_point(convolve2d_result, True)
    print(result)


if __name__ == '__main__':
    with open("p2.jpg", "rb") as f:
        sliderImage = f.read()
    with open("test.jpg", "rb") as f:
        gapImage = f.read()
    discern_gap(gapImage, sliderImage, True)
