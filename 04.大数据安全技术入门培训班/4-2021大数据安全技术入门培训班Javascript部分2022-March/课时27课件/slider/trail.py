import math
import random

import numpy as np
import matplotlib.pyplot as plt
trail_1 = [
    [
        9,
        1,
        111
    ],
    [
        13,
        1,
        121
    ],
    [
        19,
        1,
        126
    ],
    [
        28,
        1,
        136
    ],
    [
        36,
        1,
        146
    ],
    [
        49,
        1,
        153
    ],
    [
        61,
        1,
        163
    ],
    [
        75,
        -2,
        171
    ],
    [
        86,
        -2,
        180
    ],
    [
        96,
        -4,
        190
    ],
    [
        104,
        -4,
        198
    ],
    [
        114,
        -5,
        204
    ],
    [
        122,
        -5,
        214
    ],
    [
        128,
        -6,
        222
    ],
    [
        134,
        -7,
        230
    ],
    [
        139,
        -7,
        242
    ],
    [
        143,
        -7,
        246
    ],
    [
        147,
        -8,
        253
    ],
    [
        151,
        -8,
        266
    ],
    [
        155,
        -8,
        272
    ],
    [
        158,
        -8,
        292
    ],
    [
        161,
        -9,
        299
    ],
    [
        165,
        -9,
        303
    ],
    [
        168,
        -10,
        306
    ],
    [
        171,
        -10,
        313
    ],
    [
        176,
        -10,
        322
    ],
    [
        179,
        -10,
        330
    ],
    [
        184,
        -11,
        341
    ],
    [
        188,
        -11,
        355
    ],
    [
        191,
        -11,
        361
    ],
    [
        194,
        -11,
        367
    ],
    [
        196,
        -11,
        375
    ],
    [
        198,
        -12,
        384
    ],
    [
        201,
        -12,
        393
    ],
    [
        203,
        -12,
        401
    ],
    [
        206,
        -12,
        412
    ],
    [
        208,
        -12,
        420
    ],
    [
        211,
        -13,
        430
    ],
    [
        214,
        -13,
        437
    ],
    [
        215,
        -13,
        448
    ],
    [
        218,
        -13,
        454
    ],
    [
        220,
        -13,
        465
    ],
    [
        223,
        -13,
        473
    ],
    [
        225,
        -13,
        485
    ],
    [
        227,
        -13,
        497
    ],
    [
        228,
        -14,
        505
    ],
    [
        229,
        -14,
        516
    ],
    [
        231,
        -14,
        525
    ],
    [
        232,
        -14,
        534
    ],
    [
        233,
        -14,
        540
    ],
    [
        235,
        -14,
        551
    ],
    [
        237,
        -14,
        562
    ],
    [
        239,
        -14,
        573
    ],
    [
        240,
        -14,
        583
    ],
    [
        241,
        -14,
        588
    ],
    [
        243,
        -14,
        612
    ],
    [
        244,
        -14,
        621
    ],
    [
        245,
        -14,
        632
    ],
    [
        247,
        -14,
        638
    ],
    [
        248,
        -14,
        653
    ],
    [
        249,
        -14,
        661
    ],
    [
        250,
        -14,
        673
    ],
    [
        251,
        -14,
        684
    ],
    [
        252,
        -14,
        696
    ],
    [
        253,
        -14,
        709
    ],
    [
        254,
        -14,
        727
    ],
    [
        255,
        -14,
        740
    ],
    [
        256,
        -14,
        762
    ],
    [
        256,
        -15,
        785
    ],
    [
        257,
        -15,
        809
    ],
    [
        258,
        -15,
        836
    ],
    [
        259,
        -15,
        864
    ],
    [
        260,
        -15,
        875
    ],
    [
        261,
        -15,
        899
    ],
    [
        262,
        -15,
        950
    ],
    [
        263,
        -15,
        969
    ],
    [
        264,
        -15,
        983
    ],
    [
        265,
        -15,
        1016
    ],
    [
        266,
        -15,
        1035
    ],
    [
        267,
        -15,
        1057
    ],
    [
        268,
        -15,
        1069
    ],
    [
        269,
        -15,
        1102
    ],
    [
        270,
        -15,
        1244
    ]
]
trail_2 = [
    [
        11,
        0,
        140
    ],
    [
        13,
        0,
        147
    ],
    [
        16,
        0,
        158
    ],
    [
        19,
        0,
        168
    ],
    [
        21,
        0,
        177
    ],
    [
        24,
        -1,
        184
    ],
    [
        27,
        -1,
        193
    ],
    [
        30,
        -1,
        202
    ],
    [
        32,
        -1,
        213
    ],
    [
        34,
        -1,
        217
    ],
    [
        37,
        -1,
        228
    ],
    [
        38,
        -1,
        235
    ],
    [
        41,
        -1,
        249
    ],
    [
        43,
        -1,
        261
    ],
    [
        45,
        -2,
        270
    ],
    [
        47,
        -2,
        282
    ],
    [
        49,
        -2,
        293
    ],
    [
        50,
        -2,
        301
    ],
    [
        51,
        -2,
        312
    ],
    [
        53,
        -2,
        322
    ],
    [
        54,
        -2,
        332
    ],
    [
        56,
        -2,
        342
    ],
    [
        58,
        -2,
        352
    ],
    [
        60,
        -2,
        362
    ],
    [
        62,
        -2,
        374
    ],
    [
        65,
        -2,
        384
    ],
    [
        66,
        -2,
        392
    ],
    [
        68,
        -2,
        399
    ],
    [
        69,
        -2,
        409
    ],
    [
        71,
        -2,
        422
    ],
    [
        73,
        -2,
        428
    ],
    [
        74,
        -2,
        436
    ],
    [
        76,
        -2,
        447
    ],
    [
        77,
        -2,
        452
    ],
    [
        79,
        -2,
        466
    ],
    [
        82,
        -2,
        476
    ],
    [
        83,
        -2,
        485
    ],
    [
        85,
        -2,
        495
    ],
    [
        86,
        -2,
        506
    ],
    [
        87,
        -2,
        515
    ],
    [
        88,
        -2,
        523
    ],
    [
        90,
        -2,
        542
    ],
    [
        91,
        -2,
        549
    ],
    [
        93,
        -2,
        562
    ],
    [
        94,
        -2,
        568
    ],
    [
        95,
        -2,
        586
    ],
    [
        96,
        -2,
        604
    ],
    [
        97,
        -2,
        630
    ],
    [
        98,
        -2,
        640
    ],
    [
        99,
        -2,
        661
    ],
    [
        100,
        -2,
        680
    ],
    [
        101,
        -2,
        708
    ],
    [
        102,
        -2,
        728
    ],
    [
        103,
        -2,
        756
    ],
    [
        104,
        -2,
        782
    ],
    [
        105,
        -2,
        804
    ],
    [
        106,
        -2,
        821
    ],
    [
        107,
        -2,
        862
    ],
    [
        108,
        -2,
        890
    ],
    [
        109,
        -2,
        927
    ],
    [
        110,
        -2,
        951
    ],
    [
        111,
        -2,
        1029
    ],
    [
        112,
        -2,
        1052
    ],
    [
        113,
        -2,
        1095
    ],
    [
        114,
        -2,
        1112
    ],
    [
        115,
        -2,
        1135
    ],
    [
        116,
        -2,
        1213
    ]
]
trail_3 = [
    [
        13,
        0,
        86
    ],
    [
        18,
        -1,
        96
    ],
    [
        22,
        -1,
        102
    ],
    [
        28,
        -1,
        114
    ],
    [
        33,
        -2,
        120
    ],
    [
        38,
        -2,
        125
    ],
    [
        43,
        -2,
        139
    ],
    [
        47,
        -3,
        149
    ],
    [
        51,
        -3,
        156
    ],
    [
        55,
        -3,
        164
    ],
    [
        58,
        -3,
        172
    ],
    [
        60,
        -4,
        179
    ],
    [
        63,
        -4,
        186
    ],
    [
        65,
        -4,
        195
    ],
    [
        68,
        -4,
        204
    ],
    [
        70,
        -4,
        217
    ],
    [
        72,
        -4,
        221
    ],
    [
        75,
        -4,
        232
    ],
    [
        77,
        -5,
        239
    ],
    [
        78,
        -5,
        251
    ],
    [
        81,
        -5,
        257
    ],
    [
        82,
        -5,
        269
    ],
    [
        84,
        -6,
        276
    ],
    [
        85,
        -6,
        284
    ],
    [
        86,
        -6,
        292
    ],
    [
        87,
        -6,
        305
    ],
    [
        88,
        -6,
        312
    ],
    [
        89,
        -6,
        323
    ],
    [
        90,
        -6,
        340
    ],
    [
        91,
        -6,
        362
    ],
    [
        92,
        -6,
        370
    ],
    [
        93,
        -6,
        391
    ],
    [
        94,
        -6,
        401
    ],
    [
        96,
        -6,
        417
    ],
    [
        97,
        -6,
        438
    ],
    [
        98,
        -6,
        464
    ],
    [
        99,
        -6,
        487
    ],
    [
        100,
        -6,
        501
    ],
    [
        101,
        -6,
        521
    ],
    [
        102,
        -6,
        548
    ],
    [
        103,
        -6,
        565
    ],
    [
        104,
        -6,
        590
    ],
    [
        105,
        -6,
        642
    ],
    [
        106,
        -6,
        688
    ],
    [
        107,
        -6,
        721
    ],
    [
        108,
        -6,
        735
    ],
    [
        109,
        -6,
        770
    ],
    [
        110,
        -6,
        832
    ],
    [
        111,
        -6,
        857
    ],
    [
        112,
        -6,
        887
    ],
    [
        113,
        -6,
        902
    ],
    [
        114,
        -6,
        923
    ],
    [
        115,
        -6,
        950
    ],
    [
        115,
        -5,
        999
    ],
    [
        116,
        -5,
        1008
    ],
    [
        117,
        -5,
        1034
    ],
    [
        118,
        -5,
        1081
    ],
    [
        118,
        -4,
        1089
    ],
    [
        119,
        -4,
        1100
    ],
    [
        120,
        -4,
        1122
    ],
    [
        121,
        -4,
        1159
    ]
]
trail_4 = [
    [
        9,
        0,
        136
    ],
    [
        14,
        -1,
        143
    ],
    [
        17,
        -1,
        152
    ],
    [
        22,
        -2,
        161
    ],
    [
        29,
        -2,
        169
    ],
    [
        35,
        -2,
        177
    ],
    [
        41,
        -3,
        186
    ],
    [
        51,
        -3,
        200
    ],
    [
        58,
        -3,
        206
    ],
    [
        69,
        -4,
        212
    ],
    [
        77,
        -4,
        220
    ],
    [
        87,
        -4,
        231
    ],
    [
        95,
        -4,
        237
    ],
    [
        105,
        -4,
        245
    ],
    [
        114,
        -4,
        254
    ],
    [
        120,
        -4,
        266
    ],
    [
        124,
        -4,
        271
    ],
    [
        128,
        -4,
        285
    ],
    [
        131,
        -4,
        295
    ],
    [
        133,
        -4,
        302
    ],
    [
        135,
        -4,
        308
    ],
    [
        136,
        -4,
        316
    ],
    [
        137,
        -4,
        324
    ],
    [
        138,
        -4,
        335
    ],
    [
        139,
        -4,
        340
    ],
    [
        141,
        -4,
        353
    ],
    [
        142,
        -4,
        362
    ],
    [
        143,
        -4,
        372
    ],
    [
        144,
        -4,
        387
    ],
    [
        145,
        -4,
        389
    ],
    [
        146,
        -4,
        406
    ],
    [
        147,
        -4,
        425
    ],
    [
        148,
        -4,
        455
    ],
    [
        149,
        -4,
        466
    ],
    [
        150,
        -4,
        483
    ],
    [
        150,
        -5,
        492
    ],
    [
        151,
        -5,
        499
    ],
    [
        150,
        -5,
        1202
    ]
]
trail_5 = [
    [
        8,
        -1,
        128
    ],
    [
        12,
        -2,
        137
    ],
    [
        15,
        -2,
        145
    ],
    [
        19,
        -2,
        156
    ],
    [
        22,
        -4,
        160
    ],
    [
        26,
        -4,
        174
    ],
    [
        29,
        -5,
        178
    ],
    [
        32,
        -5,
        187
    ],
    [
        35,
        -5,
        198
    ],
    [
        37,
        -5,
        207
    ],
    [
        38,
        -6,
        212
    ],
    [
        40,
        -6,
        222
    ],
    [
        43,
        -7,
        230
    ],
    [
        44,
        -7,
        240
    ],
    [
        48,
        -8,
        250
    ],
    [
        50,
        -8,
        256
    ],
    [
        53,
        -8,
        266
    ],
    [
        56,
        -9,
        274
    ],
    [
        60,
        -9,
        281
    ],
    [
        64,
        -10,
        292
    ],
    [
        69,
        -10,
        302
    ],
    [
        73,
        -10,
        310
    ],
    [
        78,
        -11,
        319
    ],
    [
        83,
        -12,
        327
    ],
    [
        88,
        -12,
        336
    ],
    [
        92,
        -13,
        343
    ],
    [
        97,
        -13,
        352
    ],
    [
        100,
        -13,
        359
    ],
    [
        103,
        -13,
        367
    ],
    [
        106,
        -13,
        375
    ],
    [
        108,
        -13,
        386
    ],
    [
        111,
        -13,
        393
    ],
    [
        112,
        -13,
        402
    ],
    [
        115,
        -13,
        411
    ],
    [
        117,
        -13,
        422
    ],
    [
        118,
        -13,
        428
    ],
    [
        120,
        -13,
        438
    ],
    [
        122,
        -13,
        444
    ],
    [
        123,
        -13,
        456
    ],
    [
        125,
        -13,
        465
    ],
    [
        126,
        -13,
        472
    ],
    [
        127,
        -13,
        479
    ],
    [
        129,
        -13,
        490
    ],
    [
        131,
        -13,
        501
    ],
    [
        133,
        -13,
        512
    ],
    [
        135,
        -13,
        524
    ],
    [
        137,
        -13,
        529
    ],
    [
        139,
        -13,
        541
    ],
    [
        140,
        -13,
        550
    ],
    [
        142,
        -13,
        562
    ],
    [
        143,
        -13,
        576
    ],
    [
        144,
        -13,
        589
    ],
    [
        145,
        -13,
        595
    ],
    [
        147,
        -13,
        608
    ],
    [
        148,
        -13,
        618
    ],
    [
        149,
        -13,
        631
    ],
    [
        151,
        -14,
        644
    ],
    [
        152,
        -14,
        664
    ],
    [
        153,
        -14,
        673
    ],
    [
        155,
        -14,
        694
    ],
    [
        156,
        -14,
        706
    ],
    [
        157,
        -14,
        721
    ],
    [
        158,
        -14,
        731
    ],
    [
        159,
        -14,
        742
    ],
    [
        160,
        -14,
        759
    ],
    [
        161,
        -14,
        774
    ],
    [
        162,
        -14,
        799
    ],
    [
        163,
        -14,
        815
    ],
    [
        164,
        -14,
        839
    ],
    [
        165,
        -14,
        853
    ],
    [
        166,
        -14,
        870
    ],
    [
        167,
        -14,
        899
    ],
    [
        168,
        -14,
        920
    ],
    [
        169,
        -14,
        940
    ],
    [
        170,
        -14,
        956
    ],
    [
        171,
        -14,
        977
    ],
    [
        172,
        -14,
        998
    ],
    [
        173,
        -14,
        1106
    ],
    [
        174,
        -14,
        1129
    ],
    [
        175,
        -14,
        1182
    ],
    [
        175,
        -13,
        1191
    ]
]
# 2
def show_plt():
    for i in range(1, 6):
        trail_list = eval(f"trail_{i}")
        print(f"trail_{i}")
        x_trail = []
        y_trail = []
        t_trail = []
        for trail in trail_list:
            x = trail[0]
            y = trail[1]
            t = trail[2]
            x_trail.append(x)
            y_trail.append(y)
            t_trail.append(t)
        print(np.diff(x_trail))
        plt.plot(t_trail, x_trail)
    plt.show()


def easeOutQuint(x):
    return (1 - math.pow(1 - x, 5))

# 3
def get_trail(move_distence, show=False):
    def __set_pt_time(_dist):
        if _dist < 100:
            __need_time = int(random.uniform(500, 1500))
        else:
            __need_time = int(random.uniform(1000, 2000))
        __end_pt_time = []
        __move_pt_time = []
        __pos_z = []

        total_move_time = __need_time * random.uniform(0.8, 0.9)
        start_point_time = random.uniform(110, 200)
        __start_pt_time = [int(start_point_time)]

        sum_move_time = 0

        _tmp_total_move_time = total_move_time
        while True:
            delta_time = random.uniform(15, 20)
            if _tmp_total_move_time < delta_time:
                break

            sum_move_time += delta_time
            _tmp_total_move_time -= delta_time
            __move_pt_time.append(int(start_point_time + sum_move_time))

        last_pt_time = __move_pt_time[-1]
        __move_pt_time.append(int(last_pt_time + _tmp_total_move_time))

        sum_end_time = start_point_time + total_move_time
        other_point_time = __need_time - sum_end_time
        end_first_ptime = other_point_time / 2

        while True:
            delta_time = random.uniform(110, 200)
            if end_first_ptime - delta_time <= 0:
                break

            end_first_ptime -= delta_time
            sum_end_time += delta_time
            __end_pt_time.append(int(sum_end_time))

        __end_pt_time.append(int(sum_end_time + (other_point_time / 2 + end_first_ptime)))
        __pos_z.extend(__start_pt_time)
        __pos_z.extend(__move_pt_time)
        __pos_z.extend(__end_pt_time)
        return __pos_z

    def __get_pos_y(point_count):
        _pos_y = []
        start_y = random.randint(290, 292)
        end_y = random.randint(300, 305)
        x = np.linspace(start_y, end_y, point_count)
        for _, val in enumerate(x):
            _pos_y.append(int(val))

        return _pos_y

    time_list = __set_pt_time(move_distence)
    trail_length = len(time_list)
    t = np.linspace(-0.5, 1, trail_length)  # t
    mult = move_distence/7.59375
    # s_x = [random.randint(20, 22), random.randint(23, 25), random.randint(25, 27)]
    x = [int(mult * (easeOutQuint(i) + 6.59375)) + random.randint(20, 22) for i in t]
    y = __get_pos_y(trail_length)
    # t=-0.5 x=-6.59375
    # t=1 x=7.59375
    delta_pt = abs(np.random.normal(scale=3, size=trail_length))
    for index in range(len(delta_pt)):
        change_x = int(x[index] + delta_pt[index])
        if index+1 < trail_length and x[index+1] > change_x:
            x[index] = change_x

    if show:
        delta_t = [i for i in range(trail_length)]
        plt.plot(delta_t, delta_pt, color='green')
        # plt.plot(time_list, x, color='red')
        plt.show()
    result = []
    print(x[-1] - x[0])
    for idx in range(trail_length):
        result.append([x[idx], y[idx], time_list[idx]])
    return result

def showeaseOutQuint(distance):
    def func(x):
        return 1 - pow(1 - x, 5) + 6.59375
    print(func(-0.5), func(1))
    x = np.linspace(-0.5, 1, 70)
    y = [distance/7.59375 * func(i) for i in x]
    delta_pt = abs(np.random.normal(scale=1.1, size=70))
    for index in range(len(delta_pt)):
        change_y = int(x[index] + delta_pt[index])
        if index+1 < 70 and y[index+1] > change_y:
            y[index] += change_y
    t = np.linspace(100, 1200, 70)
    plt.plot(t, y)
    plt.show()

if __name__ == '__main__':
    # show_plt()
    distance = 100
    # showeaseOutQuint(distance)
    result = get_trail(distance, False)
    print(result)
    """        
    1. 收集轨迹
    2. 画出轨迹图像 找缓动函数相同形状
    3. 绘制缓动函数 找到符合形状的作用域
    4. 找到作用域内最大值 最小值 上下移动 *距离系数
    5. 替换时间（t）轴为自己的
    6. 高斯函数增加波动
    7. 细节修改 x轴 t轴 np.diff对比
    """

