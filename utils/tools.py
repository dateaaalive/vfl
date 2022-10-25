import yaml
import pandas as pd
import time


def wait_func(func, t=2):
    def decor(*args, **kwargs):
        res = None
        while res is not True:
            try:
                res = func(*args, **kwargs)
            except Exception as e:
                print(e)
                return
            else:
                time.sleep(t)
        return res
    return decor


def read_yml(path):
    with open(path, encoding='utf-8') as f:
        return yaml.load(f.read(), Loader=yaml.FullLoader)


def read_data(path):
    data = pd.read_csv(path)
    columns = data.columns.values.tolist()
    columns = columns[1:]
    data_np = data.iloc[:, 1:].to_numpy()
    return columns, data_np


def sum_wx(w, b, x):
    swx = b
    for wx in list(zip(w, x)):
        swx += wx[0] * wx[1]
    return swx


def sub_wx_y(wx, y):
    return wx - y
