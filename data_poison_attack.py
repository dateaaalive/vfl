import pandas as pd
import numpy as np
import os
import random

data = pd.read_csv("F:\downloads\code\data\label\\train.csv")

rand_list = [random.choice(list(data.loc[:, 'idx'].index)) for _ in range(1000)]
for i in rand_list:
    if data.loc[i, 'y'] == 1:
        data.loc[i, 'y'] = 0
    else:
        data.loc[i, 'y'] = 1

if not os.path.exists("F:\downloads\code\data\posion_attack"):
    os.mkdir("F:\downloads\code\data\posion_attack")

data.to_csv("F:\downloads\code\data\posion_attack\\train.csv", index=False)

np_list = np.array(rand_list)
np.savez("./conf/rand_list.npz", np_list)
