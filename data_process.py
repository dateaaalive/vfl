import pandas as pd
import numpy as np
import os
from typing import List, Dict, Tuple

attr_classes = {
    "workclass": ['Private', 'Self-emp-not-inc', 'Self-emp-inc', 'Federal-gov', 'Local-gov', 'State-gov', 'Without-pay',
                  'Never-worked', 'Retired'],
    "education": ['Bachelors', 'Some-college', '11th', 'HS-grad', 'Prof-school', 'Assoc-acdm', 'Assoc-voc', '9th',
                  '7th-8th', '12th', 'Masters', '1st-4th', '10th', 'Doctorate', '5th-6th', 'Preschool'],
    "marital-status": ['Married-civ-spouse', 'Divorced', 'Never-married', 'Separated', 'Widowed',
                       'Married-spouse-absent', 'Married-AF-spouse'],
    "occupation": ['Tech-support', 'Craft-repair', 'Other-service', 'Sales', 'Exec-managerial', 'Prof-specialty',
                   'Handlers-cleaners', 'Machine-op-inspct', 'Adm-clerical', 'Farming-fishing', 'Transport-moving',
                   'Priv-house-serv', 'Protective-serv', 'Armed-Forces', 'Retired', 'Student', 'None'],
    "relationship": ['Wife', 'Own-child', 'Husband', 'Not-in-family', 'Other-relative', 'Unmarried'],
    "race": ['White', 'Asian-Pac-Islander', 'Amer-Indian-Eskimo', 'Other', 'Black'],
    "sex": ['Female', 'Male'],
    "native-country": ['United-States', 'Cambodia', 'England', 'Puerto-Rico', 'Canada', 'Germany',
                       'Outlying-US(Guam-USVI-etc)', 'India', 'Japan', 'Greece', 'South', 'China', 'Cuba', 'Iran',
                       'Honduras', 'Philippines', 'Italy', 'Poland', 'Jamaica', 'Vietnam', 'Mexico', 'Portugal',
                       'Ireland', 'France', 'Dominican-Republic', 'Laos', 'Ecuador', 'Taiwan', 'Haiti', 'Columbia',
                       'Hungary', 'Guatemala', 'Nicaragua', 'Scotland', 'Thailand', 'Yugoslavia', 'El-Salvador',
                       'Trinadad&Tobago', 'Peru', 'Hong', 'Holand-Netherlands'],
    "label": ['<=50K', '>50K']
}


def get_mean_std(df: pd.DataFrame):
    res = {}
    for col in ["age", "capital-gain", "capital-loss", "hours-per-week"]:
        mean = df[col].mean()
        std = df[col].std()
        res[col] = {"mean": mean, "std": std}
    return res


def int_to_one_hot(val: int, total: int) -> List[int]:
    res = [0] * total
    if val >= 0:
        res[val] = 1
    return res


def df_to_arr(df: pd.DataFrame) -> np.ndarray:
    names = df.columns.tolist()
    rows = len(df)

    arr = []
    for i in range(rows):
        arr_row = []
        for col in names:
            if col in attr_classes:
                raw_val = df.iloc[i][col]
                if raw_val == "?":
                    val = -1
                else:
                    val = attr_classes[col].index(raw_val)
                if col == "label":
                    arr_row.append(val)
                else:
                    arr_row.extend(int_to_one_hot(val, len(attr_classes[col])))
            else:
                val = df.iloc[i][col]
                arr_row.append(val)
        arr.append(arr_row)
    res = np.array(arr, dtype=np.float32)
    return res


def miss_value_handler(df, mean_std):
    for col in attr_classes:
        df[col] = df[col].str.strip()

    df.drop(columns=["fnlwgt", "education-num"], inplace=True)

    df.loc[df.workclass == "Never-worked", ["occupation"]] = "None"
    df.loc[(df.age < 24) & (df.occupation == "?"), ["workclass", "occupation"]] = ["Never-worked", "Student"]
    df.loc[(df.age > 60) & (df.occupation == "?"), ["workclass", "occupation"]] = ["Retired", "Retired"]

    for col in mean_std:
        mean = mean_std[col]["mean"]
        std = mean_std[col]["std"]

        df[col] = (df[col] - mean) / std
    return df


def split_feature(arr: np.ndarray) -> Tuple[np.ndarray, ...]:
    feature, label = arr[:, :-1], arr[:, -1:]

    a_feature_size = 40
    b_feature_size = 80

    a_feature = feature[:, :a_feature_size]
    b_feature = feature[:, a_feature_size:b_feature_size]
    c_feature = feature[:, b_feature_size:]

    return a_feature, b_feature, c_feature, label


names = ["age", "workclass", "fnlwgt", "education", "education-num", "marital-status", "occupation",
         "relationship", "race", "sex", "capital-gain", "capital-loss", "hours-per-week", "native-country",
         "label"]
train_data = pd.read_csv("data/adult.data.csv", header=None, names=names)
test_data = pd.read_csv("data/adult.test.csv", header=None, names=names)
test_data['label'] = test_data['label'].str.replace('.', '')

mean_std = get_mean_std(train_data)
train_data = miss_value_handler(train_data, mean_std)
test_data = miss_value_handler(test_data, mean_std)
train_data = df_to_arr(train_data)
test_data = df_to_arr(test_data)
if not os.path.exists("data"):
    os.mkdir("data")
np.savez("data/adult.train.npz", train_data)
a, b, c, label = split_feature(train_data)
if not os.path.exists("data/2"):
    os.mkdir("data/2")
if not os.path.exists("data/3"):
    os.mkdir("data/3")
if not os.path.exists("data/4"):
    os.mkdir("data/4")
if not os.path.exists("data/label"):
    os.mkdir("data/label")
np.savez("data/2/train.npz", a)
np.savez("data/3/train.npz", b)
np.savez("data/4/train.npz", c)
np.savez("data/label/train.npz", label)
np.savez("data/adult.test.npz", test_data)
a, b, c, label = split_feature(test_data)
np.savez("data/2/test.npz", a)
np.savez("data/3/test.npz", b)
np.savez("data/4/test.npz", c)
np.savez("data/label/test.npz", label)


def to_suitable_data(file_name, start_index=0, has_label=False):
    data_npz = np.load(file_name)
    for data_name in data_npz.files:
        columns = []
        if has_label is True:
            columns.append('y')
            for i in range(1, data_npz[data_name].shape[1]):
                columns.append('x' + str(i + start_index))
        else:
            for i in range(data_npz[data_name].shape[1]):
                columns.append('x' + str(i + start_index))
        data_pd = pd.DataFrame(data_npz[data_name], columns=columns)
        idx = range(data_pd.shape[0])
        data_pd.insert(0, 'idx', idx)
    data_pd.to_csv(file_name.replace('.npz', '.csv'), index=False)


to_suitable_data("data/2/train.npz")
to_suitable_data("data/3/train.npz", 40)
to_suitable_data("data/4/train.npz", 80)
to_suitable_data("data/label/train.npz", 0, True)
to_suitable_data("data/2/test.npz")
to_suitable_data("data/3/test.npz", 40)
to_suitable_data("data/4/test.npz", 80)
to_suitable_data("data/label/test.npz", 0, True)
