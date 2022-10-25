import copy
import os
import grpc
import random
import numpy as np
from phe import paillier
from pathlib import Path

from utils import *
import proto.vfl_pb2 as vfl_pb2
import proto.vfl_pb2_grpc as vfl_pb2_grpc


class VflClient:
    def __init__(self, cid):
        self.cid = cid
        self.identity = "guest"

    def send_rpc(self, func, params):
        try:
            res, call = getattr(self.vfl_stub, func).with_call(
                params,
                compression=grpc.Compression.Gzip,
                timeout=30
            )
        except Exception as e:
            print(e)
        else:
            return res

    def init_task(self):
        path = str(Path(os.path.realpath(__file__)).parent.parent) + "/conf/task_conf.yml"
        self.task_conf = read_yml(path)
        self.haddr = self.task_conf['haddr']
        self.hport = self.task_conf['hport']
        self.epoch_max = self.task_conf['epoch']
        self.lr = self.task_conf['lr']
        self.clients = self.task_conf['cid']
        self.epoch = 0
        self.other_encrypt_power = {}
        self.data_list = {}
        self.cross_host_wx_y = {}
        self.unlearn_power = {}
        self.unlearn_data_list = {}
        self.loigt_list = []
        channel = grpc.insecure_channel(f'{self.haddr}:{self.hport}',
                                        options=[
                                            ("grpc.max_send_message_length", 1024 * 1024 * 1024),
                                            ("grpc.max_receive_message_length", 1024 * 1024 * 1024)
                                        ])
        self.vfl_stub = vfl_pb2_grpc.VflStub(channel)

        self.columns, self.raw_data = read_data(
            str(Path(os.path.realpath(__file__)).parent.parent / 'data' / str(self.cid) / "train.csv"))
        self.label_col, temp_label = read_data(
            str(Path(os.path.realpath(__file__)).parent.parent / 'data' / 'posion_attack' / "train.csv"))
        self.raw_label = [y[0] for y in temp_label]
        if self.cid == self.clients[0]:
            self.identity = "host"
            self.label_col, temp_label = read_data(
                str(Path(os.path.realpath(__file__)).parent.parent / 'data' / 'posion_attack' / "train.csv"))
            self.raw_label = [y[0] for y in temp_label]
        self.init_model_weight(self.columns)

    def init_model_weight(self, x_col):
        self.w = [random.random() for _ in range(len(x_col))]
        self.b = random.random()
        print(f"init w: {self.w}")
        print(f"init b: {self.b}")

    def start_task(self):
        self.init_task()
        res = self.send_rpc("register", vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch))
        if res.code == 0:
            print(f"{self.cid} register successfully!  start upload encrypt data...")
            self.public_key = paillier.PaillierPublicKey(n=int(res.desc))

        self.epoch += 1
        while self.epoch <= self.epoch_max:
            print(f"{self.epoch} start...")
            wx_list = []
            for raw_item_list in self.raw_data:
                wx_list.append(sum_wx(self.w, self.b, raw_item_list))

            print(sum(wx_list))
            if self.identity == "host":
                wx_y_list = list(map(sub_wx_y, wx_list, self.raw_label))
                sum_wx_y = sum(wx_y_list)
                print(f"host data {sum_wx_y}")

                wx_y_power = sum(list(map(lambda x: x ** 2, wx_y_list)))
                encrypt_power = self.public_key.encrypt(wx_y_power)
                self.upload_encrypt_power(encrypt_power)
                print(f"host upload encrypt_power successfully.")

                encrypt_wx_y_list = list(map(lambda x: self.public_key.encrypt(x), wx_y_list))
                self.upload_data_list(encrypt_wx_y_list)
                print(f"host upload data_list successfully.")

                print("start get encrypt power...")
                self.get_encrypt_power()
                print("start get data list...")
                self.get_data_list()
                print(f"host get data list successfully.")

                cross_wx_y_dict = {}
                for cid, data_list in self.data_list.items():
                    cross_wx_y_list = []
                    for data in zip(wx_list, data_list):
                        cross_wx_y_list.append(2 * data[0] * data[1])
                    cross_wx_y_dict[cid] = sum(cross_wx_y_list)
                print(f"cross_wx_y_dict: {cross_wx_y_dict}")
                self.upload_cross_wx_y(cross_wx_y_dict)
                print(f"host upload cross_wx_y successfully.")

                encrypt_wx_y = self.public_key.encrypt(sum_wx_y)
                self.upload_encrypt_data(encrypt_wx_y)
            else:
                sum_wx_list = sum(wx_list)
                print(f"guest data {sum_wx_list}")

                wx_power = sum(list(map(lambda x: x ** 2, wx_list)))
                encrypt_power = self.public_key.encrypt(wx_power)
                self.upload_encrypt_power(encrypt_power)
                print(f"guest upload encrypt_power successfully.")

                encrypt_wx_list = list(map(lambda x: self.public_key.encrypt(x), wx_list))
                self.upload_data_list(encrypt_wx_list)
                print(f"guest upload data_list successfully.")

                print("start get encrypt power...")
                self.get_encrypt_power()
                print("start get data list...")
                self.get_data_list()

                print("start get cross_wx_y...")
                cross_wx_y_dict = {}
                for cid, data_list in self.data_list.items():
                    cross_wx_y_list = []
                    for data in zip(wx_list, data_list):
                        cross_wx_y_list.append(2 * data[0] * data[1])
                    cross_wx_y_dict[cid] = cross_wx_y_list

                self.get_cross_wx_y()

                encrypt_logit_list = copy.deepcopy(encrypt_wx_list)
                for cid, data_list in self.data_list.items():
                    encrypt_logit_list = list(map(lambda x: x[0] + x[1], zip(encrypt_logit_list, data_list)))
                self.upload_logit_list(encrypt_logit_list)
                predit_list = [1 if logit > 0.5 else 0 for logit in self.loigt_list]
                count = sum(list(map(lambda x: x[0] == x[1], zip(predit_list, self.raw_label))))
                print(f"train predict: {count/len(self.raw_label)}")

                print("start upload and get total loss...")
                temp_cross_loss = self.public_key.encrypt(0)
                for item in cross_wx_y_dict.values():
                    temp_cross_loss += sum(item)
                encrypt_total_loss = (encrypt_power + sum(self.other_encrypt_power.values()) + temp_cross_loss +
                                      sum(self.cross_host_wx_y.values())) / len(self.raw_data)
                self.upload_total_loss(encrypt_total_loss)
                self.get_total_loss()
                print(f"total loss: {self.total_loss}.")

                encrypt_wx = self.public_key.encrypt(sum_wx_list)
                self.upload_encrypt_data(encrypt_wx)

            self.get_col_encrypt_data()

            temp_b = self.b - self.lr * self.col_encrypt_data
            temp_w = []
            for index, wi in enumerate(self.w):
                raw_data_index = 0.0
                for data in self.raw_data:
                    raw_data_index += data[index]
                temp_w.append(wi - 0.1 * wi - self.lr * raw_data_index / len(self.raw_data) * self.col_encrypt_data)

            self.upload_encrypt_gradient(temp_w, temp_b)
            self.get_decrypt_gradient()

            self.epoch += 1

            print(f"w: {self.w}")
            print(f"b: {self.b}")

        print(f"start unlearn one client...")
        if self.identity == "host":
            self.unlearn_one_client()
        else:
            self.get_unlearn_param()
            print(f"get unlearn param: {self.unlearn_param}")

            temp_b = self.b - self.lr * self.unlearn_param
            temp_w = []
            for index, wi in enumerate(self.w):
                raw_data_index = 0.0
                for data in self.raw_data:
                    raw_data_index += data[index]
                temp_w.append(wi - 0.1 * wi - self.lr * raw_data_index / len(self.raw_data) * self.unlearn_param)

            self.upload_encrypt_gradient(temp_w, temp_b)
            self.get_decrypt_gradient()
            print(f"unlearn successfully...")
            print(f"w: {self.w}")
            print(f"b: {self.b}")

            self.epoch += 1
            wx_list = []
            for raw_item_list in self.raw_data:
                wx_list.append(sum_wx(self.w, self.b, raw_item_list))
            if self.cid == self.clients[-1]:
                self.label_col, temp_label = read_data(
                    str(Path(os.path.realpath(__file__)).parent.parent / 'data' / 'label' / "train.csv"))
                self.raw_label = [y[0] for y in temp_label]
                wx_list = list(map(sub_wx_y, wx_list, self.raw_label))
            unlearn_power = sum(list(map(lambda x: x ** 2, wx_list)))
            encrypt_unlearn_power = self.public_key.encrypt(unlearn_power)
            self.upload_unlearn_power(encrypt_unlearn_power)
            encrypt_unlearn_wx_list = list(map(lambda x: self.public_key.encrypt(x), wx_list))
            self.upload_unlearn_data_list(encrypt_unlearn_wx_list)
            self.get_unlearn_power()
            self.get_unlearn_data_list()

            print("start get unlearn cross_wx_y...")
            cross_wx_y_dict = {}
            for cid, data_list in self.unlearn_data_list.items():
                cross_wx_y_list = []
                for data in zip(wx_list, data_list):
                    cross_wx_y_list.append(2 * data[0] * data[1])
                cross_wx_y_dict[cid] = cross_wx_y_list

            self.get_cross_wx_y()
            print("start upload and get unlearn total loss...")
            temp_cross_loss = self.public_key.encrypt(0)
            for item in cross_wx_y_dict.values():
                temp_cross_loss += sum(item)
            encrypt_total_loss = (encrypt_unlearn_power + sum(self.unlearn_power.values()) + temp_cross_loss +
                                  sum(self.cross_host_wx_y.values())) / len(self.raw_data)
            self.upload_total_loss(encrypt_total_loss)
            self.get_total_loss()
            print(f"unlearn total loss: {self.total_loss}.")

            encrypt_logit_list = copy.deepcopy(encrypt_unlearn_wx_list)
            for cid, data_list in self.unlearn_data_list.items():
                encrypt_logit_list = list(map(lambda x: x[0] + x[1], zip(encrypt_logit_list, data_list)))
            print(f"encrypt_logit_list: {len(encrypt_logit_list)}")
            self.upload_logit_list(encrypt_logit_list)
            predit_list = [1 if logit > 0.5 else 0 for logit in self.loigt_list]
            count = sum(list(map(lambda x: x[0] == x[1], zip(predit_list, self.raw_label))))
            print(f"unlearn predict: {count / len(self.raw_label)}")

            print('test posion attack predict...')
            self.label_col, temp_label = read_data(
                str(Path(os.path.realpath(__file__)).parent.parent / 'data' / 'label' / "train.csv"))
            self.raw_label = [y[0] for y in temp_label]
            rand_np = np.load(str(Path(os.path.realpath(__file__)).parent.parent / "conf" / "rand_list.npz"))
            rand_list = rand_np['arr_0'].tolist()
            count = 0.0
            for i in rand_list:
                count += predit_list[i] == self.raw_label[i]
            print(f"posion attack failed predict: {count/len(rand_list)}")

    @wait_func
    def get_unlearn_power(self):
        res = self.send_rpc("get_unlearn_power", vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch))
        if res.code.code != 0:
            print(res.code.desc)
            return False
        else:
            for cid, data in res.data.items():
                if cid != self.cid:
                    ciphertext = int(data.ciphertext)
                    exponent = data.exponent
                    self.unlearn_power[cid] = paillier.EncryptedNumber(self.public_key, ciphertext, exponent)
            return True

    @wait_func
    def get_unlearn_data_list(self):
        res = self.send_rpc("get_unlearn_data_list", vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch))
        if res.code.code != 0:
            print(res.code.desc)
            return False
        else:
            for cid, rpc_list in res.data_list.items():
                if cid != self.cid:
                    rpc_list = rpc_list.data_list
                    data_list = []
                    for rpc_data in rpc_list:
                        data_list.append(
                            paillier.EncryptedNumber(self.public_key, int(rpc_data.ciphertext), rpc_data.exponent))
                    self.unlearn_data_list[cid] = data_list
            return True

    @wait_func
    def upload_unlearn_data_list(self, encrypt_unlearn_wx_list):
        rpc_data = []
        for data in encrypt_unlearn_wx_list:
            ciphertext = str(data.ciphertext())
            rpc_data.append(vfl_pb2.EncryptData(ciphertext=ciphertext, exponent=data.exponent))
        rpc_param = vfl_pb2.UploadDataList(node=vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch),
                                           data_list=rpc_data)
        res = self.send_rpc("upload_unlearn_data_list", rpc_param)
        if res.code == 0:
            return True
        else:
            print(f"upload_unlearn_data_list: {res.code}, desc: {res.desc}")

    @wait_func
    def upload_unlearn_power(self, unlearn_power):
        ciphertext = str(unlearn_power.ciphertext())
        res = self.send_rpc("upload_unlearn_power", vfl_pb2.UploadData(
            node=vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch),
            data=vfl_pb2.EncryptData(ciphertext=ciphertext, exponent=unlearn_power.exponent)))
        if res.code == 0:
            return True
        else:
            print(f"upload_unlearn_power: {res.code}, desc: {res.desc}")

    @wait_func
    def get_cross_wx_y(self):
        res = self.send_rpc("get_cross_wx_y", vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch))
        if res.code.code == 0:
            for cid, data in res.data.items():
                if cid != self.cid:
                    ciphertext = int(data.ciphertext)
                    exponent = data.exponent
                    self.cross_host_wx_y[cid] = paillier.EncryptedNumber(self.public_key, ciphertext, exponent)
            return True
        return False

    @wait_func
    def upload_cross_wx_y(self, cross_wx_y_dict):
        rpc_dict = {}
        for cid, data in cross_wx_y_dict.items():
            ciphertext = str(data.ciphertext())
            exponent = data.exponent
            rpc_dict[cid] = vfl_pb2.EncryptData(ciphertext=ciphertext, exponent=exponent)
        res = self.send_rpc("upload_cross_wx_y", vfl_pb2.UploadDataDict(
            node=vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch),
            data=rpc_dict))
        if res.code == 0:
            return True
        else:
            print(f"upload_total_loss: {res.code}, desc: {res.desc}")

    @wait_func
    def get_unlearn_param(self):
        res = self.send_rpc("get_unlearn_param", vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch))
        if res.code.code == 0:
            ciphertext = int(res.data.ciphertext)
            exponent = res.data.exponent
            self.unlearn_param = paillier.EncryptedNumber(self.public_key, ciphertext, exponent)
            return True
        print(res.code.desc)
        return False

    def unlearn_one_client(self):
        res = self.send_rpc("unlearn_one_client", vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch))
        if res.code == 0:
            return True
        else:
            print(f"upload_total_loss: {res.code}, desc: {res.desc}")

    @wait_func
    def upload_total_loss(self, loss):
        ciphertext = str(loss.ciphertext())
        res = self.send_rpc("upload_total_loss", vfl_pb2.UploadData(
            node=vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch),
            data=vfl_pb2.EncryptData(ciphertext=ciphertext, exponent=loss.exponent)))
        if res.code == 0:
            return True
        else:
            print(f"upload_total_loss: {res.code}, desc: {res.desc}")

    @wait_func
    def get_total_loss(self):
        res = self.send_rpc("get_total_loss", vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch))
        if res.code.code != 0:
            return False
        else:
            self.total_loss = res.loss
            return True

    @wait_func
    def get_data_list(self):
        res = self.send_rpc("get_data_list", vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch))
        if res.code.code != 0:
            print(res.code.desc)
            return False
        else:
            for cid, rpc_list in res.data_list.items():
                if cid != self.cid:
                    rpc_list = rpc_list.data_list
                    data_list = []
                    for rpc_data in rpc_list:
                        data_list.append(
                            paillier.EncryptedNumber(self.public_key, int(rpc_data.ciphertext), rpc_data.exponent))
                    self.data_list[cid] = data_list
            return True

    @wait_func
    def upload_logit_list(self, logit_list):
        rpc_data = []
        for data in logit_list:
            ciphertext = str(data.ciphertext())
            rpc_data.append(vfl_pb2.EncryptData(ciphertext=ciphertext, exponent=data.exponent))
        rpc_param = vfl_pb2.UploadDataList(node=vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch),
                                           data_list=rpc_data)
        res = self.send_rpc("upload_logit_list", rpc_param)
        if res.code.code == 0:
            print()
            self.loigt_list = res.logit
            return True
        else:
            print(f"upload_logit_list: {res.code.code}, desc: {res.code.desc}")

    @wait_func
    def upload_data_list(self, data_list):
        rpc_data = []
        for data in data_list:
            ciphertext = str(data.ciphertext())
            rpc_data.append(vfl_pb2.EncryptData(ciphertext=ciphertext, exponent=data.exponent))
        rpc_param = vfl_pb2.UploadDataList(node=vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch),
                                           data_list=rpc_data)
        res = self.send_rpc("upload_data_list", rpc_param)
        if res.code == 0:
            return True
        else:
            print(f"upload_data_list: {res.code}, desc: {res.desc}")

    @wait_func
    def upload_encrypt_gradient(self, encrypt_w, encrypt_b):
        rpc_w = []
        for wi in encrypt_w:
            ciphertext = str(wi.ciphertext())
            rpc_w.append(vfl_pb2.EncryptData(ciphertext=ciphertext, exponent=wi.exponent))
        rpc_b = vfl_pb2.EncryptData(ciphertext=str(encrypt_b.ciphertext()), exponent=encrypt_b.exponent)
        res = self.send_rpc("upload_encrypt_gradient",
                            vfl_pb2.EncryptGradient(node=vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch),
                                                    w=rpc_w, b=rpc_b))
        if res.code == 0:
            return True
        else:
            print(f"upload_encrypt_gradient: {res.code}, desc: {res.desc}")

    @wait_func
    def upload_encrypt_power(self, encrypt_power):
        ciphertext = str(encrypt_power.ciphertext())
        res = self.send_rpc("upload_encrypt_power", vfl_pb2.UploadData(
            node=vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch),
            data=vfl_pb2.EncryptData(ciphertext=ciphertext, exponent=encrypt_power.exponent)))
        if res.code == 0:
            return True
        else:
            print(f"upload_encrypt_power: {res.code}, desc: {res.desc}")

    @wait_func
    def upload_encrypt_data(self, encrypt_data):
        ciphertext = str(encrypt_data.ciphertext())
        res = self.send_rpc("upload_encrypt_data", vfl_pb2.UploadData(
            node=vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch),
            data=vfl_pb2.EncryptData(ciphertext=ciphertext, exponent=encrypt_data.exponent)))
        if res.code == 0:
            return True
        else:
            print(f"upload_encrypt_data: {res.code}, desc: {res.desc}")

    @wait_func
    def get_col_encrypt_data(self):
        res = self.send_rpc("get_col_encrypt_data", vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch))
        if res.code.code != 0:
            return False
        else:
            ciphertext = int(res.data.ciphertext)
            exponent = res.data.exponent
            self.col_encrypt_data = paillier.EncryptedNumber(self.public_key, ciphertext, exponent)
            return True

    @wait_func
    def get_encrypt_power(self):
        res = self.send_rpc("get_encrypt_power", vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch))
        if res.code.code != 0:
            print(res.code.desc)
            return False
        else:
            for cid, data in res.data.items():
                if cid != self.cid:
                    ciphertext = int(data.ciphertext)
                    exponent = data.exponent
                    self.other_encrypt_power[cid] = paillier.EncryptedNumber(self.public_key, ciphertext, exponent)
            return True

    @wait_func
    def get_decrypt_gradient(self):
        res = self.send_rpc("get_decrypt_gradient", vfl_pb2.NodeInfo(cid=self.cid, epoch=self.epoch))
        if res.code.code != 0:
            return False
        else:
            self.w = res.w
            self.b = res.b
            return True
