import os
import grpc
import random
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
                grpc.Compression.Gzip
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
        channel = grpc.insecure_channel(f'{self.haddr}:{self.hport}',
                                        options=[
                                            ("grpc.max_send_message_length", 256 * 1024 * 1024),
                                            ("grpc.max_receive_message_length", 256 * 1024 * 1024)
                                        ])
        self.vfl_stub = vfl_pb2_grpc.VflStub(channel)

        self.columns, self.raw_data = read_data(
            str(Path(os.path.realpath(__file__)).parent.parent / 'data' / str(self.cid) / "train.csv"))
        if self.cid == self.clients[0]:
            self.identity = "host"
            self.label_col, temp_label = read_data(
                str(Path(os.path.realpath(__file__)).parent.parent / 'data' / 'label' / "train.csv"))
            self.raw_label = [y[0] for y in temp_label]
        self.init_model_weight(self.columns)

    def init_model_weight(self, x_col):
        self.w = [random.random() for _ in range(len(x_col))]
        if self.identity == "host":
            self.b = random.random()
        else:
            self.b = 0
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

                cross_wx_y_list = list(map(lambda x: self.public_key.encrypt(x), wx_y_list))
                self.upload_data_list(cross_wx_y_list)
                print(f"host upload data_list successfully.")

                encrypt_wx_y = self.public_key.encrypt(sum_wx_y)
                self.upload_encrypt_data(encrypt_wx_y)
            else:
                sum_wx_list = sum(wx_list)
                print(f"guest data {sum_wx_list}")

                wx_power = sum(list(map(lambda x: x ** 2, wx_list)))
                encrypt_power = self.public_key.encrypt(wx_power)

                self.get_encrypt_power()
                self.get_data_list()
                cross_wx_y_list = []
                for data in zip(wx_list, self.data_list):
                    cross_wx_y_list.append(2 * data[0] * data[1])

                encrypt_total_loss = (encrypt_power + self.other_encrypt_power + sum(cross_wx_y_list)) / len(self.raw_data)
                self.upload_total_loss(encrypt_total_loss)
                self.get_total_loss()
                print(f"total loss: {self.total_loss}.")

                encrypt_wx = self.public_key.encrypt(sum_wx_list)
                self.upload_encrypt_data(encrypt_wx)

            self.get_col_encrypt_data()

            if self.identity == "host":
                temp_b = self.b - self.lr * self.col_encrypt_data
            else:
                temp_b = self.public_key.encrypt(0.0)
            temp_w = []
            for index, wi in enumerate(self.w):
                raw_data_index = 0.0
                for data in self.raw_data:
                    raw_data_index += data[index]
                temp_w.append(wi - self.lr * raw_data_index / len(self.raw_data) * self.col_encrypt_data)

            self.upload_encrypt_gradient(temp_w, temp_b)
            self.get_decrypt_gradient()

            self.epoch += 1

            print(f"w: {self.w}")
            print(f"b: {self.b}")

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
            return False
        else:
            data_list = []
            rpc_data_list = res.data_list
            for rpc_data in rpc_data_list:
                data_list.append(paillier.EncryptedNumber(self.public_key, int(rpc_data.ciphertext), rpc_data.exponent))
            self.data_list = data_list
            return True

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
            return False
        else:
            ciphertext = int(res.data.ciphertext)
            exponent = res.data.exponent
            self.other_encrypt_power = paillier.EncryptedNumber(self.public_key, ciphertext, exponent)
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
