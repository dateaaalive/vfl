import os
import time

from phe import paillier
from pathlib import Path

from utils import *


class SerControl:
    def __init__(self):
        self.regist_list = []
        self.encrypt_data = {}
        self.encrypt_power = {}
        self.data_list = {}
        self.total_loss = None
        self.sum_encrypt_data_list = []
        self.cid_encrypt_data_dict = {}
        self.unlearn_data = None
        self.last_data = {}
        self.cross_wx_y = {}
        self.unlearn_power = {}
        self.unlearn_data_list = {}

    def init_task(self):
        path = str(Path(os.path.realpath(__file__)).parent.parent) + "/conf/task_conf.yml"
        self.task_conf = read_yml(path)
        self.clients = self.task_conf['cid']
        self.epoch_max = self.task_conf['epoch']
        self.public_key, self.private_key = paillier.generate_paillier_keypair(n_length=256)
        self.sum_encrypt_data = None
        self.raw_b = {}
        self.raw_w = {}
        self.epoch = 0

    def start_task(self):
        self.init_task()
        print("task start ...")
        while len(self.regist_list) < len(self.clients):
            time.sleep(1)
        print("all clients have register, start task!")
        for cid in self.regist_list:
            self.cid_encrypt_data_dict[cid] = []

        self.epoch += 1

        while self.epoch <= self.epoch_max:
            self.encrypt_data = {}
            self.encrypt_power = {}
            self.data_list = {}
            self.cross_wx_y = {}
            self.sum_encrypt_data = None
            print(f"{self.epoch} start...")
            while len(self.encrypt_data) < len(self.clients):
                time.sleep(1)
            print("all clients has upload encrypt data, start add data!")
            for cid, data in self.encrypt_data.items():
                self.cid_encrypt_data_dict[cid].append(data)

            self.sum_encrypt_data = self.add_encrypt_data()
            self.sum_encrypt_data_list.append(self.sum_encrypt_data)
            sum_data = self.private_key.decrypt(self.sum_encrypt_data)
            print(f"sum data {sum_data}")

            self.raw_w = {}
            self.raw_b = {}
            while len(self.raw_w) < len(self.clients):
                time.sleep(1)
            print("all clients params has been decrypted.")

            self.epoch += 1

        for cid, data_list in self.cid_encrypt_data_dict.items():
            decrypt_data = [self.private_key.decrypt(data) for data in data_list]
            print(f"cid: {cid}, data_list: {decrypt_data}")

        while self.unlearn_data is None:
            print(f"unlearn_data: {self.unlearn_data}")
            time.sleep(1)
        self.raw_w = {}
        self.raw_b = {}
        while len(self.raw_w) < (len(self.clients) - 1):
            print(f"raw_w: {self.raw_w}")
            time.sleep(1)
        print("all clients params has been decrypted.")
        self.epoch += 1

        while True:
            time.sleep(1)

    def unlearn_one_client(self, cid):
        cid_unlearn_data = sum(self.cid_encrypt_data_dict[cid])
        sum_data = sum(self.sum_encrypt_data_list)
        # self.unlearn_data = (sum_data - cid_unlearn_data)
        self.unlearn_data = -1 * self.last_data[cid]
        decrypt_unlearn = self.private_key.decrypt(self.unlearn_data)
        print(f"unlearn data: {decrypt_unlearn}")
        return True

    def upload_encrypt_data(self, cid, ciphertext, exponent):
        encrypt_data = paillier.EncryptedNumber(self.public_key, ciphertext, exponent)
        self.encrypt_data[cid] = encrypt_data
        self.last_data[cid] = encrypt_data
        if len(self.encrypt_data) < len(self.clients):
            print(f"waiting other clients upload encrypt data...")
            return False
        else:
            print(f"All client upload encrypt data! Start merge encrypt data...")
            for cid, encrypt_item in self.encrypt_data.items():
                data = self.private_key.decrypt(encrypt_item)
                print(f"{cid} upload data {data}.")
            return True

    def upload_encrypt_gradient(self, cid, cip_w, exp_w, cip_b, exp_b):
        raw_w = []
        encrypt_b = paillier.EncryptedNumber(self.public_key, cip_b, exp_b)
        self.raw_b[cid] = self.private_key.decrypt(encrypt_b)
        for cw, ew in list(zip(cip_w, exp_w)):
            raw_w.append(self.private_key.decrypt(paillier.EncryptedNumber(self.public_key, cw, ew)))
            self.raw_w[cid] = raw_w
        return True

    def add_encrypt_data(self):
        add_data = self.encrypt_data[self.clients[0]]
        for cid, data in self.encrypt_data.items():
            if cid != self.clients[0]:
                add_data = add_data + data
        return add_data

    def upload_encrypt_power(self, cid, ciphertext, exponent):
        encrypt_power = paillier.EncryptedNumber(self.public_key, ciphertext, exponent)
        self.encrypt_power[cid] = encrypt_power
        return True

    def upload_cross_wx_y(self, cid, cip_list, exp_list):
        for item in zip(cid, cip_list, exp_list):
            encrypt_cross = paillier.EncryptedNumber(self.public_key, item[1], item[2])
            self.cross_wx_y[item[0]] = encrypt_cross
        return True

    def upload_data_list(self, cid, ciphertext, exponent):
        data_list = []
        for data in zip(ciphertext, exponent):
            cip_num, exp_num = data[0], data[1]
            data_list.append(paillier.EncryptedNumber(self.public_key, cip_num, exp_num))
        self.data_list[cid] = data_list
        return True

    def upload_total_loss(self, ciphertext, exponent):
        total_loss = paillier.EncryptedNumber(self.public_key, ciphertext, exponent)
        self.total_loss = self.private_key.decrypt(total_loss)
        return True

    def get_encrypt_power(self):
        if len(self.encrypt_power) < len(self.clients):
            print(f"get_encrypt_power keys: {self.encrypt_power.keys()}")
            return None
        return self.encrypt_power

    def get_data_list(self):
        if len(self.data_list) < len(self.clients):
            print(f"get_data_list keys: {self.data_list.keys()}")
            return None
        return self.data_list

    def get_cross_wx_y(self):
        if len(self.cross_wx_y) < (len(self.clients) - 1):
            print(f"get_cross_wx_y keys: {self.cross_wx_y.keys()}")
            return None
        return self.cross_wx_y

    def upload_unlearn_power(self, cid, ciphertext, exponent):
        encrypt_power = paillier.EncryptedNumber(self.public_key, ciphertext, exponent)
        self.unlearn_power[cid] = encrypt_power
        return True

    def upload_unlearn_data_list(self, cid, ciphertext, exponent):
        data_list = []
        for data in zip(ciphertext, exponent):
            cip_num, exp_num = data[0], data[1]
            data_list.append(paillier.EncryptedNumber(self.public_key, cip_num, exp_num))
        self.unlearn_data_list[cid] = data_list
        return True

    def get_unlearn_power(self):
        if len(self.unlearn_power) < (len(self.clients) - 1):
            print(f"get_unlearn_power keys: {self.unlearn_power.keys()}")
            return None
        return self.unlearn_power

    def get_unlearn_data_list(self):
        if len(self.unlearn_data_list) < (len(self.clients) - 1):
            print(f"get_unlearn_data_list keys: {self.unlearn_data_list.keys()}")
            return None
        return self.unlearn_data_list

    def upload_logit_list(self, cid, ciphertext, exponent):
        data_list = []
        for data in zip(ciphertext, exponent):
            cip_num, exp_num = data[0], data[1]
            data_list.append(self.private_key.decrypt(paillier.EncryptedNumber(self.public_key, cip_num, exp_num)))
        return data_list