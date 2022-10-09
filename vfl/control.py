import os
from phe import paillier
from pathlib import Path

from utils import *


class SerControl:
    def __init__(self):
        self.regist_list = []
        self.encrypt_data = {}
        self.encrypt_power = None
        self.data_list = []
        self.total_loss = None

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

        self.epoch += 1

        while self.epoch <= self.epoch_max:
            self.encrypt_data = {}
            self.sum_encrypt_data = None
            print(f"{self.epoch} start...")
            while len(self.encrypt_data) < len(self.clients):
                time.sleep(1)
            print("all clients has upload encrypt data, start add data!")

            self.sum_encrypt_data = self.add_encrypt_data()
            sum_data = self.private_key.decrypt(self.sum_encrypt_data)
            print(f"sum data {sum_data}")

            self.raw_w = {}
            self.raw_b = {}
            while len(self.raw_w) < len(self.clients):
                time.sleep(1)
            print("all clients params has been decrypted.")

            self.epoch += 1

        while True:
            time.sleep(1)

    def upload_encrypt_data(self, cid, ciphertext, exponent):
        encrypt_data = paillier.EncryptedNumber(self.public_key, ciphertext, exponent)
        self.encrypt_data[cid] = encrypt_data
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
        self.encrypt_power = encrypt_power
        return True

    def upload_data_list(self, ciphertext, exponent):
        data_list = []
        for data in zip(ciphertext, exponent):
            cip_num, exp_num = data[0], data[1]
            data_list.append(paillier.EncryptedNumber(self.public_key, cip_num, exp_num))
        self.data_list = data_list
        return True

    def upload_total_loss(self, ciphertext, exponent):
        total_loss = paillier.EncryptedNumber(self.public_key, ciphertext, exponent)
        self.total_loss = self.private_key.decrypt(total_loss)
        return True