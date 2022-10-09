import grpc
from concurrent import futures

import vfl
from proto import *


class VflHost:
    def __init__(self, hid):
        self.hid = hid
        self.rpc_servicer = VflService()
        self.rpc_server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=10),
            compression=grpc.Compression.Gzip,
            options=[
                ("grpc.max_send_message_length", 256 * 1024 * 1024),
                ("grpc.max_receive_message_length", 256 * 1024 * 1024)
            ]
        )
        vfl_pb2_grpc.add_VflServicer_to_server(self.rpc_servicer, self.rpc_server)
        self.rpc_server.add_insecure_port(f'[::]:50051')
        self.rpc_server.start()
        # self.rpc_server.wait_for_termination()

    def start_task(self):
        self.rpc_servicer.ser_control.start_task()


class VflService(vfl_pb2_grpc.VflServicer):
    def __init__(self):
        self.ser_control = vfl.SerControl()

    def register(self, request, context):
        cid = request.cid
        self.ser_control.regist_list.append(cid)
        print(f"{cid} register successfully!")
        public_key = str(self.ser_control.public_key.n)
        return vfl_pb2.Code(code=0, desc=public_key)

    def upload_encrypt_data(self, request, context):
        cid = request.node.cid
        epoch = request.node.epoch
        ciphertext = int(request.data.ciphertext)
        exponent = request.data.exponent
        if epoch != self.ser_control.epoch:
            return vfl_pb2.Code(code=1, desc="server epoch not ready")
        res = self.ser_control.upload_encrypt_data(cid, ciphertext, exponent)
        if res:
            return vfl_pb2.Code(code=0, desc="upload encrypt data successfully! waiting reconstruct data...")
        else:
            return vfl_pb2.Code(code=0, desc="upload encrypt data successfully! waiting other client upload data...")

    def get_col_encrypt_data(self, request, context):
        epoch = request.epoch
        if epoch != self.ser_control.epoch:
            return vfl_pb2.DownloadData(code=vfl_pb2.Code(code=1, desc="server epoch not ready"),
                                            data=vfl_pb2.EncryptData(ciphertext=None, exponent=None))
        res = self.ser_control.sum_encrypt_data
        if res is None:
            return vfl_pb2.DownloadData(code=vfl_pb2.Code(code=1, desc="server not add data done."),
                                            data=vfl_pb2.EncryptData(ciphertext=None, exponent=None))
        else:
            ciphertext = str(res.ciphertext())
            exponent = res.exponent
            return vfl_pb2.DownloadData(code=vfl_pb2.Code(code=0, desc="server add data done"),
                                            data=vfl_pb2.EncryptData(ciphertext=ciphertext, exponent=exponent))

    def upload_encrypt_gradient(self, request, context):
        cid = request.node.cid
        epoch = request.node.epoch
        rpc_w = request.w
        cip_b = int(request.b.ciphertext)
        exp_b = request.b.exponent
        cip_w = []
        exp_w = []
        if epoch != self.ser_control.epoch:
            return vfl_pb2.Code(code=1, desc=f"server epoch not ready.")
        for number in rpc_w:
            cip_w.append(int(number.ciphertext))
            exp_w.append(number.exponent)
        res = self.ser_control.upload_encrypt_gradient(cid, cip_w, exp_w, cip_b, exp_b)
        if res:
            return vfl_pb2.Code(code=0, desc="upload gradient to server successfully.")
        else:
            return vfl_pb2.Code(code=1, desc="fail to upload gradient to server.")

    def get_decrypt_gradient(self, request, context):
        epoch = request.epoch
        if epoch != (self.ser_control.epoch - 1):
            return vfl_pb2.DecryptGradient(code=vfl_pb2.Code(code=1, desc="server epoch not ready"), w=None, b=None)
        cid = request.cid
        raw_w = self.ser_control.raw_w[cid]
        raw_b = self.ser_control.raw_b[cid]
        if raw_w is None or raw_b is None:
            return vfl_pb2.DecryptGradient(code=vfl_pb2.Code(code=1, desc="server not ready decrypt gradient"), w=None, b=None)
        else:
            return vfl_pb2.DecryptGradient(code=vfl_pb2.Code(code=0, desc="get decrypt gradient successfully."), w=raw_w,
                                    b=raw_b)

    def upload_encrypt_power(self, request, context):
        cid = request.node.cid
        epoch = request.node.epoch
        if epoch != self.ser_control.epoch:
            return vfl_pb2.Code(code=1, desc=f"server epoch not ready.")
        ciphertext = int(request.data.ciphertext)
        exponent = request.data.exponent
        res = self.ser_control.upload_encrypt_power(cid, ciphertext, exponent)
        if res:
            return vfl_pb2.Code(code=0, desc="upload encrypt power successfully! waiting other get encrypt power...")

    def get_encrypt_power(self, request, context):
        epoch = request.epoch
        if epoch != self.ser_control.epoch:
            return vfl_pb2.DownloadData(code=vfl_pb2.Code(code=1, desc="server epoch not ready"),
                                            data=vfl_pb2.EncryptData(ciphertext=None, exponent=None))
        encrypt_power = self.ser_control.encrypt_power
        if encrypt_power is None:
            return vfl_pb2.DownloadData(code=vfl_pb2.Code(code=1, desc="server not get encrypt power."),
                                            data=vfl_pb2.EncryptData(ciphertext=None, exponent=None))
        else:
            ciphertext = str(encrypt_power.ciphertext())
            exponent = encrypt_power.exponent
            return vfl_pb2.DownloadData(code=vfl_pb2.Code(code=0, desc="get encrypt power successfully"),
                                            data=vfl_pb2.EncryptData(ciphertext=ciphertext, exponent=exponent))

    def upload_data_list(self, request, context):
        cid = request.node.cid
        epoch = request.node.epoch
        if epoch != self.ser_control.epoch:
            return vfl_pb2.Code(code=1, desc=f"server epoch not ready.")
        data_list = request.data_list
        ciphertext = []
        exponent = []
        for enc_num in data_list:
            ciphertext.append(int(enc_num.ciphertext))
            exponent.append(enc_num.exponent)
        res = self.ser_control.upload_data_list(ciphertext, exponent)
        if res:
            return vfl_pb2.Code(code=0, desc="upload data list successfully! waiting other get data list...")

    def get_data_list(self, request, context):
        epoch = request.epoch
        if epoch != self.ser_control.epoch:
            return vfl_pb2.DownloadDataList(code=vfl_pb2.Code(code=1, desc=f"server epoch not ready."), data_list=None)
        data_list = self.ser_control.data_list
        if data_list is None:
            return vfl_pb2.DownloadDataList(code=vfl_pb2.Code(code=1, desc=f"server not get data_list."),
                                            data_list=None)
        else:
            rpc_data_list = []
            for data in data_list:
                rpc_data_list.append(vfl_pb2.EncryptData(ciphertext=str(data.ciphertext()), exponent=data.exponent))
            return vfl_pb2.DownloadDataList(code=vfl_pb2.Code(code=0, desc=f"get data_list successfully."),
                                            data_list=rpc_data_list)

    def upload_total_loss(self, request, context):
        epoch = request.node.epoch
        if epoch != self.ser_control.epoch:
            return vfl_pb2.Code(code=1, desc=f"server epoch not ready.")
        ciphertext = int(request.data.ciphertext)
        exponent = request.data.exponent
        res = self.ser_control.upload_total_loss(ciphertext, exponent)
        if res:
            return vfl_pb2.Code(code=0, desc="upload total loss successfully! waiting decrypt loss...")

    def get_total_loss(self, request, context):
        epoch = request.epoch
        if epoch != self.ser_control.epoch:
            return vfl_pb2.DownloadData(code=vfl_pb2.Code(code=1, desc="server epoch not ready"),
                                            data=vfl_pb2.EncryptData(ciphertext=None, exponent=None))
        total_loss = self.ser_control.total_loss
        if total_loss is None:
            return vfl_pb2.DownloadData(code=vfl_pb2.Code(code=1, desc="server not get total loss."),
                                            data=vfl_pb2.EncryptData(ciphertext=None, exponent=None))
        else:
            return vfl_pb2.Loss(code=vfl_pb2.Code(code=0, desc="get total loss successfully"),
                                loss=total_loss)
