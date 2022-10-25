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
                ("grpc.max_send_message_length", 1024 * 1024 * 1024),
                ("grpc.max_receive_message_length", 1024 * 1024 * 1024)
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
        cid = request.cid
        epoch = request.epoch
        if epoch != (self.ser_control.epoch - 1):
            print(f"{cid} epoch: {epoch}, server epoch: {self.ser_control.epoch}")
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
            return vfl_pb2.DownloadDataDict(code=vfl_pb2.Code(code=1, desc="server epoch not ready"),
                                            data=None)
        encrypt_power = self.ser_control.get_encrypt_power()
        if encrypt_power is None:
            return vfl_pb2.DownloadDataDict(code=vfl_pb2.Code(code=1, desc="server not get encrypt power."),
                                            data=None)
        else:
            rpc_data_dict = {}
            for cid, data in encrypt_power.items():
                ciphertext = str(data.ciphertext())
                exponent = data.exponent
                rpc_data = vfl_pb2.EncryptData(ciphertext=ciphertext, exponent=exponent)
                rpc_data_dict[cid] = rpc_data
            print(f"rpc_data_dict: {rpc_data_dict}")
            return vfl_pb2.DownloadDataDict(code=vfl_pb2.Code(code=0, desc="get encrypt power successfully"),
                                            data=rpc_data_dict)

    def upload_cross_wx_y(self, request, context):
        cid = request.node.cid
        epoch = request.node.epoch
        if epoch != self.ser_control.epoch:
            return vfl_pb2.Code(code=1, desc=f"server epoch not ready.")
        cid_list = []
        cip_list = []
        exp_list = []
        for cid, data in request.data.items():
            cid_list.append(cid)
            cip_list.append(int(data.ciphertext))
            exp_list.append(data.exponent)
        res = self.ser_control.upload_cross_wx_y(cid_list, cip_list, exp_list)
        if res:
            return vfl_pb2.Code(code=0, desc="upload encrypt power successfully! waiting other get encrypt power...")

    def get_cross_wx_y(self, request, context):
        epoch = request.epoch
        if epoch != self.ser_control.epoch:
            return vfl_pb2.DownloadDataDict(code=vfl_pb2.Code(code=1, desc="server epoch not ready"),
                                            data=None)
        cross_wx_y = self.ser_control.get_cross_wx_y()
        if cross_wx_y is None:
            return vfl_pb2.DownloadDataDict(code=vfl_pb2.Code(code=1, desc="server not get encrypt power."),
                                            data=None)
        else:
            print(f"cross_wx_y: {cross_wx_y}")
            rpc_data_dict = {}
            for cid, data in cross_wx_y.items():
                ciphertext = str(data.ciphertext())
                exponent = data.exponent
                rpc_data = vfl_pb2.EncryptData(ciphertext=ciphertext, exponent=exponent)
                rpc_data_dict[cid] = rpc_data
            print(f"rpc_data_dict: {rpc_data_dict}")
            return vfl_pb2.DownloadDataDict(code=vfl_pb2.Code(code=0, desc="get encrypt power successfully"),
                                            data=rpc_data_dict)

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
        res = self.ser_control.upload_data_list(cid, ciphertext, exponent)
        if res:
            return vfl_pb2.Code(code=0, desc="upload data list successfully! waiting other get data list...")

    def get_data_list(self, request, context):
        epoch = request.epoch
        if epoch != self.ser_control.epoch:
            return vfl_pb2.DownloadDataList(code=vfl_pb2.Code(code=1, desc=f"server epoch not ready."), data_list=None)
        data_dict = self.ser_control.get_data_list()
        if data_dict is None:
            return vfl_pb2.DownloadDataList(code=vfl_pb2.Code(code=1, desc=f"server not get data_list."),
                                            data_list=None)
        else:
            rpc_data_dict = {}
            for cid, data_list in data_dict.items():
                rpc_data_list = []
                for data in data_list:
                    rpc_data_list.append(vfl_pb2.EncryptData(ciphertext=str(data.ciphertext()), exponent=data.exponent))
                rpc_data_dict[cid] = vfl_pb2.DataList(data_list=rpc_data_list)
            return vfl_pb2.DownloadDataList(code=vfl_pb2.Code(code=0, desc=f"get data_list successfully."),
                                            data_list=rpc_data_dict)

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

    def unlearn_one_client(self, request, context):
        cid = request.cid
        res = self.ser_control.unlearn_one_client(cid)
        if res:
            return vfl_pb2.Code(code=0, desc="unlearn one client successfully! waiting get unlearn param.")

    def get_unlearn_param(self, request, context):
        res = self.ser_control.unlearn_data
        if res is None:
            return vfl_pb2.DownloadData(code=vfl_pb2.Code(code=1, desc="server not get unlearn param."),
                                        data=vfl_pb2.EncryptData(ciphertext=None, exponent=None))
        else:
            ciphertext = str(res.ciphertext())
            exponent = res.exponent
            return vfl_pb2.DownloadData(code=vfl_pb2.Code(code=0, desc="get unlearn param successfully"),
                                        data=vfl_pb2.EncryptData(ciphertext=ciphertext, exponent=exponent))

    def upload_unlearn_power(self, request, context):
        cid = request.node.cid
        epoch = request.node.epoch
        if epoch != self.ser_control.epoch:
            print(f"client epoch: {epoch}, server epoch: {self.ser_control.epoch}.")
            return vfl_pb2.Code(code=1, desc=f"server epoch not ready.")
        ciphertext = int(request.data.ciphertext)
        exponent = request.data.exponent
        res = self.ser_control.upload_unlearn_power(cid, ciphertext, exponent)
        if res:
            return vfl_pb2.Code(code=0, desc="upload encrypt power successfully! waiting other get encrypt power...")

    def upload_unlearn_data_list(self, request, context):
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
        res = self.ser_control.upload_unlearn_data_list(cid, ciphertext, exponent)
        if res:
            return vfl_pb2.Code(code=0, desc="upload data list successfully! waiting other get data list...")

    def get_unlearn_power(self, request, context):
        epoch = request.epoch
        if epoch != self.ser_control.epoch:
            return vfl_pb2.DownloadDataDict(code=vfl_pb2.Code(code=1, desc="server epoch not ready"),
                                            data=None)
        unlearn_power = self.ser_control.get_unlearn_power()
        if unlearn_power is None:
            return vfl_pb2.DownloadDataDict(code=vfl_pb2.Code(code=1, desc="server not get encrypt power."),
                                            data=None)
        else:
            rpc_data_dict = {}
            for cid, data in unlearn_power.items():
                ciphertext = str(data.ciphertext())
                exponent = data.exponent
                rpc_data = vfl_pb2.EncryptData(ciphertext=ciphertext, exponent=exponent)
                rpc_data_dict[cid] = rpc_data
            print(f"rpc_data_dict: {rpc_data_dict}")
            return vfl_pb2.DownloadDataDict(code=vfl_pb2.Code(code=0, desc="get encrypt power successfully"),
                                            data=rpc_data_dict)

    def get_unlearn_data_list(self, request, context):
        epoch = request.epoch
        if epoch != self.ser_control.epoch:
            return vfl_pb2.DownloadDataList(code=vfl_pb2.Code(code=1, desc=f"server epoch not ready."), data_list=None)
        data_dict = self.ser_control.get_unlearn_data_list()
        if data_dict is None:
            return vfl_pb2.DownloadDataList(code=vfl_pb2.Code(code=1, desc=f"server not get data_list."),
                                            data_list=None)
        else:
            rpc_data_dict = {}
            for cid, data_list in data_dict.items():
                rpc_data_list = []
                for data in data_list:
                    rpc_data_list.append(vfl_pb2.EncryptData(ciphertext=str(data.ciphertext()), exponent=data.exponent))
                rpc_data_dict[cid] = vfl_pb2.DataList(data_list=rpc_data_list)
            return vfl_pb2.DownloadDataList(code=vfl_pb2.Code(code=0, desc=f"get data_list successfully."),
                                            data_list=rpc_data_dict)

    def upload_logit_list(self, request, context):
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
        res = self.ser_control.upload_logit_list(cid, ciphertext, exponent)
        return vfl_pb2.DecryptLogit(code=vfl_pb2.Code(code=0, desc=f"get logit list successfully."),
                                    logit=res)
