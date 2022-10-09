import os
from grpc_tools import protoc
from pathlib import Path

if __name__ == '__main__':
    path = Path(os.path.realpath(__file__)).parent
    protos = path.rglob('*.proto')

    for proto in protos:
        print(f'Generateing "{proto.stem}"')
        res = protoc.main(['grpc_tools.protoc',
                           f'-I{path}',
                           f'--python_out={path}',
                           f'--grpc_python_out={path}',
                           f'{proto}'])
        if res != 0:
            raise Exception(f'Failed.')

        fname = path / f'{proto.stem}_pb2_grpc.py'
        with fname.open('r+', encoding='utf-8') as f:
            cont = f.read()
            f.seek(0)
            cont = cont.replace(f'import {proto.stem}_pb2 as', f'from . import {proto.stem}_pb2 as')
            f.write(cont)

        print('Done and redirected.')
