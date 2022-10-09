import argparse

from vfl import *

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--cid', required=True, help='fled client cid')
    args = parser.parse_args()
    cid = args.cid
    vfl_client = VflClient(cid)
    vfl_client.start_task()
