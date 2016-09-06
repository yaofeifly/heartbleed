# -*- coding:utf-8 -*-
import struct
import urllib
import base64


def get_instance(logger):
    return Heartbleed(logger)

port2protocol = {'443': 'https://', '990': 'ftps://', '465': 'smtps://', '25': 'smtp://', '587': 'smtp://',
                 '563': 'nntps://', '636': 'ldaps://', '993': 'imaps://', '995': 'pop3s://', '21': 'ftp://',
                 '110': 'pop3://', '143': 'imap://'}

ATTACK_SUCCESS = 0
ATTACK_FAILED = 1
UNKNOWN = -1


class Heartbleed(object):
    def __init__(self, logger):
        self._logger = logger

    @staticmethod
    def get_feature():
        return [r'^\x18\x03[\x01-\x03][\x00-\xff]{2}[\x01-\x02]',
                r'^\x18(?:(?:\xfe\xfd)|(?:\xfe\xff))[\x00-\xff]{10}[\x01-\x02]']

    def decode(self, seq, server_ip, server_port):
        """
        result=0 is UNKNOWN, result=1 is ATTACK_FAILED, result=2 is ATTACK_SUCCESS
        response_error is judge the response whether is none
        :param seq:
        :param server_ip:
        :param server_port:
        :return:
        """
        result = 0
        response_error = 1

        if len(seq) == 0:
            return UNKNOWN, None
        special_item = dict()
        vuln_url = urllib.quote(port2protocol.get(server_port, 'ssl://') + ''.join(server_ip))  # TODO ://
        special_item['vuln_url'] = vuln_url
        special_item['vuln_type'] = 'heartbleed'
        special = list()
        special.append(special_item)
        for item in seq:
            request = base64.b64decode(item['request'])  # TODO: modify
            response = base64.b64decode(item['response'])
            if len(request) > 7:
                choose_type = request[0:3]
                typ, ver = struct.unpack('>BH', choose_type)
                if 769 <= ver <= 771:  # TODO: modify
                    data = request[3:8]
                    plaintext_length, hb_type, payload_length = struct.unpack('>HBH', data)
                    if len(response) > 5:
                        res_data = response[0:6]
                        res_typ, res_ver, res_plaintext_length, hb_restype = struct.unpack('>BHHB', res_data)
                    else:
                        response_error = 0
                elif ver == 65279 or ver == 65277:  # TODO:modify
                    if len(request) > 15:
                        data = request[11:16]
                        plaintext_length, hb_type, payload_length = struct.unpack('>HBH', data)
                        if len(response) > 15:
                            res_data = response[0:3]
                            res_data1 = response[11:14]
                            res_typ, res_ver = struct.unpack('>BH', res_data)
                            res_plaintext_length, hb_restype = struct.unpack('>HB', res_data1)
                        else:
                            response_error = 0
                # is heartbeat
                # 判断为心跳请求包
                if typ == 24 and hb_type == 1:
                    '''通过Request数据包中的读取到的plaintext_length可以计算出真实数据中最大的payload_length的长度，如果从数据包中读取的payload_length任然比计算出的最大的payload_length的长度还要大，则可以判断该数据包为构造的数据包，即有可能是heartbleed的攻击包
                    代码中减去的19为heartbeat心跳包类型（Request或Response）占一个字节，payload_length（payload的长度）占两个字节，以及最少的padding的长度占16个字节
                    具体出处详情见rfc6520文档'''
                    if payload_length > plaintext_length - 19:

                        if response_error == 0:
                            result = 1
                        elif response_error == 1:
                            # It may have heartbleed!
                            # 判断为心跳响应包
                            # 判断Request的plaintext_length的长度与Response的plaintext_length长度，如果Response的大于Request的长度即为内存溢出，即心脏出血攻击成功
                            if res_typ == 24 and hb_restype == 2 and res_plaintext_length > plaintext_length:
                                result = 2
                                break
                            else:
                                result = 1

        if result == 0:
            return UNKNOWN, None
        elif result == 1:
            return ATTACK_FAILED, special
        else:
            return ATTACK_SUCCESS, special
