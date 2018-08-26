# -*- coding: UTF-8 -*-
import argparse


class TcpData(object):
    """重组tcpstream

    返回指定流，无重传的tcpstream列表"""

    def __init__(self, tcp_stream, client_ads, server_ads):
        self.tcp_stream = tcp_stream
        self.client_ads = client_ads
        self.server_ads = server_ads

    @staticmethod
    def get_appoint_tcp_stream(data, client_ads, server_ads):
        """将获取的tcpstream进行过滤，筛选出指定的tcpstream，且定义其数据流的方向

        :param client_ads:获取client端的ip，port
        :param server_ads:获取server端的ip，port
        :param data: 获取tcpstream
        :return: 指定tcpstream（含有方向）的列表
        """
        new_stream = []
        for meta in data:
            forward_stream = [
                client_ads[0],
                server_ads[0],
                client_ads[1],
                server_ads[1]]
            reverse_stream = [
                server_ads[0],
                client_ads[0],
                server_ads[1],
                client_ads[1]]
            actual_stream = meta[:4]
            if forward_stream != actual_stream and reverse_stream != actual_stream:
                continue
            if client_ads == [meta[0], meta[2]]:
                new_stream.append(meta[:8] + ['C->S'])
            else:
                new_stream.append(meta[:8] + ['S->C'])
        return new_stream

    @staticmethod
    def find_start_flags(data):
        """传入指定的tcpstream后，过滤出client与server连通后的第三次握手的循环数i

        :param data: 传入指定的tcpstream
        :return: 第三次握手时的循环数i（表明在第几组，9个为一组数据）
        """
        for meta in data:
            flags_syn = meta[6] & 0x02  # 2
            flags_ack = meta[6] & 0x10  # 16
            if not (flags_ack and flags_syn):
                continue
            return data.index(meta) + 1

    def reassemble_tcp(self):
        """重组tcp，过滤出重传，以及多个小时后的同一tcpstream

        返回List of TCPData"""
        reassemble_data = []
        specify_stream = self.get_appoint_tcp_stream(
            self.tcp_stream, self.client_ads, self.server_ads)
        # 第三次握手时的循环数
        start = self.find_start_flags(specify_stream)
        for num, meta in enumerate(specify_stream[start:]):
            flags_push = meta[6] & 0x08  # 8
            flags_ack = meta[6] & 0x10  # 16
            flags_fin = meta[6] & 0x01  # 1
            seq, ack = meta[4], meta[5]
            if flags_fin:
                return reassemble_data
            if not (flags_ack and flags_push):
                continue
            seq += len(meta[7])
            # get next meta
            next_meta = specify_stream[start+num+1]
            if seq == next_meta[5] and ack == next_meta[4]:
                reassemble_data.append(meta)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='renturn a reassemble tcp stream list')
    parser.add_argument(
        '--metas',
        type=list,
        help='tcp stream list',
        required=True)
    parser.add_argument(
        '--client',
        type=list,
        help='address (ip and port) list',
        required=True)
    parser.add_argument(
        '--server',
        type=list,
        help='address (ip and port) list',
        required=True)
    args = parser.parse_args()
