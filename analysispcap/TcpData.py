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
        i = 0
        new_stream = []
        while i < len(data):
            expect_stream = {
                client_ads[0],
                client_ads[1],
                server_ads[0],
                server_ads[1]}
            actual_stream = set(data[i:i + 4])
            if expect_stream != actual_stream:
                i += 8
                continue
            if client_ads == [data[i], data[i + 2]]:
                new_stream.extend(data[i:i + 8])
                new_stream.append('C->S')
            else:
                new_stream.extend(data[i:i + 8])
                new_stream.append('S->C')
            i += 8
        return new_stream

    @staticmethod
    def find_start_flags(data):
        """传入指定的tcpstream后，过滤出client与server连通后的第三次握手的循环数i

        :param data: 传入指定的tcpstream
        :return: 第三次握手时的循环数i（表明在第几组，9个为一组数据）
        """
        i = 0
        while i < len(data):
            flags_syn = data[i + 6] & 0x02  # 2
            flags_ack = data[i + 6] & 0x10  # 16
            if not (flags_ack and flags_syn):
                i += 9
                continue
            return i + 9

    def reassemble_tcp(self):
        """重组tcp，过滤出重传，以及多个小时后的同一tcpstream

        返回List of TCPData"""
        reassemble_data = []
        specify_stream = self.get_appoint_tcp_stream(
            self.tcp_stream, self.client_ads, self.server_ads)
        # 第三次握手时的循环数i
        start = self.find_start_flags(specify_stream)
        while start < len(specify_stream):
            flags_push = specify_stream[start + 6] & 0x08  # 8
            flags_ack = specify_stream[start + 6] & 0x10  # 16
            flags_fin = specify_stream[start + 6] & 0x01  # 1
            seq, ack = specify_stream[start + 4], specify_stream[start + 5]
            if flags_fin:
                return reassemble_data
            if not (flags_ack and flags_push):
                start += 9
                continue
            seq += len(specify_stream[start + 7])
            start += 9
            ack_data = {specify_stream[start + 4], specify_stream[start + 5]}
            if ack_data == {ack, seq}:
                reassemble_data.extend(specify_stream[start - 9:start])


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
    newdata = TcpData(args.metas, args.client, args.server)
    newdata.reassemble_tcp()
