# -*- coding: UTF-8 -*-
import struct
import io
import argparse
import time


class AnalysisPcap(object):
    """通过对pcap文件的解析

    返回TCP下的应用层数据"""

    def __init__(self, pcap_path, http_file):
        self.pcap_path = pcap_path
        self.http_file = http_file

    @staticmethod
    def is_tcp(data):
        """传入数据帧，对数据帧的ip的protocol字段进行判断，若为tcp协议

        返回TRUE，反之则为FALSE"""
        return data[23] == 6

    @staticmethod
    def is_ipv4(data):
        """传入数据帧，对数据帧的以太网层的type字段进行判断，若为IPV4

        返回TRUE，反之则为FALSE"""
        return struct.unpack('H', data[12:14])[0] == 8

    @staticmethod
    def get_tcp_data(data):
        """传入数据帧，对数据帧的Tcp中的应用层数据进行获取

        返回该tcp数据"""
        ip_header_len = (data[14] & 0x0F) * 4
        ip_total_len = struct.unpack(
            '!H', data[16: 18])[0]
        tcp_header_len = (data[14 + ip_header_len + 12] >> 4) * 4
        tcontent = data[14 + ip_header_len +
                        tcp_header_len:14 + ip_total_len]
        return tcontent

    @staticmethod
    def reassemble_tcp_stream(tcp_stream, info_set):
        """重组tcp流，过滤重传的tcpstream

        :param tcp_stream: 未过滤重传的Tcp-stream
        :param info_set: 包含Client和Server端的IP,Port信息的字典
        :return:重组tcpstream的字典
        """

        retcp_stream, filter_stream = dict(), []
        retcp_stream['Client'] = {
            'IP': info_set['source'],
            'Port': info_set['source_port']}
        retcp_stream['Server'] = {
            'IP': info_set['destination'],
            'Port': info_set['destinate_port']}
        retcp_stream['flow'] = set()
        # 过滤重传的tcp，重组Tcp-stream
        for info in tcp_stream.values():
            single_info = '[{},{},{}]'.format(
                info['seq'], info['ack'], info['content'])
            if single_info not in filter_stream:
                filter_stream.append(single_info)
                recontent = 'time:{},direction:{},content:{}'.format(
                    info['time'], info['direction'], info['content'])
                retcp_stream['flow'].add(recontent)
        return retcp_stream

    def appoint_tcp_stream(
            self,
            data,
            info_set,
            pkt_time):
        """

        :param data: 传入数据帧
        :param info_set: 包含Client和Server端的IP,Port信息的字典
        :param pkt_time: 数据包到达的时间戳
        :return: tcp流的字典
        """

        # 对ip地址进行拼接(XXX.XXX.XXX.XXX)
        ip_source = '.'.join([str(i) for i in data[26:30]])
        ip_destinate = '.'.join([str(i) for i in data[30:34]])
        ip_header_len = (data[14] & 0x0F) * 4
        tcp_source = struct.unpack(
            '!H', data[14 + ip_header_len:14 + ip_header_len + 2])[0]
        tcp_destinate = struct.unpack(
            '!H', data[14 + ip_header_len + 2:14 + ip_header_len + 4])[0]
        push = data[14 + ip_header_len + 13] & 0x08
        expect_set = {
            info_set['source'],
            info_set['destination'],
            info_set['destinate_port'],
            info_set['source_port']}
        actual_set = {ip_source, ip_destinate, tcp_source, tcp_destinate}
        # 过滤非指定的以及非http请求的Tcp流
        if expect_set != actual_set:
            return None
        if push != 8:
            return None
        tcp_stream = dict()
        seq = struct.unpack(
            '!I', data[14 + ip_header_len + 4: 14 + ip_header_len + 8])[0]
        ack = struct.unpack(
            '!I', data[14 + ip_header_len + 8: 14 + ip_header_len + 12])[0]
        tcp_stream['seq'], tcp_stream['ack'] = seq, ack
        tcp_stream['push'], tcp_stream['content'] = push, self.get_tcp_data(
            data)
        # 添加Client与Server请求方向
        if info_set['source_port'] == tcp_source:
            direction = 'C—>S'
            tcp_stream['direction'] = direction
            tcp_stream['time'] = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(pkt_time))
        else:
            direction = 'S—>C'
            tcp_stream['direction'] = direction
            tcp_stream['time'] = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(pkt_time))
        return tcp_stream

    def dump_tcp_content(self):
        """传入pcap文件，导出 PCAP 文件中的 TCP 内容

        返回包含所有 TCP 内容的数组"""
        open_file = open(self.pcap_path, 'rb')
        file_length = int(open_file.seek(0, io.SEEK_END))
        open_file.seek(24)
        tcp_content, tcp_stream = [], dict()
        pcap_header = 24
        source, destinate = '192.168.43.158', '183.232.24.222'
        source_port, destinate_port = 64343, 80
        # 组合Client与Server的IP与端口信息
        info_set = {
            'source': source,
            'destination': destinate,
            'source_port': source_port,
            'destinate_port': destinate_port}
        i = 1
        while pcap_header < file_length:
            # Packet header, len=16
            pkt_time_seconds = struct.unpack('I', open_file.read(4))[0]
            pkt_times_ms = struct.unpack('I', open_file.read(4))[0]
            pkt_time = eval('{}.{}'.format(pkt_time_seconds, pkt_times_ms))
            pkt_length = struct.unpack('I', open_file.read(4))[0]
            open_file.seek(4, io.SEEK_CUR)
            # Packet body
            pkt_body = open_file.read(pkt_length)
            if self.is_ipv4(pkt_body) and self.is_tcp(pkt_body):
                stream = self.appoint_tcp_stream(
                    pkt_body, info_set, pkt_time)
                tcontent = self.get_tcp_data(pkt_body)
                tcp_content.append(tcontent)
                if stream:
                    pnumber = '第{}个包'.format(i)
                    tcp_stream[pnumber] = stream
            else:
                tcp_content.append(None)
            i += 1
            pcap_header += 16 + pkt_length
        open_file.close()
        # 打印重组Tcp-stream的信息
        restream = self.reassemble_tcp_stream(tcp_stream, info_set)
        print(restream)
        return tcp_content

    def write_file(self):
        """将有效的应用层数据写入文件http_file中

        返回tcp下的应用层数据文件"""
        tcp_data = self.dump_tcp_content()
        tcp_content = open(self.http_file, 'w', encoding='utf-8')
        for data in tcp_data:
            if data:
                content = 'TCP的应用层数据:{}\n'.format(data)
                tcp_content.write(content)
        tcp_content.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Process pcapfile and sava tcpdata in txt.')
    parser.add_argument(
        '--pcap',
        type=str,
        help='pcap file path',
        required=True)
    parser.add_argument(
        '--save',
        type=str,
        help='sava tcpdata file path',
        required=True)
    args = parser.parse_args()
    t1 = AnalysisPcap(args.pcap, args.save)
    t1.write_file()
