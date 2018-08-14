# -*- coding: UTF-8 -*-
import struct
import io
import argparse


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

    def appoint_tcp_stream(
            self,
            data,
            source,
            destinate,
            source_port,
            destinate_port):
        """指定tcp流

        :param data: 传入数据帧
        :param source: 传入源ip地址
        :param destinate: 传入目的ip地址
        :param source_port: 传入源tcp端口
        :param destinate_port: 传入目的tcp端口
        :return: tcp流以字典的形式 {Sequence number:Tcp content}
        """
        # 对ip地址进行拼接(XXX.XXX.XXX.XXX)
        ip_source = '.'.join([str(i) for i in data[26:30]])
        ip_destinate = '.'.join([str(i) for i in data[30:34]])
        ip_header_len = (data[14] & 0x0F) * 4
        tcp_source = struct.unpack(
            '!H', data[14 + ip_header_len:14 + ip_header_len + 2])[0]
        tcp_destinate = struct.unpack(
            '!H', data[14 + ip_header_len + 2:14 + ip_header_len + 4])[0]
        tcp_stream = dict()
        if ip_source == source and ip_destinate == destinate:
            if tcp_source == source_port and tcp_destinate == destinate_port:
                seq = struct.unpack(
                    '!I', data[14 + ip_header_len + 4: 14 + ip_header_len + 8])[0]
                content = self.get_tcp_data(data)
                tcp_stream[seq] = content
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
        while pcap_header < file_length:
            # Packet header, len=16
            open_file.seek(8, io.SEEK_CUR)
            pkt_length = struct.unpack('I', open_file.read(4))[0]
            open_file.seek(4, io.SEEK_CUR)
            # Packet body
            pkt_body = open_file.read(pkt_length)
            if self.is_ipv4(pkt_body):
                if self.is_tcp(pkt_body):
                    stream = self.appoint_tcp_stream(
                        pkt_body, source, destinate, source_port, destinate_port)
                    tcp_stream.update(stream)
                    tcontent = self.get_tcp_data(pkt_body)
                    tcp_content.append(tcontent)
                else:
                    tcp_content.append(None)
            else:
                tcp_content.append(None)
            pcap_header += 16 + pkt_length
        open_file.close()
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
