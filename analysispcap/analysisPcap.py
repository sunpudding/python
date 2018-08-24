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
    def is_ipv4_tcp(data):
        """传入数据帧，对数据帧的以太网层的type字段以及ip的protocol字段进行判断，若为IPV4下的tcp协议

        返回TRUE，反之则为FALSE"""
        return struct.unpack('H', data[12:14])[0] == 8 and data[23] == 6

    @staticmethod
    def get_tcp_data(data):
        """传入数据帧，对数据帧的Tcp中的 src, dst,src_port,dst_port, seq, ack, flags, content

        返回该tcp数据列表"""
        ip_header_len = (data[14] & 0x0F) * 4
        ip_total_len = struct.unpack(
            '!H', data[16: 18])[0]
        src_ip = '.'.join([str(i) for i in data[26:30]])
        dst_ip = '.'.join([str(i) for i in data[30:34]])
        src_port = struct.unpack(
            '!H', data[14 + ip_header_len:14 + ip_header_len + 2])[0]
        dst_port = struct.unpack(
            '!H', data[14 + ip_header_len + 2:14 + ip_header_len + 4])[0]
        seq = struct.unpack(
            '!I', data[14 + ip_header_len + 4:14 + ip_header_len + 8])[0]
        ack = struct.unpack(
            '!I', data[14 + ip_header_len + 8:14 + ip_header_len + 12])[0]
        flags = data[14 + ip_header_len + 13]
        tcp_header_len = (data[14 + ip_header_len + 12] >> 4) * 4
        tcontent = data[14 + ip_header_len +
                        tcp_header_len:14 + ip_total_len]
        return [src_ip, dst_ip, src_port, dst_port, seq, ack, flags, tcontent]

    def dump_tcp_content(self):
        """传入pcap文件，导出 PCAP 文件中的 TCP 内容

        返回包含所有 TCP 内容的数组"""
        open_file = open(self.pcap_path, 'rb')
        file_length = int(open_file.seek(0, io.SEEK_END))
        open_file.seek(24)
        pcap_header = 24
        tcp_stream = []
        while pcap_header < file_length:
            # Packet header, len=16
            open_file.seek(8, io.SEEK_CUR)
            pkt_length = struct.unpack('I', open_file.read(4))[0]
            open_file.seek(4, io.SEEK_CUR)
            # Packet body
            pkt_body = open_file.read(pkt_length)
            if self.is_ipv4_tcp(pkt_body):
                data = self.get_tcp_data(pkt_body)
                tcp_stream.extend(data)
            pcap_header += 16 + pkt_length
        open_file.close()
        return tcp_stream

    def write_file(self):
        """将有效的应用层数据写入文件http_file中

        返回tcp下的应用层数据文件"""
        tcp_data = self.dump_tcp_content()
        tcp_content = open(self.http_file, 'w', encoding='utf-8')
        i = 0
        while i < len(tcp_data):
            if tcp_data[i + 7]:
                content = 'TCP的应用层数据:{}\n'.format(tcp_data[i + 7])
                tcp_content.write(content)
            i += 8
        tcp_content.close()


if __name__ == "__main__":
    # AnalysisPcap
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
    t1.dump_tcp_content()
    t1.write_file()
