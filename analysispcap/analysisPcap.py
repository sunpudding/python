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
        self.f = open(self.pcap_path, 'rb')

    @staticmethod
    def is_tcp(data):
        """传入数据帧，对数据帧的ip的protocol字段进行判断，若为tcp协议

        返回TRUE，反之则为FALSE"""
        ip_protocol = struct.unpack('b', data[23:24])[0]
        if ip_protocol == 6:
            return True
        else:
            return False

    @staticmethod
    def is_ipv4(data):
        """传入数据帧，对数据帧的以太网层的type字段进行判断，若为IPV4

        返回TRUE，反之则为FALSE"""
        ethernet_type = struct.unpack('H', data[12:14])[0]
        if ethernet_type == 8:
            return True
        else:
            return False

    def dump_tcp_content(self):
        """传入pcap文件，导出 PCAP 文件中的 TCP 内容

        返回包含所有 TCP 内容的数组"""

        read_pcap = self.f.read()
        self.f.seek(24)
        tcp_content = []
        pcap_header = 24
        while pcap_header < len(read_pcap):
            # Packet header, len=16
            self.f.seek(8, io.SEEK_CUR)
            pkt_length = struct.unpack('I', self.f.read(4))[0]
            self.f.seek(4, io.SEEK_CUR)
            # Packet body
            pkt_body = self.f.read(pkt_length)
            if self.is_ipv4(pkt_body):
                if self.is_tcp(pkt_body):
                    header = hex(struct.unpack(
                        'b', pkt_body[14:15])[0])
                    ip_header_len = (int(header, 16) & 0x0F) * 4
                    ip_total_len = int(hex(struct.unpack(
                        '!H', pkt_body[16: 18])[0]), 16)
                    theader_len = hex(struct.unpack(
                        '!b',
                        pkt_body[14 + ip_header_len + 12:14 + ip_header_len + 13])[0])
                    tcp_header_len = abs(int(theader_len, 16) >> 4) * 4
                    tcontent = pkt_body[14 + ip_header_len +
                                        tcp_header_len:14 + ip_total_len]
                    tcp_content.append(tcontent)
                else:
                    tcp_content.append(None)
            else:
                tcp_content.append(None)
            pcap_header += 16 + pkt_length
        self.f.close()
        return tcp_content

    def write_file(self):
        """将应用层数据写入文件http_file中

        返回tcp下的应用层数据文件"""
        tcp_data = self.dump_tcp_content()
        tcp_content = open(self.http_file, 'w+', encoding='utf-8')
        i = 0
        while i < len(tcp_data):
            if tcp_data[i] is None or tcp_data[i] == b'':
                pass
            else:
                tcp_content.write('TCP的应用层数据:' + str(tcp_data[i]) + '\n')
            i += 1
        tcp_content.close()
        with open(self.http_file, 'r', encoding="utf-8") as f:
            rdtcp_data = f.readlines()
        return rdtcp_data


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
