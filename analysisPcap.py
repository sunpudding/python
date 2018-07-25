# -*- coding: UTF-8 -*-
import struct
import argparse


class Analysis_Pcap(object):
    """通过对pcap文件的解析

    返回TCP下的应用层数据"""

    def __init__(self):
        """传入两个必填参数--pcap --save"""
        parser = argparse.ArgumentParser(
            description='Process pcapfile and sava tcpdata in txt.')
        parser.add_argument('--pcap', type=str, help='pcap file path')
        parser.add_argument('--save', type=str, help='sava tcpdata file path')
        self.args = parser.parse_args()
        self.fpcap = open(self.args.pcap, 'rb')
        self.string_data = self.fpcap.read()
        self.ftxt = open("pcapHeader.txt", 'w')
        self.TcpdataTxt = open(self.args.save, 'w')

    def Pcap_fileHeader(self):
        """对pcap的文件包头进行解析

        写入本地txt"""
        self.pcap_header = {}
        # 用来识别文件自己和字节顺序
        self.pcap_header['magic_number'] = self.string_data[0:4]
        # 当前文件主要的版本号
        self.pcap_header['version_major'] = self.string_data[4:6]
        # 当前文件次要的版本号
        self.pcap_header['version_minor'] = self.string_data[6:8]
        # GMT和本地时间的相差，用秒来表示。
        self.pcap_header['thiszone'] = self.string_data[8:12]
        # 最大的存储长度
        self.pcap_header['sigfigs'] = self.string_data[12:16]
        # 每个包的最大长度
        self.pcap_header['snaplen'] = self.string_data[16:20]
        # 链路类型
        self.pcap_header['linktype'] = self.string_data[20:24]
        self.ftxt.write("Pcap文件的包头内容如下： \n")
        for key in [
            'magic_number',
            'version_major',
            'version_minor',
            'thiszone',
            'sigfigs',
            'snaplen',
                'linktype']:
            self.ftxt.write(key + " : " + repr(self.pcap_header[key]) + '\n')

    def Packet_Num(self):
        """对pcap的文件包头进行解析

        返回数据包的数量"""
        i = 24
        self.p_num = 0
        while (i < len(self.string_data)):
            lens = self.string_data[i + 12:i + 16]
            plen = struct.unpack('I', lens)[0]
            i = i + plen + 16
            self.p_num += 1
        return self.p_num

    def Packet_TcpData(self):
        """对pcap的数据包内的数据进行解析

        返回tcp下的应用层数据文件"""
        i = 24
        self.TcpdataTxt.write("以下为IPV4协议下的TCP应用层数据" + '\n')
        while (i < len(self.string_data)):
            # 获取以太网上层的type类型
            self.type = hex(struct.unpack('!H',
                                          self.string_data[i + 16 + 12:i + 16 + 14])[0])

            # 判断是否为IPV4协议（'0x0800'）
            if self.type == '0x800':
                self.protocol = hex(struct.unpack(
                    'b', self.string_data[i + 16 + 23:i + 16 + 24])[0])
                # 判断是否为TCP协议（‘0x06’）
                if self.protocol == '0x6':
                    # 获取ip包的总长度
                    self.ipLen = int(
                        hex(struct.unpack('!H', self.string_data[i + 16 + 16:i + 16 + 18])[0]), 16)
                # 获取ip包的报头长度
                    self.ipHeader = hex(struct.unpack(
                        'b', self.string_data[i + 16 + 14:i + 16 + 15])[0])
                    self.ipHeaderLen = (int(self.ipHeader, 16) & 0x0F) * 4
                # 获取TCP包的报头长度
                    self.TcpHlen = hex(struct.unpack(
                        '!b', self.string_data[i + 16 + 14 + self.ipHeaderLen + 12:i + 16 + 14 + self.ipHeaderLen + 13])[0])
                    self.TcpHeaderlen = abs(int(self.TcpHlen, 16) >> 4) * 4
                    # 获取tcp下的应用层数据
                    self.Tcpdata = self.string_data[i +
                                                    16 +
                                                    14 +
                                                    self.ipHeaderLen +
                                                    self.TcpHeaderlen:i +
                                                    16 +
                                                    14 +
                                                    self.ipLen]
                    if len(self.Tcpdata) != 0:
                        self.TcpdataTxt.write(
                            "TCP的应用层数据：%s" %
                            self.Tcpdata + '\n')
                    else:
                        self.TcpdataTxt.write("TCP的应用层数据：无" + '\n')
                else:
                    self.TcpdataTxt.write("非TCP协议！" + '\n')
            else:
                self.TcpdataTxt.write("此数据包不遵循IPV4协议" + '\n')
            self.packet_len = struct.unpack(
                'I', self.string_data[i + 12:i + 16])[0]
            i = i + self.packet_len + 16

    def Pcap_FileClose(self):
        """关闭pcap文件以及txt文件"""
        self.fpcap.close()
        self.ftxt.close()
        self.TcpdataTxt.close()


if __name__ == "__main__":
    t1 = Analysis_Pcap()
    t1.Pcap_fileHeader()
    t1.Packet_Num()
    t1.Packet_TcpData()
    t1.Pcap_FileClose()
