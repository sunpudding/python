# -*- coding:utf-8 -*-
import struct


class Analysis_Pcap(object):
    """通过对pcap文件的解析

    返回应用层数据"""
    def __init__(self):
        self.fpcap = open('te2.pcap', 'rb')
        self.string_data = self.fpcap.read()

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
        with open("result.txt", "w") as self.f:
            self.f.write("Pcap文件的包头内容如下： \n")
        for key in [
            'magic_number',
            'version_major',
            'version_minor',
            'thiszone',
            'sigfigs',
            'snaplen',
                'linktype']:
            # self.ftxt.write(key + " : " + repr(self.pcap_header[key]) + '\n')
            with open("result.txt","a") as self.f:
                self.f.write(key + " : " + repr(self.pcap_header[key]) + '\n')

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

    def Packet_dic(self):
        """对pcap的数据包进行解析，存为字典

        返回应用层数据列表"""
        i = 24
        j = 0
        self.packet_data = []
        self.pcap_packet_header = {}
        while (i < len(self.string_data)):
            # 数据包头各个字段
            # 时间戳高位
            self.pcap_packet_header['GMTtime%s' %
                               j] = struct.unpack('I', self.string_data[i:i + 4])[0]
            # 时间戳低位
            self.pcap_packet_header['MicroTime%s' %
                               j] = struct.unpack('I', self.string_data[i + 4:i + 8])[0]
            # 当前数据区的长度,即抓取到的数据帧长度，由此可以得到下一个数据帧的位置。
            self.pcap_packet_header['caplen%s' % j] = struct.unpack(
                'I', self.string_data[i + 8:i + 12])[0]
            # 离线数据长度,：网络中实际数据帧的长度，一般不大于caplen，多数情况下和Caplen数值相等
            self.pcap_packet_header['len%s' % j] = struct.unpack(
                'I', self.string_data[i + 12:i + 16])[0]
            # 求出此包的包长len
            self.packet_len = struct.unpack('I', self.string_data[i + 12:i + 16])[0]
            # 进行判断后，写入此包应用层数据
            if self.packet_len <= 54:
                self.packet_data.append("无HTTP报文")
            else:
                self.packet_data.append(self.string_data[i + 16 + 54:i + 16 + self.packet_len])
            i = i + self.packet_len + 16
            j += 1
        for i in range(self.Packet_Num()):
            # 先写每一包的包头
            with open("data.txt","a") as self.f:
                self.f.write("这是第" + str(i) + "包数据的包头和数据：" + '\n')
            for key in [
                        'GMTtime%s' %
                        i,
                        'MicroTime%s' %
                        i,
                        'caplen%s' %
                        i,
                        'len%s' %
                        i]:
                with open("data.txt","a") as self.f:
                    self.f.write(key + ' : ' + repr(self.pcap_packet_header[key]) + '\n')
                # 再写数据部分
            with open("data.txt", "a") as self.f:
                self.f.write('HTTP报文内容：' + repr(self.packet_data[i]) + '\n')
        return self.packet_data

    def Packet_Http(self):
        """对pcap的数据包进行解析，将应用层数据http写入本地文件

        返回结果文件"""
        getHttpData = self.Packet_dic()
        for i in getHttpData:
            if i != "无HTTP报文":
                with open("HTTPdata.txt","a") as self.f:
                    self.f.write("这是第%s个包的http数据"%getHttpData.index(i)+ '\n')
                    self.f.write("http数据：%s"%i+ '\n')

    def Pcap_FileClose(self):
        """关闭pcap文件"""
        self.fpcap.close()

if __name__=="__main__":
    Analysis_Pcap().Pcap_fileHeader()
    print(Analysis_Pcap().Packet_Num())
    #可暂不运行此实例
    # Analysis_Pcap().Packet_dic()
    Analysis_Pcap().Packet_Http()
    Analysis_Pcap().Pcap_FileClose()