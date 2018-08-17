from analysispcap.analysisPcap import AnalysisPcap
import binascii


def test_dump_tcp_content():
    """ 测试dump_tcp_content返回的列表中的数据帧"""
    http_file, pcap_file = 'single-http.txt', 'single-frame.pcap'
    http_file1, pcap_file1 = 'http.txt', 'sinatcp.pcap'
    obj = AnalysisPcap(pcap_file, http_file)
    tcp_content = obj.dump_tcp_content()
    tcp_data = binascii.a2b_hex('5902000001000100949370fb0000000000000000')
    assert tcp_content == [tcp_data]
    example = AnalysisPcap(pcap_file1, http_file1)
    data1 = example.dump_tcp_content()
    assert data1[5] == tcp_data
    assert data1[6] != tcp_data


def test_is_ipv4():
    """测试数据帧是否为IPV4协议"""
    http_file, pcap_file = 'http.txt', 'sinatcp.pcap'
    example = AnalysisPcap(pcap_file, http_file)
    data_true = binascii.a2b_hex(
        '2054fa2ad244c821589685a7080045000028688e40008006d291c0a82b9e6f0d645cfb3c01bbcad54c3d86f5ccf15011040084310000')
    data_false = binascii.a2b_hex(
        '2054fa2ad244c821589685a708060001080006040001c821589685a7c0a82b9e2054fa2ad244c0a82b01')
    assert example.is_ipv4(data_true)
    assert example.is_ipv4(data_false) is False


def test_is_tcp():
    """测试数据帧是否为tcp协议"""
    http_file, pcap_file = 'http.txt', 'sinatcp.pcap'
    example = AnalysisPcap(pcap_file, http_file)
    tcp_true = binascii.a2b_hex(
        '2054fa2ad244c821589685a7080045000028688e40008006d291c0a82b9e6f0d645cfb3c01bbcad54c3d86f5ccf15011040084310000')
    tcp_false = binascii.a2b_hex(
        'c821589685a72054fa2ad24408004504006b59a940003411f22e6f1e9f41c0a82b9e1f400fbb0057dc3c02373f0081b17a1b9cf80900000006c25ae346c20de45234640b44883b443a745f3a5f276b1b628e97b2284697d8c70c47febe30cf04328ad9f4f17aa5863db8f279640ad82afd1bc372cca5cf5e03')
    assert example.is_tcp(tcp_true)
    assert example.is_tcp(tcp_false) is False


def test_reassemble_tcp_stream():
    """测试过滤重传的Tcp-Stream"""
    http_file, pcap_file = 'http.txt', 'sinatcp.pcap'
    example = AnalysisPcap(pcap_file, http_file)
    content = b'GET / HTTP/1.1\r\nHost: www.sina.com.cn'
    tcp_stream = {'第一个包':
                  {'seq': 2465436776,
                   'ack': 3158707224,
                   'push': 8,
                   'content': content,
                   'direction': 'C—>S',
                   'time': '2018-07-18 22:25:00'},
                  '第二个包':
                  {'seq': 2465436776,
                      'ack': 3158707224,
                      'push': 8,
                      'content': content,
                      'direction': 'C—>S',
                      'time': '2018-07-18 22:25:00'},
                  '第三个包':
                      {'seq': 2465436899,
                       'ack': 3158707458,
                       'push': 8,
                       'content': content,
                       'direction': 'C—>S',
                       'time': '2018-07-18 22:25:05'}
                  }
    info_set = {
        'source': '192.168.43.158',
        'destination': '183.232.24.222',
        'source_port': 64343,
        'destinate_port': 80}
    restream = {
        'Client': {
            'IP': '192.168.43.158',
            'Port': 64343},
        'Server': {
            'IP': '183.232.24.222',
            'Port': 80},
        'flow': {
            "time:2018-07-18 22:25:00,direction:C—>S,content:b'GET / HTTP/1.1\\r\\nHost: www.sina.com.cn'",
            "time:2018-07-18 22:25:05,direction:C—>S,content:b'GET / HTTP/1.1\\r\\nHost: www.sina.com.cn'"}}
    frestream = {
        'Client': {
            'IP': '192.168.43.158',
            'Port': 64343},
        'Server': {
            'IP': '183.232.24.222',
            'Port': 80},
        'flow': {"time:2018-07-18 22:25:00,direction:C—>S,content:b'GET / HTTP/1.1\\r\\nHost: www.sina.com.cn'"}}
    assert example.reassemble_tcp_stream(tcp_stream, info_set) == restream
    assert example.reassemble_tcp_stream(tcp_stream, info_set) != frestream


def test_appoint_tcp_stream():
    """测试获取的Tcp-stream"""
    data = binascii.a2b_hex('2054fa2ad244c821589685a70800450003df3674400080060398c0a82b9eb7e818defb57005092f39468bc460c185018004478130000474554202f20485454502f312e310d0a486f73743a207777772e73696e612e636f6d2e636e0d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a43616368652d436f6e74726f6c3a206d61782d6167653d300d0a557067726164652d496e7365637572652d52657175657374733a20310d0a557365722d4167656e743a204d6f7a696c6c612f352e30202857696e646f7773204e542031302e303b2057696e36343b2078363429204170706c655765624b69742f3533372e333620284b48544d4c2c206c696b65204765636b6f29204368726f6d652f36372e302e333339362e3939205361666172692f3533372e33360d0a4163636570743a20746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c696d6167652f776562702c696d6167652f61706e672c2a2f2a3b713d302e380d0a4163636570742d456e636f64696e673a20677a69702c206465666c6174650d0a4163636570742d4c616e67756167653a207a682c656e2d55533b713d302e392c656e3b713d302e380d0a436f6f6b69653a20554f523d2c7777772e73696e612e636f6d2e636e2c3b2053475549443d313533313331343139333437375f34323430313239343b2053494e41474c4f42414c3d3132332e3135302e3234342e3235355f313533313331343139342e38353338363b205355423d5f32416b4d73476f387366384e7871774a526d503452784776696259743279415f4569654b61526e37334a524d7948526c2d7944396a716d777374524236423571687732543738705238795a50566c594c45445368345f6d4d4334714f553b20535542503d3030333357725358715078664d37322d5773396a71674d463535353239503944395746644c78476d485556502e4c4f32457a3446575947443b206c786c727474703d313533313730363634353b20434e5a5a44415441313237313233303438393d313634383537373736392d313533313330393330322d6e756c6c253743313533313931383439303b204170616368653d3131372e3133362e302e3133395f313533313932333534322e3431313137353b20554c563d313533313932333534363638323a31303a31303a383a3131372e3133362e302e3133395f313533313932333534322e3431313137353a313533313932333534333330323b206963617374355f6170635f3235323134343d310d0a49662d4d6f6469666965642d53696e63653a205765642c203138204a756c20323031382031343a32303a303320474d540d0a0d0a')
    source = '192.168.43.158'
    destinate = '183.232.24.222'
    tcp_source = 64343
    tcp_destinate = 80
    info_set = {
        'source': source,
        'destination': destinate,
        'source_port': tcp_source,
        'destinate_port': tcp_destinate}
    pkt_time = 1531923900.830477
    content = binascii.a2b_hex('474554202f20485454502f312e310d0a486f73743a207777772e73696e612e636f6d2e636e0d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a43616368652d436f6e74726f6c3a206d61782d6167653d300d0a557067726164652d496e7365637572652d52657175657374733a20310d0a557365722d4167656e743a204d6f7a696c6c612f352e30202857696e646f7773204e542031302e303b2057696e36343b2078363429204170706c655765624b69742f3533372e333620284b48544d4c2c206c696b65204765636b6f29204368726f6d652f36372e302e333339362e3939205361666172692f3533372e33360d0a4163636570743a20746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c696d6167652f776562702c696d6167652f61706e672c2a2f2a3b713d302e380d0a4163636570742d456e636f64696e673a20677a69702c206465666c6174650d0a4163636570742d4c616e67756167653a207a682c656e2d55533b713d302e392c656e3b713d302e380d0a436f6f6b69653a20554f523d2c7777772e73696e612e636f6d2e636e2c3b2053475549443d313533313331343139333437375f34323430313239343b2053494e41474c4f42414c3d3132332e3135302e3234342e3235355f313533313331343139342e38353338363b205355423d5f32416b4d73476f387366384e7871774a526d503452784776696259743279415f4569654b61526e37334a524d7948526c2d7944396a716d777374524236423571687732543738705238795a50566c594c45445368345f6d4d4334714f553b20535542503d3030333357725358715078664d37322d5773396a71674d463535353239503944395746644c78476d485556502e4c4f32457a3446575947443b206c786c727474703d313533313730363634353b20434e5a5a44415441313237313233303438393d313634383537373736392d313533313330393330322d6e756c6c253743313533313931383439303b204170616368653d3131372e3133362e302e3133395f313533313932333534322e3431313137353b20554c563d313533313932333534363638323a31303a31303a383a3131372e3133362e302e3133395f313533313932333534322e3431313137353a313533313932333534333330323b206963617374355f6170635f3235323134343d310d0a49662d4d6f6469666965642d53696e63653a205765642c203138204a756c20323031382031343a32303a303320474d540d0a0d0a')
    tcp_stream = {
        'seq': 2465436776,
        'ack': 3158707224,
        'push': 8,
        'content': content,
        'direction': 'C—>S',
        'time': '2018-07-18 22:25:00'}
    tcp_fstresm = {
        'seq': 2465436775,
        'ack': 3158707223,
        'push': 0,
        'content': content,
        'direction': 'C—>S',
        'time': '2018-07-18 22:25:00'}
    http_file, pcap_file = 'http.txt', 'sinatcp.pcap'
    example = AnalysisPcap(
        pcap_file,
        http_file).appoint_tcp_stream(
        data,
        info_set,
        pkt_time)
    assert tcp_stream == example
    assert example != tcp_fstresm


def test_get_tcp_data():
    """"测试从数据帧中获取的tcp中的数据"""
    http_file, pcap_file = 'http.txt', 'sinatcp.pcap'
    example = AnalysisPcap(pcap_file, http_file)
    tcpdata_true = binascii.a2b_hex(
        '2054fa2ad244c821589685a708004500003c469240008006e605c0a82b9eca6c1771d8570050db1569575186d1415018004140e500005902000001000100949370fb0000000000000000')
    tcpdata_empty = binascii.a2b_hex(
        '2054fa2ad244c821589685a7080045000028688e40008006d291c0a82b9e6f0d645cfb3c01bbcad54c3d86f5ccf15011040084310000')
    assert example.get_tcp_data(tcpdata_true) == binascii.a2b_hex(
        '5902000001000100949370fb0000000000000000')
    assert example.get_tcp_data(tcpdata_true) != binascii.a2b_hex(
        '503231000100949370fb00000000')
    assert example.get_tcp_data(tcpdata_empty) == b''
    assert example.get_tcp_data(tcpdata_empty) != binascii.a2b_hex(
        '503231000100949370fb00000000')


def test_write_file():
    """"测试写入本地的应用层数据文件"""
    http_file, pcap_file = 'http.txt', 'sinatcp.pcap'
    creat_http_file = AnalysisPcap(pcap_file, http_file).write_file()
    read_line = open(http_file, 'r', encoding='utf-8').readlines()
    data_true = binascii.a2b_hex('5902000001000100949370fb0000000000000000')
    data_false = binascii.a2b_hex(
        '000001000100949370fb000000000000000059020000')
    last_data = binascii.a2b_hex(
        '00')
    assert read_line[0] == 'TCP的应用层数据:{}\n'.format(data_true)
    assert read_line[1] != 'TCP的应用层数据:{}\n'.format(data_true)
    assert read_line[0] != 'TCP的应用层数据:{}\n'.format(data_false)
    assert read_line[-1] == 'TCP的应用层数据:{}\n'.format(last_data)
