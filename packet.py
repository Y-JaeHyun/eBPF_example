#!/usr/bin/env python3.8


from scapy.all import *
import threading
import time
import argparse


def server(d, port, loop, ip):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as s:
            #with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
            s.bind((ip, port))
            s.listen(5)
            conn, addr = s.accept()

            for i in range(loop):
                res = conn.recv(1024)
                print(f'{i} : client to server msg :{res.decode()}')
                byteData = d.__bytes__()
                conn.sendall(byteData)

            conn.close()
            s.close()
    except Exception as e:
            print(e)


def client(d, port, loop, ip):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as s:
        #with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
            s.connect((ip, port))

            for i in range(loop):
                time.sleep(1)
                byteData = d.__bytes__()
                s.sendall(byteData)
                res = s.recv(1024)
                print(f'{i} : server to client msg :{res.decode()}')

    except Exception as e:
        print(e)


def packetShow(packetList):
    #packet print
        for p in packetList:
            print ("================================")
            p.show()


def checkAgentData():
    pass

def packetQueue(packet):
    print(f"received queue {packet.time} diff: {time.time() - packet.time} ")
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='NPM Agent Test Tool')
    parser.add_argument('-t', '--type', default='local', type=str, help='run type - local, server, client (default : local)')
    parser.add_argument('-i', '--interface', default='lo', type=str,  help='sniff network interface(default : lo)')
    parser.add_argument('-c', '--connect_ip', default='127.0.0.1', type=str,  help='connect ip (default : 127.0.0.1)')
    parser.add_argument('-pr', '--proto', default='TCP', type=str, help='protocol(default : TCP)')
    parser.add_argument('-p', '--port', default=8080, type=int, help='server port(default : 8888)')
    parser.add_argument('-cds', '--client_data_size', default=100, type=int, help='client data size(default : 100)')
    parser.add_argument('-sds', '--server_data_size', default=50, type =int, help='sever data size(default : 50)')
    parser.add_argument('-l', '--loop', default=10, type=int, help='data send loop, server send + client send 1 Loop (default : 10)')
    parser.add_argument('-w', '--write', help='write packet file (default : None)')
    parser.add_argument('-s', '--show', default=False, type=bool, help='show packet in console (default : False)')

    args = parser.parse_args()

    f = args.proto.lower() + " port " + str(args.port)
 
    sniffer = AsyncSniffer(iface=args.interface, filter = f)
    sniffer.start()
    print ("Start Sniff")

    #비동기 이기 때문에 실제 Setup 완료까지 대기.
    #동기 수행시 sniffer 종료시점이 지정되어야함 (count, packet 조건 등)
    time.sleep(1)
    if sniffer.running == False:
        time.sleep(1)
    

    if args.type == "local":
        bindIp = "127.0.0.1"
        connectIp = "127.0.0.1"

        serverData = RandString(args.server_data_size)
        serverThread = threading.Thread(target=server, args=(serverData, args.port, args.loop, bindIp))
        serverThread.start()

        clientData = RandString(args.client_data_size)
        clientThread = threading.Thread(target=client, args=(clientData, args.port, args.loop, connectIp))
        clientThread.start()

        serverThread.join()
        clientThread.join()
    elif args.type == "server":
        bindIp = "0.0.0.0"

        serverData = RandString(args.server_data_size)
        serverThread = threading.Thread(target=server, args=(serverData, args.port, args.loop, bindIp))
        serverThread.start()

        serverThread.join()
    elif args.type == "client":
        connectIp = args.connect_ip

        clientData = RandString(args.client_data_size)
        clientThread = threading.Thread(target=client, args=(clientData, args.port, args.loop, connectIp))
        clientThread.start()
        clientThread.join()

    else:
        print ("Type Error - local / server / client")
    print("please wait")    

    time.sleep(5)

    packetHash = []
    packetList = []

    sniffer.stop()

    #lo의 경우 server/clinet 두개다 잡혀서 pcap 보기 어려움. 해시값 기준으로 중복 제거
    #단, 중복 제거된 경우  서버측 정보와 클라이언트 정보가 뒤섞이기 때문에 time 값을 통한 latency 측정은 의미 없음
    if False:
        for p in sniffer.results:
            h = hash(raw(p))
            if h in packetHash:
                continue
            packetHash.append(h)
            packetList.append(p)
    else:
        for p in sniffer.results:
            packetList.append(p)

    #packet write
    if args.write != None:
        wrpcap(args.write, packetList)

    if args.show:
        packetShow(packetList)

    print ("hello")
