// main.go
package main

import (
	"fmt"
	"net"

	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	//"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func CaptureSaveFile() {
	return
}

func main() {
	//创建目录
	os.MkdirAll("capture_packet", 0777)

	//创建文件名字
	t := time.Now()
	fil := "capture_packet" + "/" + "capture" + "_" + t.Format("20060102150405") + ".pcap"

	//创建文件
	F, _ := os.Create(fil)

	//填充wireshark头
	W := pcapgo.NewWriter(F)
	W.WriteFileHeader(1024, layers.LinkTypeEthernet)

	//设置监听地址
	Addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:"+strconv.Itoa(8099))

	if nil != err {
		fmt.Println("resulve udp addr fail")
		return
	} else {
		//创建udp连接
		Conn, err := net.ListenUDP("udp", Addr)
		if nil != err {
			fmt.Println("create conn fail")
			return
		} else {
			fmt.Println("Capture Start")
			for {
				//套接字接收缓存
				buffer := make([]byte, 65535)

				//接收数据
				num, _, err := Conn.ReadFromUDP(buffer)
				if nil != err {
					continue
				} else {
					captureInfo := gopacket.CaptureInfo{
						Timestamp:      time.Now().UTC(),
						CaptureLength:  num,
						Length:         num,
						InterfaceIndex: 0,
					}
					//写入pcap数据包头以及数据
					W.WritePacket(captureInfo, buffer[:num])
					F.Seek(0, os.SEEK_END)
				}
			}
		}
	}

	chSignal := make(chan os.Signal, 5)
	//signal.Notify(chSignal)
	//监听指定信号
	signal.Notify(chSignal, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT,
		syscall.SIGSEGV, syscall.SIGABRT)

	fmt.Println("capture server start")

	//阻塞直至有信号传入
	sig := <-chSignal
	switch sig {
	case syscall.SIGSEGV, syscall.SIGABRT:
	default:
	}
	fmt.Println("*************Server Recive signal %s, program exit", sig.String())
	F.Close()
	fmt.Println("CLOSE")
	time.After(1 * time.Second)
}
