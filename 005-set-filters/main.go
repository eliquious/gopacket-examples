package main

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"

    "log"
    "time"
)

var (
    device       string = "en0"
    snapshot_len int32  = 1024 * 256
    promiscuous  bool   = true
    err          error
    timeout      time.Duration = 30 * time.Second
    handle       *pcap.Handle
)

func main() {
    // Open device
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    // Set filter
    var filter string = "tcp and port 80"
    err = handle.SetBPFFilter(filter)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Only capturing TCP port 80 packets.")

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        // Do something with a packet here.
        // fmt.Println(packet)

        // Let's see if the packet is TCP
        tcpLayer := packet.Layer(layers.LayerTypeTCP)
        if tcpLayer != nil {
            tcp, _ := tcpLayer.(*layers.TCP)

            if tcp.SrcPort == 80 {
                fmt.Println("TCP layer detected.")

                // TCP layer variables:
                // SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
                // Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
                fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
                fmt.Println("Sequence number: ", tcp.Seq)
                fmt.Println()
            }
        }
    }
}
