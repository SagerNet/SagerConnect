package main

import (
	"flag"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chzyer/readline"
	"github.com/sagernet/sagerconnect/api"
	"github.com/sagernet/sagerconnect/core"
	"github.com/sagernet/sagerconnect/tun"
	"github.com/xjasonlyu/tun2socks/log"
)

//go:generate goversioninfo --platform-specific

type scanResult struct {
	ok       bool
	addr     *net.UDPAddr
	nif      *net.Interface
	response *api.Response
}

type ifAddr struct {
	nif  *net.Interface
	inet *net.IPNet
}

func main() {
	log.SetLevel(log.InfoLevel)

	fs := flag.NewFlagSet("SagerConnect", flag.ExitOnError)
	verbose := fs.Bool("v", false, "enable debug log (override)")
	bypass := fs.Bool("b", false, "bypass LAN route (override)")
	selectedIndex := fs.Int("d", -1, "selected device index (skip select)")
	remoteIp := fs.String("a", "", "remote ip address (skip scan)")
	socksPort := fs.Int("socks", 2080, "remote socks port (skip scan)")
	dnsPort := fs.Int("dns", 6450, "remote dns port (skip scan)")
	tunName := fs.String("t", tun.DefaultTunName, "tun interface name")
	mtu := fs.Int("m", 1500, "mtu")
	_ = fs.Parse(os.Args[1:])

	core.Must("su", core.ExecSu())

	var devices []scanResult

	if *remoteIp == "" {
		// scan devices

		deviceName, err := os.Hostname()
		core.Must("get hostname", err)

		query, err := api.MakeQuery(&api.Query{Version: api.Version, DeviceName: deviceName})
		core.Must("make scan query", err)

		//core.Must0(api.ParseQuery(query))

		ifAddrs, err := listIfAddr()
		if len(ifAddrs) == 0 {
			core.Must("get available network interface", err)
		}

		rc := make(chan scanResult)
		for _, ifAddr := range ifAddrs {
			ifAddr := ifAddr
			go func() {
				rErr := scanResult{false, nil, nil, nil}
				conn, err := net.ListenUDP("udp4", &net.UDPAddr{
					IP: ifAddr.inet.IP,
				})

				core.Maybef("create multicast conn on if %s", err, ifAddr.nif.Name)
				if err != nil {
					rc <- rErr
					return
				}
				_, err = conn.WriteTo(query, &net.UDPAddr{
					IP:   net.IPv4bcast,
					Port: 11451,
				})

				core.Maybef("send scan query on %s", err, ifAddr.nif.Name)
				if err != nil {
					rc <- rErr
					return
				}
				_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
				buffer := make([]byte, 2048)
				length, addr, err := conn.ReadFromUDP(buffer)

				if err != nil && strings.Contains(err.Error(), "timeout") {
					rc <- rErr
					return
				}

				core.Maybe("read scan result", err)
				if err != nil {
					rc <- rErr
					return
				}

				core.Maybe("close scan conn", conn.Close())

				response, err := api.ParseResponse(buffer[:length])
				core.Maybe("parse response", err)
				if err != nil {
					rc <- rErr
					return
				}

				rc <- scanResult{
					ok:       true,
					addr:     addr,
					nif:      ifAddr.nif,
					response: response,
				}
			}()
		}

		deviceMap := make(map[string]scanResult)
		for range ifAddrs {
			result := <-rc
			if !result.ok {
				continue
			}
			deviceMap[result.addr.IP.String()] = result
		}
		close(rc)

		for _, device := range deviceMap {
			devices = append(devices, device)
			log.Infof("Found %d. %s (%s)", len(devices), device.response.DeviceName, device.addr.IP.String())
		}
	} else {
		ip := net.ParseIP(*remoteIp)
		if ip == nil {
			log.Fatalf("Failed to parse remote address: %s", *remoteIp)
		}

		devices = append(devices, scanResult{
			ok: true,
			addr: &net.UDPAddr{
				IP:   ip,
				Port: -1,
			},
			response: &api.Response{
				Version:   api.Version,
				SocksPort: uint16(*socksPort),
				DnsPort:   uint16(*dnsPort),
			},
		})
	}

	deviceSize := len(devices)
	var selected *scanResult
	if deviceSize == 0 {
		log.Fatalf("no devices found")
	} else if deviceSize > 1 {
		if *selectedIndex != -1 {
			if deviceSize < *selectedIndex {
				log.Fatalf("Invalid device selected: %d", *selectedIndex)
			}
			selected = &devices[*selectedIndex-1]
		} else {
			for {
				line, err := readline.Line("> Select device to connect: ")
				if err != nil {
					log.Fatalf("failed to read selection: %v", err)
				}
				index, err := strconv.ParseUint(line, 10, 8)
				if err != nil || deviceSize < int(index) {
					log.Errorf("Invalid device selected: %s", line)
					continue
				}
				selected = &devices[index-1]
				break
			}
		}
	} else {
		selected = &devices[0]
	}

	if *remoteIp == "" {
		log.Infof("Selected %s (%s)", selected.response.DeviceName, selected.addr.IP.String())
	}

	if *socksPort != 2080 {
		selected.response.SocksPort = uint16(*socksPort)
	}

	if *socksPort != 6450 {
		selected.response.DnsPort = uint16(*dnsPort)
	}

	if *verbose {
		selected.response.Debug = true
	}

	if *bypass {
		selected.response.BypassLan = true
	}

	log.Infof("SOCKS port: %d", selected.response.SocksPort)
	log.Infof("DNS port: %d", selected.response.DnsPort)
	log.Infof("Enable log: %v", selected.response.Debug)

	if *mtu != 1500 {
		log.Infof("MTU: %d", *mtu)
	}

	tun2socks, err := tun.NewTun2socks(*tunName, selected.addr.IP.String(), int(selected.response.SocksPort), int(selected.response.DnsPort), *mtu, selected.response.Debug)
	core.Must("create tun", err)
	tun2socks.Start()

	cmd, err := tun.AddRoute(*tunName, selected.response.BypassLan)
	if err != nil {
		tun2socks.Close()
		log.Fatalf("Add route failed: %s: %v\n", cmd, err)
	}

	log.Infof("%s started", *tunName)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.SetLevel(log.InfoLevel)
	tun2socks.Close()
	log.Infof("Closed")
}

func listIfAddr() (ifAddrs []ifAddr, err error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, nif := range ifs {
		addrs, err := nif.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			if addr, isIPNet := addr.(*net.IPNet); isIPNet && addr.IP.To4() != nil && !addr.IP.IsLoopback() && !addr.IP.IsLinkLocalUnicast() {
				ifAddrs = append(ifAddrs, ifAddr{
					nif:  &nif,
					inet: addr,
				})
				break
			}
		}
	}

	return
}
