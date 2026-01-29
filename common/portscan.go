package common

import (
	"bytes"
	"dddd/ddout"
	"dddd/lib/masscan"
	"dddd/structs"
	"dddd/utils"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

func ParsePort(ports string) (scanPorts []int) {
	if ports == "" {
		return
	}
	slices := strings.Split(ports, ",")
	for _, port := range slices {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		upper := port
		if strings.Contains(port, "-") {
			ranges := strings.Split(port, "-")
			if len(ranges) < 2 {
				continue
			}

			startPort, _ := strconv.Atoi(ranges[0])
			endPort, _ := strconv.Atoi(ranges[1])
			if startPort < endPort {
				port = ranges[0]
				upper = ranges[1]
			} else {
				port = ranges[1]
				upper = ranges[0]
			}
		}
		start, _ := strconv.Atoi(port)
		end, _ := strconv.Atoi(upper)
		for i := start; i <= end; i++ {
			scanPorts = append(scanPorts, i)
		}
	}
	scanPorts = utils.RemoveDuplicateElementInt(scanPorts)
	return scanPorts
}

var BackList map[string]struct{}
var BackListLock sync.RWMutex

func PortScanTCP(IPs []string, Ports string, NoPorts string, timeout int) []string {
	var AliveAddress []string

	gologger.AuditTimeLogger("开始TCP端口扫描，端口设置: %s\nTCP端口扫描目标:%s", Ports, strings.Join(IPs, ","))
	ports := ParsePort(Ports)
	noPorts := ParsePort(NoPorts)

	var probePorts []int
	for _, port := range ports {
		ok := false
		for _, nport := range noPorts {
			if nport == port {
				ok = true
				break
			}
		}
		if !ok {
			probePorts = append(probePorts, port)
		}
	}

	if len(probePorts) == 0 || len(IPs) == 0 {
		gologger.Warning().Msg("没有需要扫描的端口或IP")
		return AliveAddress
	}

	IPPortCount := make(map[string]int)
	BackList = make(map[string]struct{})

	totalTargets := len(IPs) * len(probePorts)
	gologger.Info().Msgf("扫描目标总数: %d (IP: %d, 端口: %d)", totalTargets, len(IPs), len(probePorts))

	workers := structs.GlobalConfig.TCPPortScanThreads
	maxWorkers := 500
	if workers > maxWorkers {
		workers = maxWorkers
	}
	if workers > totalTargets {
		workers = totalTargets
	}

	Addrs := make(chan Addr, workers*2)
	results := make(chan string, workers*2)
	var wg sync.WaitGroup

	var successCount int64
	var failedCount int64
	successCountLock := &sync.Mutex{}
	failedCountLock := &sync.Mutex{}

	startTime := time.Now()
	doneScan := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-doneScan:
				return
			case <-ticker.C:
				successCountLock.Lock()
				failedCountLock.Lock()
				currentSuccess := successCount
				currentFailed := failedCount
				successCountLock.Unlock()
				failedCountLock.Unlock()

				elapsed := time.Since(startTime).Seconds()
				totalProgress := int64(currentSuccess) + int64(currentFailed)
				avgSpeed := float64(totalProgress) / elapsed
				eta := float64(totalTargets-int(totalProgress)) / avgSpeed

				gologger.Info().Msgf("扫描进度: 成功=%d, 失败=%d, 总计=%d/%d, 平均速度=%.2f/s, 预计剩余=%.1fs",
					currentSuccess, currentFailed, currentSuccess+currentFailed, totalTargets, avgSpeed, eta)
			}
		}
	}()

	go func() {
		for found := range results {
			AliveAddress = append(AliveAddress, found)

			t := strings.Split(found, ":")
			ip := t[0]

			count, ok := IPPortCount[ip]
			if ok {
				if count > structs.GlobalConfig.PortsThreshold {
					inblack := false
					BackListLock.Lock()
					_, inblack = BackList[ip]
					BackListLock.Unlock()
					if !inblack {
						BackListLock.Lock()
						BackList[ip] = struct{}{}
						BackListLock.Unlock()
						gologger.Error().Msgf("%s 端口数量超出阈值(%d),放弃扫描", ip, structs.GlobalConfig.PortsThreshold)
					}
				}
				IPPortCount[ip] = count + 1
			} else {
				IPPortCount[ip] = 1
			}

			successCountLock.Lock()
			successCount++
			successCountLock.Unlock()

			wg.Done()
		}
	}()

	for i := 0; i < workers; i++ {
		go func(workerID int) {
			for addr := range Addrs {
				PortConnect(addr, results, timeout, &wg)
				wg.Done()
			}
		}(i)
	}

	for _, port := range probePorts {
		for _, host := range IPs {
			wg.Add(1)
			Addrs <- Addr{host, port}
		}
	}
	wg.Wait()
	close(Addrs)
	close(results)
	close(doneScan)

	gologger.AuditTimeLogger("TCP端口扫描结束，发现存活端口: %d 个", len(AliveAddress))

	return AliveAddress
}

type Addr struct {
	ip   string
	port int
}

var PortScan bool

func PortConnect(addr Addr, respondingHosts chan<- string, adjustedTimeout int, wg *sync.WaitGroup) {
	BackListLock.RLock()
	_, inblack := BackList[addr.ip]
	BackListLock.RUnlock()
	if inblack {
		return
	}

	host, port := addr.ip, addr.port

	conn, err := WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%v", host, port), time.Duration(adjustedTimeout)*time.Second)

	var connErr error
	if err != nil {
		connErr = err
	}

	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	if connErr == nil {
		address := host + ":" + strconv.Itoa(port)

		if PortScan {
			ddout.FormatOutput(ddout.OutputMessage{
				Type:     "PortScan",
				IP:       host,
				Port:     strconv.Itoa(port),
				Protocol: "tcp",
			})
		} else {
			ddout.FormatOutput(ddout.OutputMessage{
				Type:          "IPAlive",
				IP:            host,
				AdditionalMsg: "TCP:" + strconv.Itoa(port),
			})
		}

		wg.Add(1)
		respondingHosts <- address
	}
}

func PortScanSYN(IPs []string) []string {
	ips := strings.Join(utils.RemoveDuplicateElement(IPs), "\n")
	err := os.WriteFile("masscan_tmp.txt", []byte(ips), 0666)
	if err != nil {
		return []string{}
	}
	defer os.Remove("masscan_tmp.txt")

	ms := masscan.New(structs.GlobalConfig.MasscanPath)
	ms.SetFileName("masscan_tmp.txt")
	ms.SetPorts("1-65535")
	ms.SetRate(strconv.Itoa(structs.GlobalConfig.SYNPortScanThreads))
	gologger.Info().Msgf("调用masscan进行SYN端口扫描")
	err = ms.Run()
	gologger.AuditTimeLogger("masscan扫描结束")
	if err != nil {
		return []string{}
	}
	hosts, errParse := ms.Parse()
	if errParse != nil {
		gologger.Error().Msgf("masscan结果解析失败")
		return []string{}
	}

	var results []string
	for _, each := range hosts {
		for _, port := range each.Ports {
			results = append(results, each.Address.Addr+":"+port.Portid)
		}
	}
	results = utils.RemoveDuplicateElement(results)
	for _, each := range results {
		// gologger.Silent().Msg("[PortScan] " + each)
		t := strings.Split(each, ":")
		ddout.FormatOutput(ddout.OutputMessage{
			Type: "PortScan",
			IP:   t[0],
			Port: t[1],
		})
	}
	return results
}

// CheckMasScan 校验MasScan是否正确安装
func CheckMasScan() bool {
	var bsenv = ""
	if OS != "windows" {
		bsenv = "/bin/bash"
	}

	var command *exec.Cmd
	if OS == "windows" {
		command = exec.Command("cmd", "/c", structs.GlobalConfig.MasscanPath)
	} else if OS == "linux" {
		command = exec.Command(bsenv, "-c", structs.GlobalConfig.MasscanPath)
	} else if OS == "darwin" {
		command = exec.Command(bsenv, "-c", structs.GlobalConfig.MasscanPath)
	}
	outinfo := bytes.Buffer{}
	command.Stdout = &outinfo
	err := command.Start()
	if err != nil {
		gologger.Error().Msgf("未检测到路径 %v 存在masscan", structs.GlobalConfig.MasscanPath)
		return false
	}
	_ = command.Wait()

	// 未检测到masscan的默认banner
	if !strings.Contains(outinfo.String(), "masscan -p80,8000-8100 10.0.0.0/8 --rate=10000") {
		gologger.Error().Msgf("未检测到路径 %v 存在masscan", structs.GlobalConfig.MasscanPath)
		return false
	}

	return true
}

func RemoveFirewall(ipPorts []string) []string {
	var results []string

	gologger.AuditTimeLogger("移除开放端口过多的目标")

	m := make(map[string][]string)
	for _, ipPort := range ipPorts {
		t := strings.Split(ipPort, ":")
		ip := t[0]
		port := t[1]

		_, ok := m[ip]
		if !ok {
			m[ip] = []string{port}
		} else {
			m[ip] = append(m[ip], port)
		}
	}

	for ip, ports := range m {
		ps := utils.RemoveDuplicateElement(ports)
		if len(ps) >= structs.GlobalConfig.PortsThreshold {
			gologger.Error().Msgf("%s 端口数量超出阈值,已丢弃", ip)
			continue
		}
		for _, p := range ports {
			results = append(results, ip+":"+p)
		}
	}
	return utils.RemoveDuplicateElement(results)
}
