package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/mdns"
)

// Asset 保存一个 mDNS 服务实例及其 TCP 深度识别结果。
type Asset struct {
	IP       string            `json:"ip"`
	IPv6     string            `json:"ipv6,omitempty"`
	Port     int               `json:"port"`
	Service  string            `json:"service"`
	Host     string            `json:"host"`
	Hostname string            `json:"hostname"`
	TTL      uint32            `json:"ttl"`
	TXT      map[string]string `json:"txt,omitempty"`
	Banner   string            `json:"banner,omitempty"`
}

type scanner struct {
	network *net.IPNet
	ports   map[int]bool
	timeout time.Duration
}

func parsePorts(spec string) (map[int]bool, error) {
	result := make(map[int]bool)
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, "-", 2)
		start, err := strconv.Atoi(parts[0])
		if err != nil || start < 1 || start > 65535 {
			return nil, fmt.Errorf("无效端口: %s", item)
		}
		end := start
		if len(parts) == 2 {
			end, err = strconv.Atoi(parts[1])
			if err != nil || end < start || end > 65535 {
				return nil, fmt.Errorf("无效端口范围: %s", item)
			}
		}
		for port := start; port <= end; port++ {
			result[port] = true
		}
	}
	if len(result) == 0 {
		return nil, errors.New("端口范围不能为空")
	}
	return result, nil
}

func parseTXT(fields []string) map[string]string {
	txt := make(map[string]string)
	for _, field := range fields {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) == 2 {
			txt[parts[0]] = parts[1]
		} else if field != "" {
			txt[field] = ""
		}
	}
	return txt
}

func (s *scanner) inScope(ip net.IP) bool {
	return ip != nil && s.network.Contains(ip)
}

func (s *scanner) probe(ctx context.Context, ip string, port int) string {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: s.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(s.timeout))
	buffer := make([]byte, 4096)
	count, _ := conn.Read(buffer)
	if count > 0 {
		return strings.TrimSpace(string(buffer[:count]))
	}
	// HTTP 服务通常等待请求后才返回 banner，因此补发一个最小请求。
	if port == 80 || port == 443 || port == 5000 || port == 8080 || port == 8443 {
		_ = conn.SetWriteDeadline(time.Now().Add(s.timeout))
		_, _ = io.WriteString(conn, "GET / HTTP/1.0\r\nHost: "+ip+"\r\nUser-Agent: mdnsmap\r\n\r\n")
		_ = conn.SetReadDeadline(time.Now().Add(s.timeout))
		count, _ = conn.Read(buffer)
		if count > 0 {
			return strings.TrimSpace(string(buffer[:count]))
		}
	}
	return ""
}

func (s *scanner) queryService(ctx context.Context, service string) ([]Asset, error) {
	entries := make(chan *mdns.ServiceEntry, 128)
	params := mdns.DefaultParams(service)
	params.Timeout = s.timeout
	params.Entries = entries
	params.DisableIPv6 = false
	queryCtx, cancel := context.WithTimeout(ctx, s.timeout+250*time.Millisecond)
	defer cancel()
	queryDone := make(chan error, 1)
	go func() { queryDone <- mdns.QueryContext(queryCtx, params) }()
	var assets []Asset
	for {
		select {
		case entry := <-entries:
			if entry == nil {
				continue
			}
			ip := entry.AddrV4
			if ip == nil {
				ip = entry.Addr
			}
			if ip == nil || !s.inScope(ip) || !s.ports[entry.Port] {
				continue
			}
			asset := Asset{IP: ip.String(), Port: entry.Port, Service: cleanService(service), Host: instanceDisplayName(entry.Name), Hostname: strings.TrimSuffix(entry.Host, "."), TTL: 120, TXT: parseTXT(entry.InfoFields)}
			if entry.AddrV6IPAddr != nil {
				asset.IPv6 = entry.AddrV6IPAddr.IP.String()
			} else if entry.AddrV6 != nil {
				asset.IPv6 = entry.AddrV6.String()
			}
			asset.Banner = s.probe(ctx, asset.IP, asset.Port)
			assets = append(assets, asset)
		case err := <-queryDone:
			return assets, err
		case <-queryCtx.Done():
			return assets, nil
		}
	}
}

func cleanService(service string) string {
	service = strings.TrimSuffix(service, ".local")
	service = strings.TrimSuffix(service, ".")
	return strings.TrimPrefix(service, "_")
}

// serviceTypeFromName 从 mDNS 实例全名提取 _服务._tcp.local 类型名。
func serviceTypeFromName(name string) string {
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	for i := 0; i+2 < len(parts); i++ {
		if strings.HasPrefix(parts[i], "_") && (parts[i+1] == "_tcp" || parts[i+1] == "_udp") {
			return strings.Join(parts[i:i+3], ".")
		}
	}
	return name
}

// instanceDisplayName 将“设备._http._tcp.local”转换为示例中的设备名。
func instanceDisplayName(name string) string {
	name = strings.TrimSuffix(name, ".")
	if index := strings.Index(name, "._"); index > 0 {
		return name[:index]
	}
	return name
}

func (s *scanner) scan(ctx context.Context) ([]Asset, error) {
	meta := make(chan *mdns.ServiceEntry, 128)
	params := mdns.DefaultParams("_services._dns-sd._udp")
	params.Timeout = s.timeout
	params.Entries = meta
	ctx, cancel := context.WithTimeout(ctx, s.timeout+300*time.Millisecond)
	defer cancel()
	if err := mdns.QueryContext(ctx, params); err != nil {
		return nil, err
	}
	services := make(map[string]bool)
	for {
		select {
		case entry := <-meta:
			if entry != nil {
				name := serviceTypeFromName(entry.Name)
				if name != "" {
					services[name] = true
				}
			}
		default:
			goto queried
		}
	}
queried:
	if len(services) == 0 {
		// 常见服务类型作为显式查询，便于设备未发布 meta-query 时仍能发现资产。
		services["_http._tcp.local"] = true
		services["_workstation._tcp.local"] = true
		services["_smb._tcp.local"] = true
	}
	var all []Asset
	var mu sync.Mutex
	var wg sync.WaitGroup
	for service := range services {
		service := service
		wg.Add(1)
		go func() {
			defer wg.Done()
			assets, _ := s.queryService(ctx, service)
			mu.Lock()
			all = append(all, assets...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(all, func(i, j int) bool {
		if all[i].IP != all[j].IP {
			return all[i].IP < all[j].IP
		}
		if all[i].Port != all[j].Port {
			return all[i].Port < all[j].Port
		}
		return all[i].Service < all[j].Service
	})
	return dedupe(all), nil
}

func dedupe(input []Asset) []Asset {
	seen := make(map[string]bool)
	out := make([]Asset, 0, len(input))
	for _, asset := range input {
		key := fmt.Sprintf("%s:%d:%s:%s", asset.IP, asset.Port, asset.Service, asset.Hostname)
		if !seen[key] {
			seen[key] = true
			out = append(out, asset)
		}
	}
	return out
}

func printReport(w io.Writer, assets []Asset) {
	for _, asset := range assets {
		fmt.Fprintf(w, "  %d/tcp %s:\n", asset.Port, asset.Service)
		fmt.Fprintf(w, "    Name=%s\n    IPv4=%s\n", asset.Host, asset.IP)
		if asset.IPv6 != "" {
			fmt.Fprintf(w, "    IPv6=%s\n", asset.IPv6)
		}
		fmt.Fprintf(w, "    Hostname=%s\n    TTL=%d\n", asset.Hostname, asset.TTL)
		keys := make([]string, 0, len(asset.TXT))
		for key := range asset.TXT {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if asset.TXT[key] == "" {
				fmt.Fprintf(w, "    %s\n", key)
			} else {
				fmt.Fprintf(w, "    %s=%s\n", key, asset.TXT[key])
			}
		}
		if asset.Banner != "" {
			fmt.Fprintf(w, "    banner=%s\n", strings.ReplaceAll(asset.Banner, "\n", "\\n"))
		}
	}
}

func main() {
	var cidr, portSpec string
	var timeout time.Duration
	var jsonOutput bool
	flag.StringVar(&cidr, "cidr", "", "待测 IPv4/IPv6 网段，例如 192.168.1.0/24")
	flag.StringVar(&portSpec, "ports", "1-65535", "端口范围，例如 80,443,5000-5010")
	flag.DurationVar(&timeout, "timeout", 2*time.Second, "mDNS 查询和 banner 探测超时")
	flag.BoolVar(&jsonOutput, "json", false, "以 JSON 输出资产")
	flag.Parse()
	if cidr == "" {
		fmt.Fprintln(os.Stderr, "用法: mdnsmap -cidr 192.168.1.0/24 -ports 1-10000 [-json]")
		os.Exit(2)
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "无效网段:", err)
		os.Exit(2)
	}
	ports, err := parsePorts(portSpec)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	assets, err := (&scanner{network: network, ports: ports, timeout: timeout}).scan(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "mDNS 查询失败:", err)
		os.Exit(1)
	}
	if jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(assets)
		return
	}
	fmt.Println("services:")
	printReport(os.Stdout, assets)
}
