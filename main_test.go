package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParsePorts(t *testing.T) {
	ports, err := parsePorts("80,443,5000-5002")
	if err != nil || len(ports) != 5 || !ports[5001] {
		t.Fatalf("端口解析结果错误: %#v %v", ports, err)
	}
}

func TestParseTXT(t *testing.T) {
	want := map[string]string{"model": "TS-464C", "flag": ""}
	if got := parseTXT([]string{"model=TS-464C", "flag"}); !reflect.DeepEqual(got, want) {
		t.Fatalf("TXT 解析错误: %#v", got)
	}
}

func TestScannerScope(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.168.1.0/24")
	s := scanner{network: network}
	if !s.inScope(net.ParseIP("192.168.1.20")) || s.inScope(net.ParseIP("10.0.0.1")) {
		t.Fatal("网段过滤错误")
	}
}

func TestServiceTypeFromName(t *testing.T) {
	if got := serviceTypeFromName("slw-nas._qdiscover._tcp.local."); got != "_qdiscover._tcp.local" {
		t.Fatalf("服务类型提取错误: %s", got)
	}
}

func TestCleanAndNormalizeService(t *testing.T) {
	for input, want := range map[string]string{
		"_http._tcp.local":        "http",
		"_qdiscover._tcp.local.":  "qdiscover",
		"_device-info._tcp.local": "device-info",
	} {
		if got := cleanService(input); got != want {
			t.Errorf("服务名清洗错误: %q -> %q, want %q", input, got, want)
		}
	}
	if got := normalizeServiceQuery("_http._tcp.local."); got != "_http._tcp" {
		t.Fatalf("服务查询名规范化错误: %q", got)
	}
}

func TestInstanceDisplayName(t *testing.T) {
	if got := instanceDisplayName("slw-nas._http._tcp.local."); got != "slw-nas" {
		t.Fatalf("实例名提取错误: %s", got)
	}
}

func TestProbeReadsPassiveBanner(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "SSH-2.0-test\r\n")
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	s := scanner{timeout: time.Second}
	if got := s.probe(context.Background(), "127.0.0.1", port, "ssh"); got != "SSH-2.0-test" {
		t.Fatalf("banner 读取错误: %q", got)
	}
}

func TestProbeSendsHTTPRequest(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requestSeen := make(chan string, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		buffer := make([]byte, 2048)
		count, _ := conn.Read(buffer)
		requestSeen <- string(buffer[:count])
		_, _ = io.WriteString(conn, "HTTP/1.0 200 OK\r\nServer: test\r\n\r\n")
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	s := scanner{timeout: time.Second}
	if got := s.probe(context.Background(), "127.0.0.1", port, "http"); got != "HTTP/1.0 200 OK\r\nServer: test" {
		t.Fatalf("HTTP banner 读取错误: %q", got)
	}
	select {
	case request := <-requestSeen:
		if !strings.HasPrefix(request, "GET / HTTP/1.0\r\nHost: 127.0.0.1") {
			t.Fatalf("HTTP 探测请求错误: %q", request)
		}
	case <-time.After(time.Second):
		t.Fatal("未收到 HTTP 探测请求")
	}
}

func TestPrintReportIncludesDeepFields(t *testing.T) {
	var output bytes.Buffer
	printReport(&output, []Asset{{IP: "192.168.1.10", Port: 5000, Service: "qdiscover", Host: "slw-nas", Hostname: "slw-nas.local", TTL: 10, TXT: map[string]string{"model": "TS-464C"}, Banner: "HTTP/1.1 200 OK"}})
	for _, want := range []string{"5000/tcp qdiscover:", "IPv4=192.168.1.10", "Hostname=slw-nas.local", "TTL=10", "model=TS-464C", "banner=HTTP/1.1 200 OK"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("报告缺少 %q:\n%s", want, output.String())
		}
	}
}
