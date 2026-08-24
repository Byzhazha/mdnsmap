package main

import (
	"net"
	"reflect"
	"testing"
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

func TestInstanceDisplayName(t *testing.T) {
	if got := instanceDisplayName("slw-nas._http._tcp.local."); got != "slw-nas" {
		t.Fatalf("实例名提取错误: %s", got)
	}
}
