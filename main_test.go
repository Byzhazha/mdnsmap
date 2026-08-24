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
