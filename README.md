# mdnsmap

`mdnsmap` 是一个 Go 编写的网站测绘 CLI：输入 IP 网段和端口范围，发现网段内的 mDNS 服务，并输出 IP、端口、主机名、IPv6、TTL、TXT 元数据和 TCP banner。服务名称按 mDNS 类型显示，例如 `_qdiscover._tcp.local` 输出为 `qdiscover`。

## 使用

```bash
go run . -cidr 192.168.1.0/24 -ports 1-10000
go run . -cidr 192.168.1.0/24 -ports 80,443,5000 -json
```

参数：

- `-cidr`：必填，IPv4 或 IPv6 CIDR 网段。
- `-ports`：端口列表或范围，例 `80,443,5000-5010`。
- `-timeout`：单次 mDNS/TCP 探测超时，默认 `2s`。
- `-json`：输出便于管道处理的 JSON 数组。

程序先查询 `_services._dns-sd._udp.local` 获取服务类型，再查询每个服务的 PTR/SRV/TXT/A/AAAA 记录；对端口范围内的实例建立 TCP 连接，读取服务主动 banner，HTTP/HTTPS 服务会自动发送最小 GET 请求。

终端输出示例：

```text
services:
  5000/tcp qdiscover:
    Name=slw-nas
    IPv4=192.168.1.20
    IPv6=fe80::265e:beff:fe69:a313
    Hostname=slw-nas.local
    TTL=120
    accessType=https
    accessPort=86
    model=TS-X64
    displayModel=TS-464C
    fwVer=5.2.9
    banner=HTTP/1.1 200 OK
```

设备未发布服务目录时，程序会直接查询 `http`、`workstation`、`smb`、`qdiscover`、`device-info` 和 `afpovertcp` 类型，仍可获取示例中的设备信息。

## 验证

```bash
go test ./...
go build -o mdnsmap .
```
