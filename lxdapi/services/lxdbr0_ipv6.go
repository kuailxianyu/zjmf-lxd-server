package services

import (
	"context"
	"fmt"
	"math/big"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"lxdapi/config"
	"lxdapi/pkg/logger"

	"go.uber.org/zap"
)

// LXDBr0IPv6Manager 负责纯 IPv6 容器模式（mode3）下 lxdbr0 网桥的
// IPv6 网关配置、系统级 sysctl、以及容器内部 IPv6 地址池。
type LXDBr0IPv6Manager struct {
	mu             sync.Mutex
	enabled        bool
	prefix         string // CIDR，例如 2001:db8:aaaa::/64
	base           *big.Int
	prefixLen      int
	bridgeIf       string
	gatewayAddr    string // lxdbr0 上的网关地址（未含 /64）
	gatewayCidr    string // lxdbr0 上的网关地址（含 /64）
	allocated      map[string]string // 容器名 -> 分配的 IPv6（不含 /64）
}

var LXDBr0IPv6 *LXDBr0IPv6Manager

// InitLXDBr0IPv6 启动期调用，幂等；失败仅告警不阻塞主流程。
func InitLXDBr0IPv6() error {
	ctx := context.Background()
	lc := &logger.Context{Action: "init_lxdbr0_ipv6"}
	ctx = logger.NewContext(ctx, lc)

	// 未启用 mode3 时不初始化
	if !config.IsIPv6OnlyModeEnabled() {
		LXDBr0IPv6 = &LXDBr0IPv6Manager{enabled: false}
		logger.Global.Info(ctx, "mode3（纯 IPv6 NAT）未启用，跳过 lxdbr0 IPv6 初始化")
		return nil
	}

	prefix := config.GetV6Prefix()
	network, prefixLen, err := parseV6Prefix(prefix)
	if err != nil {
		LXDBr0IPv6 = &LXDBr0IPv6Manager{enabled: false}
		logger.Global.Warn(ctx, "IPv6 前缀解析失败，mode3 不可用",
			zap.String("prefix", prefix), zap.Error(err))
		return err
	}

	// 网关地址取前缀第 2 个地址
	hostBits := 128 - int(*prefixLen)
	shift := uint(hostBits)
	gwInt := new(big.Int).Lsh(network, shift)
	gwInt.Add(gwInt, big.NewInt(2))
	gwAddr := intToIPv6(gwInt)

	m := &LXDBr0IPv6Manager{
		enabled:       true,
		prefix:        fmt.Sprintf("%s/%d", network.String(), *prefixLen),
		base:          network,
		prefixLen:     int(*prefixLen),
		bridgeIf:      "lxdbr0",
		gatewayAddr:   gwAddr,
		gatewayCidr:   fmt.Sprintf("%s/%d", gwAddr, *prefixLen),
		allocated:     make(map[string]string),
	}

	// 加载已存在分配（从数据库或后续调用者维护；此处仅留位）
	if err := m.ensureSysctls(); err != nil {
		logger.Global.Warn(ctx, "sysctl 配置部分失败", zap.Error(err))
	}
	if err := m.ensureKernelModules(); err != nil {
		logger.Global.Warn(ctx, "内核模块加载部分失败", zap.Error(err))
	}
	if err := m.ensureGatewayAddr(); err != nil {
		logger.Global.Warn(ctx, "lxdbr0 IPv6 网关地址配置失败", zap.Error(err))
	}

	LXDBr0IPv6 = m
	logger.Global.Info(ctx, "lxdbr0 IPv6 网关配置完成",
		zap.String("bridge", m.bridgeIf),
		zap.String("prefix", m.prefix),
		zap.String("gateway", m.gatewayAddr))
	return nil
}

// IsUp 返回管理器是否可用
func (m *LXDBr0IPv6Manager) IsUp() bool {
	if m == nil {
		return false
	}
	return m.enabled
}

// AllocateV6 从 v6_prefix 池内取下一个未用地址，返回不含前缀的地址字符串
func (m *LXDBr0IPv6Manager) AllocateV6() (string, error) {
	if m == nil || !m.enabled {
		return "", fmt.Errorf("lxdbr0 IPv6 manager not enabled")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// 从 base+1 开始顺序扫描（跳过网关地址 =base+2）
	hostBits := 128 - m.prefixLen
	maxHost := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	for i := 1; i < maxHost.Int64(); i++ {
		addr := new(big.Int).Lsh(m.base, uint(hostBits))
		addr.Add(addr, big.NewInt(i))
		addrStr := intToIPv6(addr)
		// 跳过网关
		if addrStr == m.gatewayAddr {
			continue
		}
		// 检查是否已被分配
		used := false
		for _, v := range m.allocated {
			if v == addrStr {
				used = true
				break
			}
		}
		if used {
			continue
		}
		return addrStr, nil
	}
	return "", fmt.Errorf("v6 prefix %s exhausted", m.prefix)
}

// AllocateForContainer 分配并把容器名绑到地址
func (m *LXDBr0IPv6Manager) AllocateForContainer(containerName string) (string, error) {
	if m == nil || !m.enabled {
		return "", fmt.Errorf("lxdbr0 IPv6 manager not enabled")
	}
	addr, err := m.AllocateV6()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.allocated[containerName] = addr
	m.mu.Unlock()
	return addr, nil
}

// GetForContainer 返回该容器已分配的 IPv6（若无返回空）
func (m *LXDBr0IPv6Manager) GetForContainer(containerName string) string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.allocated[containerName]
}

// Release 释放容器名对应的地址
func (m *LXDBr0IPv6Manager) Release(containerName string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	delete(m.allocated, containerName)
	m.mu.Unlock()
}

// Register 外部已知分配（如从数据库恢复）时登记
func (m *LXDBr0IPv6Manager) Register(containerName, addr string) {
	if m == nil || addr == "" {
		return
	}
	m.mu.Lock()
	m.allocated[containerName] = addr
	m.mu.Unlock()
}

// GatewayAddr 返回 lxdbr0 上的网关地址
func (m *LXDBr0IPv6Manager) GatewayAddr() string {
	if m == nil {
		return ""
	}
	return m.gatewayAddr
}

// PrefixLen 返回地址池的前缀长度（例如 /64 返回 64）
func (m *LXDBr0IPv6Manager) PrefixLen() int {
	if m == nil {
		return 64
	}
	if m.prefixLen == 0 {
		return 64
	}
	return m.prefixLen
}

// ---- 内部工具 ----

func parseV6Prefix(prefix string) (*big.Int, *int, error) {
	if prefix == "" {
		return nil, nil, fmt.Errorf("empty prefix")
	}
	// 支持 "2001:db8:aaaa::/64" 或 "2001:db8:aaaa::"
	ip, cidr, err := net.ParseCIDR(prefix)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid cidr %q: %v", prefix, err)
	}
	prefixLen := cidr.Mask
	if prefixLen == 0 {
		return nil, nil, fmt.Errorf("invalid prefix length for %q", prefix)
	}
	networkIP := ip.Mask(cidr.Mask).To16()
	if networkIP == nil {
		return nil, nil, fmt.Errorf("invalid network for %q", prefix)
	}
	// 转成 big.Int（128bit）
	n := new(big.Int).SetBytes(networkIP)
	return n, &prefixLen, nil
}

func intToIPv6(n *big.Int) string {
	bytes := make([]byte, 16)
	n.FillBytes(bytes)
	ip := net.IP(bytes)
	return ip.String()
}

// ensureSysctls 写入 IPv6 转发相关 sysctl（幂等）
func (m *LXDBr0IPv6Manager) ensureSysctls() error {
	entries := map[string]string{
		"net.ipv6.conf.all.forwarding":  "1",
		"net.ipv6.conf.all.accept_ra":   "0",
		"net.ipv6.conf." + m.bridgeIf + ".forwarding":  "1",
		"net.ipv6.conf." + m.bridgeIf + ".accept_ra":   "2", // 桥接设备需要 send_ra，但这里保守用 2
		"net.ipv6.conf." + m.bridgeIf + ".send_ra":     "1",
		"net.ipv6.conf." + m.bridgeIf + ".accept_ra_deprecated": "0",
	}
	for k, v := range entries {
		cmd := exec.Command("sysctl", "-w", fmt.Sprintf("%s=%s", k, v))
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("sysctl %s=%s failed: %v out=%s", k, v, err, string(out))
		}
	}
	return nil
}

// ensureKernelModules 加载 IPv6 NAT 所需内核模块
func (m *LXDBr0IPv6Manager) ensureKernelModules() error {
	for _, mod := range []string{"ip6_tables", "nf_nat_ipv6", "nf_conntrack"} {
		cmd := exec.Command("modprobe", mod)
		if err := cmd.Run(); err != nil {
			// modprobe 幂等；如果模块已加载则 err==nil；未找到时忽略
			continue
		}
	}
	return nil
}

// ensureGatewayAddr 在 lxdbr0 上配置网关地址（先查再 add）
func (m *LXDBr0IPv6Manager) ensureGatewayAddr() error {
	if m.gatewayAddr == "" {
		return fmt.Errorf("gateway addr empty")
	}
	// 查询当前 lxdbr0 IPv6 地址
	cmd := exec.Command("ip", "-6", "addr", "show", "dev", m.bridgeIf)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip -6 addr show failed: %v out=%s", err, string(out))
	}
	text := string(out)
	if strings.Contains(text, m.gatewayAddr) {
		return nil
	}
	// 检查 lxdbr0 是否已存在同 /64 段地址（避免冲突）
	if isAlreadyInPrefix(text, m.prefix) {
		// 已有同段地址，说明用户已手工配置，跳过
		return nil
	}
	addCmd := exec.Command("ip", "-6", "addr", "add", m.gatewayCidr, "dev", m.bridgeIf)
	if out, err := addCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip -6 addr add failed: %v out=%s", err, string(out))
	}
	return nil
}

// isAlreadyInPrefix 粗略判断 lxdbr0 上是否已有同 /64 前缀的地址
func isAlreadyInPrefix(ipAddrOutput, prefix string) bool {
	// 提取 "2001:db8:aaaa::/64" 的前缀部分
	parts := strings.SplitN(prefix, "/", 2)
	if len(parts) != 2 {
		return false
	}
	_, cidr, err := net.ParseCIDR(prefix)
	if err != nil {
		return false
	}
	// 简单匹配：查找 ipAddrOutput 中 "/"+parts[1] 后紧跟的 IPv6 地址是否落入同一前缀
	lines := strings.Split(ipAddrOutput, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "scope global") {
			continue
		}
		// 提取 scope global 前的地址字段
		idx := strings.Index(line, "scope global")
		if idx < 0 {
			continue
		}
		fields := strings.Fields(line[:idx])
		if len(fields) == 0 {
			continue
		}
		addrWithPrefix := fields[0]
		ip, _, err := net.ParseCIDR(addrWithPrefix)
		if err != nil {
			continue
		}
		masked := ip.Mask(cidr.Mask)
		base, _ := parseV6Prefix(prefix)
		if base != nil && masked != nil {
			// 比较前 128-prefixLen 位
			prefixLen, _ := strconv.Atoi(parts[1])
			if prefixLen > 0 && prefixLen <= 128 {
				hostBits := 128 - prefixLen
				shift := uint(hostBits)
				if shift > 0 {
					maskedInt := new(big.Int).SetBytes(masked.To16())
					maskedInt.Rsh(maskedInt, shift)
					if maskedInt.Cmp(base) == 0 {
						return true
					}
				}
			}
		}
	}
	return false
}

