//go:build windows

// Interactive setup for the Windows client.
//
// The client is a console program people double-click, so three things have to
// happen before the tunnel can come up: the console must be able to print
// Chinese, the process must be elevated (creating an adapter and editing the
// route table both need it), and wintun.dll plus the domestic prefix list have
// to be on disk. The wizard handles all three and writes client.yaml.
package main

import (
	"archive/zip"
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	wintunVersion = "0.14.1"
	wintunURL     = "https://www.wintun.net/builds/wintun-" + wintunVersion + ".zip"
)

var stdin = bufio.NewReader(os.Stdin)

// setConsoleUTF8 switches the console to code page 65001. Without it the
// default OEM page renders every Chinese character as a box.
func setConsoleUTF8() {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	kernel32.NewProc("SetConsoleOutputCP").Call(65001)
	kernel32.NewProc("SetConsoleCP").Call(65001)
}

// isAdmin reports whether the process is elevated.
func isAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0) // the current process token
	member, err := token.IsMember(sid)
	return err == nil && member
}

func say(format string, a ...any) { fmt.Printf(format+"\n", a...) }

// ask reads one line, returning def when the user just presses enter.
func ask(prompt, def string) string {
	if def != "" {
		fmt.Printf("  %s [%s]: ", prompt, def)
	} else {
		fmt.Printf("  %s: ", prompt)
	}
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return def
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

// pause keeps the window open. A double-clicked console program that exits
// takes its error message with it.
func pause() {
	fmt.Print("\n  按回车键退出...")
	stdin.ReadString('\n')
}

func exeDir() string {
	p, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(p)
}

func banner() {
	say("")
	say("==============================================")
	say("        Max301 游戏加速 客户端")
	say("==============================================")
}

// relaunchElevated restarts the program through ShellExecute with the "runas"
// verb, which is what raises the UAC prompt. The new process gets a fresh
// console, so this one simply exits.
func relaunchElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	cwd, _ := windows.UTF16PtrFromString(exeDir())

	var args *uint16
	if len(os.Args) > 1 {
		quoted := make([]string, 0, len(os.Args)-1)
		for _, a := range os.Args[1:] {
			quoted = append(quoted, `"`+a+`"`)
		}
		args, _ = windows.UTF16PtrFromString(strings.Join(quoted, " "))
	}

	return windows.ShellExecute(0, verb, file, args, cwd, windows.SW_SHOWNORMAL)
}

// ensureAdmin returns true when the caller may continue in this process.
func ensureAdmin() bool {
	if isAdmin() {
		return true
	}
	say("")
	say("  需要管理员权限：客户端要创建网卡、修改路由表。")
	say("  正在请求提权，请在弹出的窗口点「是」。")
	if err := relaunchElevated(); err != nil {
		say("")
		say("  提权失败：%v", err)
		say("  请右键这个程序，选择「以管理员身份运行」。")
		pause()
	}
	return false
}

// httpClient returns a client that honours the system proxy. Without this, a
// machine whose hosts file blocks the host (or that has no direct route out)
// cannot download anything -- which is exactly the kind of machine a tunnel
// gets installed on. ProxyFromEnvironment covers HTTPS_PROXY; systemProxy adds
// the Internet Options setting that Windows programs normally use.
func httpClient() *http.Client {
	return &http.Client{
		Timeout: 3 * time.Minute,
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				if u, err := http.ProxyFromEnvironment(req); err == nil && u != nil {
					return u, nil
				}
				return systemProxy(), nil
			},
		},
	}
}

// systemProxy reads the per-user proxy from the registry, which is where the
// Internet Options dialog and most proxy clients on Windows write it.
func systemProxy() *url.URL {
	key, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer key.Close()

	if enabled, _, err := key.GetIntegerValue("ProxyEnable"); err != nil || enabled == 0 {
		return nil
	}
	server, _, err := key.GetStringValue("ProxyServer")
	if err != nil || server == "" {
		return nil
	}
	// ProxyServer is either "host:port" or a per-scheme list such as
	// "http=host:port;https=host:port".
	if strings.Contains(server, "=") {
		for _, part := range strings.Split(server, ";") {
			scheme, addr, ok := strings.Cut(part, "=")
			if ok && (scheme == "http" || scheme == "https") {
				server = addr
				break
			}
		}
	}
	if !strings.Contains(server, "://") {
		server = "http://" + server
	}
	u, err := url.Parse(server)
	if err != nil {
		return nil
	}
	return u
}

func download(url, dst string) error {
	resp, err := httpClient().Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s 返回 HTTP %d", url, resp.StatusCode)
	}

	// Write to a temporary name and rename on success, so an interrupted
	// download cannot leave a truncated file that looks valid.
	tmp := dst + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	return os.Rename(tmp, dst)
}

// ensureWintun puts wintun.dll next to the executable, extracting the DLL for
// this architecture out of the official zip.
func ensureWintun(dir string) error {
	dll := filepath.Join(dir, "wintun.dll")
	if _, err := os.Stat(dll); err == nil {
		say("  wintun.dll 已存在")
		return nil
	}

	say("  正在下载 Wintun 驱动（WireGuard 用的同一个驱动）...")
	zipPath := filepath.Join(os.TempDir(), "wintun.zip")
	if err := download(wintunURL, zipPath); err != nil {
		return fmt.Errorf("下载 Wintun 失败: %w", err)
	}
	defer os.Remove(zipPath)

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()

	want := "wintun/bin/amd64/wintun.dll"
	for _, f := range zr.File {
		if strings.ToLower(filepath.ToSlash(f.Name)) != want {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		out, err := os.Create(dll)
		if err != nil {
			return err
		}
		defer out.Close()
		if _, err := io.Copy(out, rc); err != nil {
			return err
		}
		say("  wintun.dll 已就位")
		return nil
	}
	return fmt.Errorf("压缩包里没找到 %s", want)
}

// cnipFile reports which prefix list to configure. The list is compiled into
// the binary, so an empty result means "use the built-in copy"; a chnroute.txt
// the user has put next to the executable wins, which is how someone keeps a
// fresher list than the release ships.
func cnipFile(dir string) string {
	path := filepath.Join(dir, "chnroute.txt")
	if st, err := os.Stat(path); err == nil && st.Size() > 1000 {
		say("  使用目录下的 chnroute.txt")
		return filepath.Base(path)
	}
	say("  使用内置的国内 IP 段列表")
	return ""
}

// askServer collects the first hop. A hostname is accepted as well as an IP,
// but it is resolved here so a typo surfaces now rather than as a tunnel that
// comes up and carries nothing.
func askServer() string {
	for {
		host := ask("服务器 IP（中转或落地节点的公网地址）", "")
		if host == "" {
			say("  这一项必填")
			continue
		}
		if net.ParseIP(host) != nil {
			return host
		}
		say("  正在解析 %s ...", host)
		if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
			say("  → %s", ips[0])
			return host
		}
		say("  解析不了 %q，请检查是否输错", host)
	}
}

func askPassword() string {
	for {
		p := ask("通信密码（和服务器上填的完全一致）", "")
		if len(p) < 16 {
			say("  至少 16 位，和服务器端一致（当前 %d 位）", len(p))
			continue
		}
		return p
	}
}

// askPorts collects the server's listening ports. They must match what the
// installer configured on that node; a mismatch is a tunnel that sends into
// nothing, with no error to read.
func askPorts() []int {
	for {
		s := ask("服务器端口（逗号分隔，和服务器上填的一致）", "20001,20002")
		ports, err := parsePorts(s)
		if err != nil {
			say("  %s", err)
			continue
		}
		return ports
	}
}

func parsePorts(s string) ([]int, error) {
	fields := strings.Split(strings.ReplaceAll(s, " ", ""), ",")
	var ports []int
	seen := map[int]bool{}
	for _, f := range fields {
		if f == "" {
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil {
			return nil, fmt.Errorf("%q 不是数字", f)
		}
		if n < 1024 || n > 65535 {
			return nil, fmt.Errorf("端口 %d 超出范围，请用 1024-65535", n)
		}
		if seen[n] {
			return nil, fmt.Errorf("端口 %d 重复了", n)
		}
		seen[n] = true
		ports = append(ports, n)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("至少要一个端口")
	}
	if len(ports) > 8 {
		return nil, fmt.Errorf("最多 8 个端口（当前 %d 个）", len(ports))
	}
	return ports, nil
}

// askRedundancy caps the answer at the port count: the loader rejects a higher
// value, and copies beyond the number of ports would land on ports nobody is
// listening on anyway.
func askRedundancy(portCount int) int {
	max := portCount
	if max > 4 {
		max = 4
	}
	if max == 1 {
		say("")
		say("  只配了 1 个端口，冗余份数固定为 1（复制需要多个端口才有意义）。")
		return 1
	}
	for {
		s := ask(fmt.Sprintf("冗余份数 1-%d（2=普通线路，3=抖动大）", max), "2")
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > max {
			say("  请输入 1 到 %d 之间的数字", max)
			continue
		}
		return n
	}
}

func askMode() string {
	say("")
	say("  分流方式：")
	say("    1) 智能分流 —— 只有访问国外走加速，国内走原路（推荐）")
	say("    2) 全局加速 —— 所有流量都走加速")
	for {
		switch ask("输入 1 或 2", "1") {
		case "1":
			return "bypass_cn"
		case "2":
			return "global"
		default:
			say("  只能输入 1 或 2")
		}
	}
}

func randomTunAddress() string {
	// A random third octet keeps the tunnel out of the way of whatever private
	// range the machine already uses.
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "10.88.0.2/24"
	}
	return fmt.Sprintf("10.88.%d.2/24", int(b[0]%250)+1)
}

// portList formats ports for the YAML flow sequence.
func portList(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ", ")
}

// writeConfig renders client.yaml. Values come from the wizard rather than a
// template file so the binary stays self-contained.
func writeConfig(path, host, password, mode, cnip string, ports []int, redundancy int) error {
	var routing string
	switch {
	case mode != "bypass_cn":
		routing = "routing:\n  mode: \"global\"\n"
	case cnip == "":
		// No cnip_file key at all: the client then uses its built-in list.
		routing = "routing:\n  mode: \"bypass_cn\"\n"
	default:
		routing = fmt.Sprintf("routing:\n  mode: \"bypass_cn\"\n  cnip_file: %q\n", cnip)
	}

	body := fmt.Sprintf(`# Max301 客户端配置，由安装向导生成。
# 密码和服务器端必须完全一致。

mode: client

tun:
  name: "Max301"
  address: %q
  mtu: 1400

relay:
  host: %q
  ports: [%s]
  password: %q
  redundancy: %d

%s
log:
  level: "info"
  file: "client.log"
`, randomTunAddress(), host, portList(ports), password, redundancy, routing)

	// 0600 is what we ask for, but Windows derives the file's ACL from the
	// parent directory and ignores the mode, so this is not a protection the
	// file actually has. restrictACL below is what does the work.
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return err
	}
	if err := restrictACL(path); err != nil {
		// Not fatal: the tunnel works regardless, and the user is typically the
		// only account on the machine. Worth saying out loud rather than hiding.
		say("  提示：无法收紧 client.yaml 的访问权限（%v）", err)
		say("        该文件保存着通信密码，请自行确认本机没有其他用户。")
	}
	return nil
}

// restrictACL limits the file to SYSTEM, Administrators and the owner, so the
// stored password is not readable by other local accounts. icacls is used
// because building the equivalent ACL through the Win32 API is a great deal of
// code for a one-off.
func restrictACL(path string) error {
	cmd := exec.Command("icacls", path,
		"/inheritance:r",
		"/grant:r", "*S-1-5-18:F", // SYSTEM
		"/grant:r", "*S-1-5-32-544:F", // Administrators
		"/grant:r", "*S-1-3-4:F", // the file's owner
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("icacls: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// setup runs the first-time wizard and returns the config path.
func setup(dir string) (string, error) {
	cfgPath := filepath.Join(dir, "client.yaml")

	if _, err := os.Stat(cfgPath); err == nil {
		say("")
		say("  找到已有配置：client.yaml")
		if ask("直接使用？(y=使用 / n=重新设置)", "y") != "n" {
			return cfgPath, nil
		}
	}

	say("")
	say("----------------------------------------------")
	say("  首次设置")
	say("----------------------------------------------")
	say("")
	say("  需要服务器的 IP 和密码 —— 就是在服务器上跑一键脚本")
	say("  时它最后打印出来的那两项。")
	say("")

	host := askServer()
	ports := askPorts()
	password := askPassword()
	redundancy := askRedundancy(len(ports))
	mode := askMode()

	say("")
	say("  正在准备运行环境...")
	if err := ensureWintun(dir); err != nil {
		return "", err
	}
	cnip := ""
	if mode == "bypass_cn" {
		cnip = cnipFile(dir)
	}

	if err := writeConfig(cfgPath, host, password, mode, cnip, ports, redundancy); err != nil {
		return "", fmt.Errorf("写配置文件失败: %w", err)
	}
	say("  配置已保存：client.yaml")
	return cfgPath, nil
}
