// Command e2e exercises a full relay chain against a fake game server, over
// real UDP sockets, and reports whether packets survive the round trip.
//
// Topology, all on loopback:
//
//	this process (client)  ->  relay  ->  exit  ->  echo server
//	                      <-         <-        <-
//
// Run with: go run ./cmd/e2e
package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"max301/internal/crypto"
	"max301/internal/protocol"
	"max301/internal/redundancy"
	"max301/internal/router"
	"max301/internal/session"
	"max301/internal/transport"
)

const password = "e2e-test-password-long-enough"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	dir, err := os.MkdirTemp("", "max301-e2e")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	// A UDP echo server standing in for the game server.
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer echo.Close()
	gamePort := echo.LocalAddr().(*net.UDPAddr).Port
	go echoLoop(echo)
	fmt.Printf("echo server on 127.0.0.1:%d\n", gamePort)

	// Ports for the two hops.
	const (
		relayPort1 = 31001
		relayPort2 = 31002
		exitPort1  = 31011
		exitPort2  = 31012
	)

	relayCfg := filepath.Join(dir, "relay.yaml")
	if err := os.WriteFile(relayCfg, []byte(fmt.Sprintf(`
mode: relay
inbound:
  listen: "127.0.0.1"
  ports: [%d, %d]
  password: "%s"
outbound:
  host: "127.0.0.1"
  ports: [%d, %d]
  password: "%s"
  redundancy: 2
log:
  level: "info"
`, relayPort1, relayPort2, password, exitPort1, exitPort2, password)), 0o600); err != nil {
		return err
	}

	exitCfg := filepath.Join(dir, "exit.yaml")
	if err := os.WriteFile(exitCfg, []byte(fmt.Sprintf(`
mode: exit
inbound:
  listen: "127.0.0.1"
  ports: [%d, %d]
  password: "%s"
outbound:
  mode: "nat"
  nat_timeout: 1m
log:
  level: "info"
`, exitPort1, exitPort2, password)), 0o600); err != nil {
		return err
	}

	// Build and launch both nodes.
	bin := filepath.Join(dir, "bin")
	for _, name := range []string{"relay", "exit"} {
		out := filepath.Join(bin, name+exeSuffix())
		cmd := exec.Command("go", "build", "-o", out, "./cmd/"+name)
		if b, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("build %s: %w: %s", name, err, b)
		}
	}

	exitProc := exec.Command(filepath.Join(bin, "exit"+exeSuffix()), "-c", exitCfg)
	exitProc.Stdout, exitProc.Stderr = prefixWriter("exit"), prefixWriter("exit")
	if err := exitProc.Start(); err != nil {
		return err
	}
	defer kill(exitProc)

	relayProc := exec.Command(filepath.Join(bin, "relay"+exeSuffix()), "-c", relayCfg)
	relayProc.Stdout, relayProc.Stderr = prefixWriter("relay"), prefixWriter("relay")
	if err := relayProc.Start(); err != nil {
		return err
	}
	defer kill(relayProc)

	time.Sleep(700 * time.Millisecond) // let both bind their sockets

	// Client side: seal inner IP packets and send them to the relay.
	cipher, err := crypto.NewCipher(crypto.DeriveKey(password))
	if err != nil {
		return err
	}
	out, err := transport.NewMultiPath("127.0.0.1", []int{relayPort1, relayPort2})
	if err != nil {
		return err
	}
	defer out.Close()

	sess := session.New(session.NewID(), cipher, 0)
	sender := redundancy.NewSender(sess, out, 2, nil)
	recv := redundancy.NewReceiver(sess, cipher, nil)

	const (
		clientIP   = "10.88.0.2"
		clientPort = 54321
		packets    = 20
	)
	var src, dst [4]byte
	copy(src[:], net.ParseIP(clientIP).To4())
	copy(dst[:], net.IPv4(127, 0, 0, 1).To4())

	fmt.Printf("sending %d packets through relay -> exit -> echo\n", packets)

	var delivered int
	buf := make([]byte, protocol.MaxFrameSize)

	for i := 0; i < packets; i++ {
		payload := []byte(fmt.Sprintf("packet-%03d", i))
		inner := router.BuildUDPPacket(nil, src, dst, clientPort, uint16(gamePort), payload)

		if err := sender.Send(inner, protocol.PriorityGame); err != nil {
			return fmt.Errorf("send %d: %w", i, err)
		}

		// Wait for the echo to come back through the tunnel.
		if got, err := awaitReply(out, recv, buf, payload, 3*time.Second); err != nil {
			fmt.Printf("  packet %d: %v\n", i, err)
		} else if got {
			delivered++
		}
	}

	fmt.Printf("\n%d/%d packets completed the round trip\n", delivered, packets)
	if delivered != packets {
		return fmt.Errorf("only %d of %d packets survived", delivered, packets)
	}
	fmt.Println("PASS: full chain carries game traffic in both directions")
	return nil
}

// awaitReply reads from the tunnel until the echo of want arrives.
func awaitReply(out *transport.MultiPathConn, recv *redundancy.Receiver,
	buf []byte, want []byte, timeout time.Duration) (bool, error) {

	deadline := time.After(timeout)
	for {
		select {
		case pkt := <-out.Recv():
			res, err := recv.Recv(pkt.Data, buf)
			if err != nil {
				continue // duplicate from the redundant path, or not for us
			}
			ip, err := router.ParseIPv4(res.Payload)
			if err != nil {
				continue
			}
			if bytes.Equal(ip.Payload, want) {
				return true, nil
			}
		case <-deadline:
			return false, fmt.Errorf("no reply within %s", timeout)
		}
	}
}

func echoLoop(conn *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		conn.WriteToUDP(buf[:n], addr)
	}
}

func kill(cmd *exec.Cmd) {
	if cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}
}

type prefixedWriter struct{ tag string }

func prefixWriter(tag string) *prefixedWriter { return &prefixedWriter{tag: tag} }

func (w *prefixedWriter) Write(p []byte) (int, error) {
	for _, line := range bytes.Split(bytes.TrimRight(p, "\n"), []byte("\n")) {
		if len(line) > 0 {
			fmt.Printf("  [%s] %s\n", w.tag, line)
		}
	}
	return len(p), nil
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}
