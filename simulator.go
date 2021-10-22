package simulator

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	sendCmd    uint32 = 8
	sessionEnd uint32 = 20
)

// TcpConfig represents connection options for connecting to a running TPM
// via TCP (e.g., the Microsoft reference TPM 2.0 simulator).
type TcpConfig struct {
	// BaseAddress is the IP address or hostname of the running TPM simulator.
	BaseAddress string
	// TPMPort is the port number (default 2321) of the TPM command handler for the simulator.
	TPMPort int
	// PlatformPort is the port number (default 2322) of the platform command handler for the simulator.
	PlatformPort int
}

// tcpTpm represents a connection to a running TPM over TCP.
type tcpTpm struct {
	// tpmConn is the open TCP connection to the running TPM.
	tpmConn net.Conn
	// platConn is the open TCP connection to the running Platform.
	platConn net.Conn
	// lastResp is the last response from the TPM.
	lastResp io.Reader
}

// OpenTcpTpm opens a connection to a running TPM via TCP (e.g., the Microsoft
// reference TPM 2.0 simulator).
func OpenTcpTpm(c *TcpConfig) (io.ReadWriteCloser, error) {
	tpmAddr := fmt.Sprintf("%s:%d", c.BaseAddress, c.TPMPort)
	tpmConn, err := net.Dial("tcp", tpmAddr)
	if err != nil {
		return nil, fmt.Errorf("could not dial TPM: %w", err)
	}
	platAddr := fmt.Sprintf("%s:%d", c.BaseAddress, c.PlatformPort)
	platConn, err := net.Dial("tcp", platAddr)
	if err != nil {
		return nil, fmt.Errorf("could not dial TPM platform: %w", err)
	}
	return &tcpTpm{
		tpmConn:  tpmConn,
		platConn: platConn,
	}, nil
}

// Read reads the last response from the TCP TPM.
func (t *tcpTpm) Read(p []byte) (int, error) {
	return t.lastResp.Read(p)
}

// tcpCmdHdr represents a framed TCP TPM command header as defined in part D of
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part4_SuppRoutines_code_pub.pdf
type tcpCmdHdr struct {
	tcpCmd   uint32
	locality uint8
	cmdLen   uint32
}

// Write frames the command and sends it to the TPM, immediately reading and
// caching the response for future calls to Read().
func (t *tcpTpm) Write(p []byte) (int, error) {
	cmd := tcpCmdHdr{
		tcpCmd:   sendCmd,
		locality: 0,
		cmdLen:   uint32(len(p)),
	}
	buf := bytes.Buffer{}
	if err := binary.Write(&buf, binary.BigEndian, cmd); err != nil {
		return 0, fmt.Errorf("could not frame TCP TPM command: %w", err)
	}
	if _, err := buf.Write(p); err != nil {
		return 0, fmt.Errorf("could not write command to buffer: %w", err)
	}
	if _, err := buf.WriteTo(t.tpmConn); err != nil {
		return 0, fmt.Errorf("could not send TCP TPM command: %w", err)
	}

	var rspLen uint32
	if err := binary.Read(t.tpmConn, binary.BigEndian, &rspLen); err != nil {
		return 0, fmt.Errorf("could not read TCP TPM response length: %w", err)
	}
	rsp := make([]byte, int(rspLen))
	if _, err := io.ReadFull(t.tpmConn, rsp); err != nil {
		return 0, fmt.Errorf("could not read TCP TPM response: %w", err)
	}
	var rc uint32
	if err := binary.Read(t.tpmConn, binary.BigEndian, &rc); err != nil {
		return 0, fmt.Errorf("could not read TCP TPM response code: %w", err)
	}
	if rc != 0 {
		return 0, fmt.Errorf("error from TCP TPM: 0x%x", rc)
	}
	t.lastResp = bytes.NewReader(rsp)
	return len(p), nil
}

type platformCommand uint32

const (
	powerOn    platformCommand = 1
	powerOff   platformCommand = 2
	nvOn       platformCommand = 11
	nvOff      platformCommand = 12
	sessionEnd platformCommand = 20
)

// sendPlatformCommand sends a command code to the running platform.
func (t *tcpTpm) sendPlatformCommand(cmd platformCommand) error {
	if err := binary.Write(p.conn, binary.BigEndian, cmd); err != nil {
		return fmt.Errorf("could not send platform command 0x%x: %w", cmd, err)
	}
	var rc uint32
	if err := binary.Read(p.conn, binary.BigEndian, &rc); err != nil {
		return fmt.Errorf("could not read platform response: %w", err)
	}
	if rc != 0 {
		return fmt.Errorf("error from TCP platform: 0x%x", rc)
	}
	return nil
}

// PowerOn powers on the simulator.
func (t *tcpTpm) PowerOn() error {
	return t.sendPlatformCommand(powerOn)
}

// PowerOff powers off the simulator.
func (t *tcpTpm) PowerOff() error {
	return t.sendPlatformCommand(powerOff)
}

// NVOn enables NV access.
func (t *tcpTpm) NVOn() error {
	return t.sendPlatformCommand(nvOn)
}

// NVOff disables NV access.
func (t *tcpTpm) NVOff() error {
	return t.sendPlatformCommand(nvOff)
}

// Close closes the connection to the TCP TPM.
func (t *tcpTpm) Close() error {
	tpmErr := binary.Write(t.tpmConn, binary.BigEndian, sessionEnd)
	t.tpmConn.Close()
	platErr := binary.Write(t.platConn, binary.BigEndian, sessionEnd)
	t.platConn.Close()
	if tpmErr != nil {
		return fmt.Errorf("could not send 'session end' to TPM:", tpmErr)
	}
	if platErr != nil {
		return fmt.Errorf("could not send 'session end' to platform:", tpmErr)
	}
	return nil
}
