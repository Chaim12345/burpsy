package proxy

import (
	"encoding/binary"
	"io"
	"net"
)

// peekClientALPN reads the TLS ClientHello from conn and returns the ALPN list
// and a connection that replays the peeked bytes for the real handshake.
func peekClientALPN(conn net.Conn) (clientOffer []string, replay net.Conn, err error) {
	buf := make([]byte, 16384)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, nil, err
	}
	peeked := buf[:n]
	offer, err := parseClientHelloALPN(peeked)
	if err != nil {
		return nil, nil, err
	}
	return offer, &replayConn{Conn: conn, prefix: peeked}, nil
}

type replayConn struct {
	net.Conn
	prefix []byte
	off    int
}

func (c *replayConn) Read(p []byte) (int, error) {
	if c.off < len(c.prefix) {
		n := copy(p, c.prefix[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(p)
}

// parseClientHelloALPN extracts ALPN protocols from a TLS record containing a
// ClientHello. Returns an empty slice when the extension is absent.
func parseClientHelloALPN(record []byte) ([]string, error) {
	if len(record) < 5 || record[0] != 0x16 {
		return nil, io.ErrUnexpectedEOF
	}
	recLen := int(binary.BigEndian.Uint16(record[3:5]))
	if len(record) < 5+recLen {
		return nil, io.ErrUnexpectedEOF
	}
	hs := record[5 : 5+recLen]
	if len(hs) < 4 || hs[0] != 0x01 {
		return nil, io.ErrUnexpectedEOF
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return nil, io.ErrUnexpectedEOF
	}
	body := hs[4 : 4+hsLen]
	if len(body) < 34 {
		return nil, io.ErrUnexpectedEOF
	}
	off := 34 // version + random
	if off >= len(body) {
		return nil, nil
	}
	sessLen := int(body[off])
	off += 1 + sessLen
	if off+2 > len(body) {
		return nil, nil
	}
	cipherLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2 + cipherLen
	if off+1 > len(body) {
		return nil, nil
	}
	compLen := int(body[off])
	off += 1 + compLen
	if off+2 > len(body) {
		return nil, nil
	}
	extLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	end := off + extLen
	if end > len(body) {
		return nil, io.ErrUnexpectedEOF
	}
	var protos []string
	for off+4 <= end {
		extType := binary.BigEndian.Uint16(body[off : off+2])
		extDataLen := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if off+extDataLen > end {
			break
		}
		if extType == 16 { // ALPN
			data := body[off : off+extDataLen]
			if len(data) < 2 {
				break
			}
			listLen := int(binary.BigEndian.Uint16(data[0:2]))
			p := 2
			listEnd := 2 + listLen
			for p+1 < listEnd && p < len(data) {
				l := int(data[p])
				p++
				if p+l > len(data) {
					break
				}
				protos = append(protos, string(data[p:p+l]))
				p += l
			}
		}
		off += extDataLen
	}
	return protos, nil
}
