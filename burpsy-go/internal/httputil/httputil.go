// Package httputil provides shared HTTP/1.x framing helpers used by the
// proxy and the raw request sender.
package httputil

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
)

// ReadHTTPResponse reads one complete HTTP response from conn, respecting
// Content-Length and chunked transfer encoding instead of waiting for EOF
// (which never arrives on a keep-alive connection).
func ReadHTTPResponse(conn net.Conn) ([]byte, error) {
	br := bufio.NewReader(conn)

	// Read the head: status line + headers, up to the blank line.
	var head bytes.Buffer
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("reading response head: %w", err)
		}
		head.WriteString(line)
		if head.Len() >= 4 && bytes.HasSuffix(head.Bytes(), []byte("\r\n\r\n")) {
			break
		}
	}
	headBytes := head.Bytes()

	statusLine := string(bytes.SplitN(headBytes, []byte("\r\n"), 2)[0])
	// Status codes that never carry a body: 1xx, 204, 304.
	noBody := len(statusLine) >= 12 && (statusLine[9] == '1' || statusLine[9:12] == "204" || statusLine[9:12] == "304")

	var body bytes.Buffer
	if !noBody {
		// Skip the status line; ReadMIMEHeader expects headers only.
		headerBlock := headBytes
		if idx := bytes.Index(headerBlock, []byte("\r\n")); idx != -1 {
			headerBlock = headerBlock[idx+2:]
		}
		h := textproto.NewReader(bufio.NewReader(bytes.NewReader(headerBlock)))
		mimeHead, err := h.ReadMIMEHeader()
		if err != nil {
			return nil, fmt.Errorf("parsing response headers: %w", err)
		}

		if te := mimeHead.Get("Transfer-Encoding"); strings.EqualFold(te, "chunked") {
			// Read chunked body until the terminating zero chunk.
			for {
				sizeLine, err := br.ReadString('\n')
				if err != nil {
					return nil, fmt.Errorf("reading chunk size: %w", err)
				}
				body.WriteString(sizeLine)
				sizeStr := strings.TrimSpace(strings.SplitN(sizeLine, ";", 2)[0])
				size, err := strconv.ParseInt(sizeStr, 16, 64)
				if err != nil {
					return nil, fmt.Errorf("bad chunk size %q: %w", sizeStr, err)
				}
				if size == 0 {
					// Trailer until blank line.
					for {
						line, err := br.ReadString('\n')
						if err != nil {
							return nil, fmt.Errorf("reading chunk trailer: %w", err)
						}
						body.WriteString(line)
						if line == "\r\n" || line == "\n" {
							break
						}
					}
					break
				}
				if _, err := io.CopyN(&body, br, size); err != nil {
					return nil, fmt.Errorf("reading chunk data: %w", err)
				}
				// Chunk data is followed by CRLF.
				crlf := make([]byte, 2)
				if _, err := io.ReadFull(br, crlf); err != nil {
					return nil, fmt.Errorf("reading chunk terminator: %w", err)
				}
				body.Write(crlf)
			}
		} else if cl := mimeHead.Get("Content-Length"); cl != "" {
			n, err := strconv.ParseInt(cl, 10, 64)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("bad Content-Length %q", cl)
			}
			if n > 0 {
				if _, err := io.CopyN(&body, br, n); err != nil {
					return nil, fmt.Errorf("reading body: %w", err)
				}
			}
		} else {
			// No framing: body runs until EOF (HTTP/1.0 style).
			if _, err := io.Copy(&body, br); err != nil {
				return nil, fmt.Errorf("reading EOF-delimited body: %w", err)
			}
		}
	}

	result := make([]byte, 0, head.Len()+body.Len())
	result = append(result, headBytes...)
	result = append(result, body.Bytes()...)
	return result, nil
}
