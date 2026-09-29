package redis

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/tidwall/redcon"
)

// commandReader bounds RESP lengths before allocating or indexing by them.
// Its buffer retains commands pipelined with the authentication handshake.
type commandReader struct {
	input *bufio.Reader
}

func newCommandReader(input io.Reader) *commandReader {
	return &commandReader{input: bufio.NewReader(input)}
}

func (r *commandReader) ReadCommand() (redcon.Command, error) {
	raw := make([]byte, 0, 128)
	marker, err := r.input.ReadByte()
	if err != nil {
		return redcon.Command{}, err
	}
	raw = append(raw, marker)
	if marker != '*' {
		return redcon.Command{}, errors.New("redis: command must be a RESP array")
	}
	count, err := r.readUnsigned(&raw)
	if err != nil {
		return redcon.Command{}, fmt.Errorf("redis: invalid array length: %w", err)
	}
	if count < 1 || count > 1024 {
		return redcon.Command{}, errors.New("redis: invalid array length")
	}

	args := make([][]byte, 0, count)
	for range count {
		marker, err = r.input.ReadByte()
		if err != nil {
			return redcon.Command{}, err
		}
		raw = append(raw, marker)
		if marker != '$' {
			return redcon.Command{}, errors.New("redis: expected bulk string")
		}
		size, err := r.readUnsigned(&raw)
		if err != nil {
			return redcon.Command{}, fmt.Errorf("redis: invalid bulk length: %w", err)
		}
		if size > maxCommandBytes-len(raw)-2 {
			return redcon.Command{}, errors.New("redis: invalid bulk length")
		}
		arg := make([]byte, size)
		if _, err := io.ReadFull(r.input, arg); err != nil {
			return redcon.Command{}, err
		}
		raw = append(raw, arg...)
		var ending [2]byte
		if _, err := io.ReadFull(r.input, ending[:]); err != nil {
			return redcon.Command{}, err
		}
		if ending != [2]byte{'\r', '\n'} {
			return redcon.Command{}, errors.New("redis: invalid bulk ending")
		}
		raw = append(raw, ending[:]...)
		args = append(args, arg)
	}
	return redcon.Command{Raw: raw, Args: args}, nil
}

func (r *commandReader) readUnsigned(raw *[]byte) (int, error) {
	var digits [20]byte
	n := 0
	for {
		b, err := r.input.ReadByte()
		if err != nil {
			return 0, err
		}
		*raw = append(*raw, b)
		if b == '\r' {
			lf, err := r.input.ReadByte()
			if err != nil {
				return 0, err
			}
			*raw = append(*raw, lf)
			if lf != '\n' || n == 0 {
				return 0, errors.New("invalid decimal header")
			}
			return strconv.Atoi(string(digits[:n]))
		}
		if b < '0' || b > '9' || n == len(digits) {
			return 0, errors.New("invalid decimal header")
		}
		digits[n] = b
		n++
	}
}
