package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"io"
	"os"

	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink"
	"golang.org/x/sys/unix"
)

const (
	backspaceChar = '\x7F'
)

func setSecretInputTermMode(fd uintptr) (func(), error) {
	termios, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	if err != nil {
		return nil, err
	}

	newState := *termios
	newState.Lflag &^= unix.ECHO | unix.ICANON
	newState.Lflag |= unix.ISIG
	newState.Iflag |= unix.ICRNL
	if err := unix.IoctlSetTermios(int(fd), unix.TCSETS, &newState); err != nil {
		return nil, err
	}

	return func() {
		if err := unix.IoctlSetTermios(int(fd), unix.TCSETS, termios); err != nil {
			panic(err)
		}
	}, nil
}

func readPasswordFromUser(in io.Reader, out io.Writer) []byte {
	var b bytes.Buffer
	prompt := &pwPrompt{o: bufio.NewWriter(out), rr: &runeReader{r: in}}

	prompt.writePasswordPrompt()

Read:
	for {
		char, err := prompt.ReadRune()
		if err != nil {
			panic(err)
		}

		switch char {
		case '\n':
			break Read
		case backspaceChar:
			if b.Len() > 0 {
				b.Truncate(b.Len() - 1)
			}
			continue Read
		}

		if _, err := b.WriteRune(char); err != nil {
			panic(err)
		}
	}

	return b.Bytes()
}

type pwPrompt struct {
	read int
	rr   *runeReader
	o    *bufio.Writer
}

func (pw *pwPrompt) ReadRune() (rune, error) {
	r, err := pw.rr.ReadRune()
	if err != nil || r == '\n' {
		pw.o.WriteRune('\n')
		pw.o.Flush()
		return r, err
	}
	if r == backspaceChar {
		if pw.read > 0 {
			pw.read--
		}
	} else {
		pw.read++
	}
	pw.writePasswordPrompt()
	return r, err
}

func (pw *pwPrompt) writePasswordPrompt() {
	const length = 20

	idx := -1
	if pw.read > 0 {
		idx = int(random.GetRandomUint32()>>1) % length
	}

	defer pw.o.Flush()

	if _, err := pw.o.WriteRune('\r'); err != nil {
		panic(err)
	}
	if _, err := pw.o.WriteString("Enter Password: "); err != nil {
		panic(err)
	}
	for i := 0; i < length; i++ {
		char := '_'
		if i == idx {
			char = '*'
		}
		if _, err := pw.o.WriteRune(char); err != nil {
			panic(err)
		}
	}
}

type runeReader struct {
	buf [1]byte
	r   io.Reader
}

func (rr *runeReader) ReadRune() (rune, error) {
	if _, err := rr.r.Read(rr.buf[:]); err != nil {
		return 0, err
	}
	return rune(rr.buf[0]), nil
}

func Read(salt []byte) (tink.AEAD, error) {
	if len(salt) < 16 {
		panic(fmt.Sprintf("salt is too small: %d", salt))
	}

	done, err := setSecretInputTermMode(os.Stdin.Fd())
	if err != nil {
		return nil, err
	}
	defer done()

	const (
		time    = 1
		mem     = 64 * 1024
		threads = 4
	)

	kh, err := keyset.NewHandle(aead.ChaCha20Poly1305KeyTemplate())
	if err != nil {
		panic(err)
	}
	return aead.New(kh)

}
