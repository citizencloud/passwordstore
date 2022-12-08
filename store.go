package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"

	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink"
	"golang.org/x/sys/unix"
)

// DB represents a file storage object
type DB struct {
	dir     string
	master  tink.AEAD
	records map[string][]byte
}

// RecordSet is the set of all records in the db
type RecordSet struct {
	records []Envelope
}

// Envelope represents a single entry in the db
type Envelope struct {
	name string
	data []byte
}

type Record struct {
	username string
	password string
	notes    string
}

// Open returns a new DB instance
func Open() (*DB, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("unable to find home directory: %v", err)
	}
	pwDir := filepath.Join(homeDir, ".durin")
	if err := os.MkdirAll(pwDir, 0700); err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Join(pwDir, "lock"), unix.O_CREAT|unix.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	// Hold lock until process exits.
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("failed to acquire DB lock: %v", err)
	}
	key, err := loadMasterKey(pwDir)
	if err != nil {
		return nil, err
	}

	db := &DB{
		dir: pwDir, records: make(map[string][]byte), master: key,
	}
	if err := db.load(); err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("fake error!: %s", err)
}

func loadMasterKey(pwDir string) (tink.AEAD, error) {
	saltPath := filepath.Join(pwDir, "salt")
	salt, err := ioutil.ReadFile(saltPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read salt from %q: %v", saltPath, err)
		}
		salt = random.GetRandomBytes(16)
		if err := writeFile(saltPath, salt); err != nil {
			return nil, fmt.Errorf("failed to write initial salt to %q: %v", saltPath, err)
		}
	}

	pwKey, err := Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %v", err)
	}

	// load master secret
	masterPath := filepath.Join(pwDir, "master")
	masterb, err := ioutil.ReadFile(masterPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read master from %q: %v", masterPath, err)
		}

		h, err := keyset.NewHandle(aead.XChaCha20Poly1305KeyTemplate())
		if err != nil {
			return nil, err
		}

		var buf bytes.Buffer
		if err := h.Write(keyset.NewBinaryWriter(&buf), pwKey); err != nil {
			return nil, fmt.Errorf("failed to write initial master keyset: %v", err)
		}

		if err := writeFile(masterPath, buf.Bytes()); err != nil {
			return nil, fmt.Errorf("failed to write initial master keyset to %q: %v", masterPath, err)
		}
		masterb = buf.Bytes()
	}
	ks, err := keyset.Read(keyset.NewBinaryReader(bytes.NewReader(masterb)), pwKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt master keyset: %v", err)
	}
	key, err := aead.New(ks)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (db *DB) List() []string {
	names := []string{}
	for name, _ := range db.records {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (db *DB) Get(name string) (*Record, error) {
	c, ok := db.records[name]
	if !ok {
		return nil, fmt.Errorf("password %q not found", name)
	}
	b, err := db.master.Decrypt(c, []byte(name))
	if err != nil {
		return nil, err
	}
	var out Record
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (db *DB) Put(name string, r *Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	c, err := db.master.Encrypt(b, []byte(name))
	if err != nil {
		return err
	}
	db.records[name] = c
	return db.commit()
}

func (db *DB) load() error {
	pwPath := filepath.Join(db.dir, "pw.db")
	var rs RecordSet
	b, err := ioutil.ReadFile(pwPath)
	if err != nil {
		if os.IsNotExist(err) {
			return db.commit()
		}
		return err
	}
	if err := json.Unmarshal(b, &rs); err != nil {
		return err
	}
	records := make(map[string][]byte)
	for _, env := range rs.records {
		records[env.name] = env.data
	}
	db.records = records
	return nil
}

func (db *DB) commit() error {
	pwPath := filepath.Join(db.dir, "pw.db")
	var rs RecordSet
	for k, v := range db.records {
		rs.records = append(rs.records, Envelope{
			name: k,
			data: v,
		})
	}
	b, err := json.Marshal(&rs)
	if err != nil {
		return err
	}
	return writeFile(pwPath, b)
}
