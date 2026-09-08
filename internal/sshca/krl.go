package sshca

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// OpenSSH key revocation lists, as described in PROTOCOL.krl. x/crypto/ssh can
// read certificates but not write a KRL, so the format is assembled here.
//
// Only serial-list revocation is emitted: Gruff knows the serial of everything
// it issued, and sshd checks the list on every certificate it is offered.
const (
	krlMagic         = "SSHKRL\n\x00"
	krlFormatVersion = 1

	sectionCertificates = 1

	certSectionSerialList = 0x20
)

// KRL builds a revocation list covering serials issued by this CA.
//
// An empty list is still worth writing: sshd treats a missing RevokedKeys file
// as a configuration error and refuses every connection, so publishing an empty
// list is what keeps a host serving before anything has been revoked.
func (ca *CA) KRL(serials []uint64, generated time.Time) ([]byte, error) {
	var certs bytes.Buffer
	// Scope the section to this CA's key, so the list cannot revoke serials
	// that happen to collide under some other authority.
	writeString(&certs, ca.signer.PublicKey().Marshal())
	writeString(&certs, nil)

	if len(serials) > 0 {
		var list bytes.Buffer
		for _, s := range serials {
			if s == 0 {
				// Serial 0 means "unset" in a certificate, and OpenSSH refuses
				// to revoke it: it would match every certificate without one.
				return nil, fmt.Errorf("cannot revoke serial 0")
			}
			binary.Write(&list, binary.BigEndian, s)
		}
		certs.WriteByte(certSectionSerialList)
		writeString(&certs, list.Bytes())
	}

	var krl bytes.Buffer
	krl.WriteString(krlMagic)
	binary.Write(&krl, binary.BigEndian, uint32(krlFormatVersion))
	binary.Write(&krl, binary.BigEndian, uint64(generated.Unix())) // krl_version
	binary.Write(&krl, binary.BigEndian, uint64(generated.Unix())) // generated_date
	binary.Write(&krl, binary.BigEndian, uint64(0))                // flags
	writeString(&krl, nil)                                         // reserved
	writeString(&krl, []byte("gruff"))                             // comment

	krl.WriteByte(sectionCertificates)
	writeString(&krl, certs.Bytes())

	return krl.Bytes(), nil
}

// writeString appends an SSH wire string: a uint32 length then the bytes.
func writeString(b *bytes.Buffer, data []byte) {
	binary.Write(b, binary.BigEndian, uint32(len(data)))
	b.Write(data)
}
