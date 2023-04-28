package tampers

import (
	"fmt"
	"math/rand"
	"strings"
)

type Tamper interface {
	Tamper(payload string) (string, error)
}

type UTF8EncodingTamper struct{}
type SpaceToCommentTamper struct{}
type ApostropheToDoubleEncodingTamper struct{}
type RandomCaseTamper struct{}

func (t *UTF8EncodingTamper) Tamper(payload string) (string, error) {
	encodedPayload := ""
	for _, c := range payload {
		encodedPayload += fmt.Sprintf("%%%X", c)
	}
	return encodedPayload, nil
}

func (t *SpaceToCommentTamper) Tamper(payload string) (string, error) {
	tamperedPayload := strings.Replace(payload, " ", "/**/", -1)
	return tamperedPayload, nil
}

func (t *ApostropheToDoubleEncodingTamper) Tamper(payload string) (string, error) {
	tamperedPayload := strings.Replace(payload, "'", "%%27", -1)
	return tamperedPayload, nil
}

func (t *RandomCaseTamper) Tamper(payload string) (string, error) {
	tamperedPayload := ""
	for _, c := range payload {
		if rand.Int()%2 == 0 {
			tamperedPayload += strings.ToUpper(string(c))
		} else {
			tamperedPayload += strings.ToLower(string(c))
		}
	}
	return tamperedPayload, nil
}
