package dns

import (
	"encoding/binary"
	"fmt"
)

type OpCode uint8

const (
	Query  OpCode = 0
	IQuery OpCode = 1
	Status OpCode = 2
)

type Message struct {
	buf []byte

	Header    Header
	Questions []Question
}

func (m Message) String() string {
	return fmt.Sprintf("Message{Header: %v query=%v, Questions: %v}", m.Header.Id(), m.Header.IsQuery(), m.Questions[0].Name())
}

func (m Message) Bytes() []byte {
	return m.buf
}

func NewMessage(buf []byte) Message {
	return Message{
		buf:       buf,
		Header:    HeaderBytes(buf[0:12]),
		Questions: NewQuestions(buf[12:]),
	}
}

// https://datatracker.ietf.org/doc/html/rfc1035#section-4
type Header interface {
	Id() uint16
	SetId(id uint16)
	IsQuery() bool
}

type HeaderBytes []byte

func (h HeaderBytes) Id() uint16 {
	return binary.BigEndian.Uint16(h[0:2])
}

func (h HeaderBytes) SetId(id uint16) {
	binary.BigEndian.PutUint16(h[0:2], id)
}

func (h HeaderBytes) IsQuery() bool {
	return h[2]&0x80 == 0
}

type Question interface {
	Name() string
}

// TODO: handle multiple questions.
func NewQuestions(buf []byte) []Question {
	return []Question{QuestionBytes(buf)}
}

type QuestionBytes []byte

// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
func (q QuestionBytes) Name() string {
	s := ""
	for i := 0; i < len(q); i++ {
		labelLen := int(q[i])
		if labelLen == 0 {
			break
		}

		s += string(q[i+1:i+1+int(labelLen)]) + "."
		i += labelLen
	}
	return s
}
