package conhoslib

import (
	"log"
	"runtime"
)

const (
	StatusError = "[ERROR]"
	StatusWarn  = "[WARN]"
	StatusInfo  = "[INFO]"
)

type Error struct {
	Message string
	Stack   []byte
}

func (e *Error) Error() string {
	return e.Message
}

func NewError(message string) *Error {
	stack := make([]byte, 1024)
	n := runtime.Stack(stack, true)
	return &Error{
		Message: message,
		Stack:   stack[:n],
	}
}

func Log(status string, message string, err *Error) {
	if err == nil {
		log.Printf("%s %s\n", status, message)
	} else {
		log.Printf("%s %s: %s, %s\n", status, message, err.Message, err.Stack)
	}
}
