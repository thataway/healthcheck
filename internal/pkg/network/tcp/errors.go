package tcp

import (
	"fmt"
)

//ErrUnableConnect ошибка если мы не смогли получить соединение
type ErrUnableConnect struct {
	Reason  error
	Address string
}

//Error ...
func (e ErrUnableConnect) Error() string {
	var s string
	if e.Reason != nil {
		s = fmt.Sprintf("connect to '%s' is failed: %v", e.Address, e.Reason)
	} else {
		s = fmt.Sprintf("connect to '%s' is failed", e.Address)
	}
	return s
}
