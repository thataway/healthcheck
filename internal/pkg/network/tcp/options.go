package tcp

import (
	"time"
)

//DialerOption опции DialTcp
type DialerOption interface { //nolint:revive
	isTcpDialerOpt()
}

//OptSocketMark маркер для метки исходящих пакетов
type OptSocketMark struct {
	DialerOption
	SocketMark int
}

//OptSocketConnectTimeout время за которе должно установиться сщедиенеие
type OptSocketConnectTimeout struct {
	DialerOption
	Timeout time.Duration
}

//OptSocketRdTimeout время чтения из сокета
type OptSocketRdTimeout struct {
	DialerOption
	Timeout time.Duration
}

//OptSocketWrTimeout время записи в сокет
type OptSocketWrTimeout struct {
	DialerOption
	Timeout time.Duration
}

// --------------------------------------------- IMPL -------------------------------------------

var (
	_ DialerOption = OptSocketConnectTimeout{}
	_ DialerOption = OptSocketMark{}
	_ DialerOption = OptSocketRdTimeout{}
	_ DialerOption = OptSocketWrTimeout{}
)

type tcpDialerOptions struct { //nolint:revive
	sockMark    int
	connectTmo  time.Duration
	rdSocketTmo time.Duration
	wrSocketTmo time.Duration
}

func (options *tcpDialerOptions) fill(opts ...DialerOption) {
	for _, o := range opts {
		switch v := o.(type) {
		case OptSocketConnectTimeout:
			options.connectTmo = v.Timeout
		case OptSocketMark:
			options.sockMark = v.SocketMark
		case OptSocketRdTimeout:
			options.rdSocketTmo = v.Timeout
		case OptSocketWrTimeout:
			options.wrSocketTmo = v.Timeout
		}
	}
}
