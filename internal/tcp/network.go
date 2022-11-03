package tcp

type NetConn interface {
	HandlerLoop()
	GetMsg() (*Message, bool)
	SendMsg(m *Message)
	Close() error
	IsClose() bool
}
