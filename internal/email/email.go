package email

import (
	"github.com/go-gomail/gomail"
)

func SendPlainMail(host string, port int, from, passwd string, to []string, subject, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("Subject", subject)
	m.SetHeader("To", to...)
	m.SetAddressHeader("From", from, "")
	// "text/html","text/plain"
	m.SetBody("text/html", body)

	return gomail.NewPlainDialer(host, port, from, passwd).DialAndSend(m)
}
