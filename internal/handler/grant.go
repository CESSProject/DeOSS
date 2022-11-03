package handler

import (
	"bufio"
	"bytes"
	"cess-gateway/configs"
	"cess-gateway/internal/db"
	"cess-gateway/internal/email"
	. "cess-gateway/internal/logger"
	"cess-gateway/internal/token"
	"cess-gateway/tools"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// It is used to authorize users
func GrantTokenHandler(c *gin.Context) {
	var resp = RespMsg{
		Code: http.StatusBadRequest,
		Msg:  Status_400_default,
	}
	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		Err.Sugar().Errorf("%v,%v", c.ClientIP(), err)
		c.JSON(http.StatusBadRequest, resp)
		return
	}
	var reqmsg ReqGrantMsg
	err = json.Unmarshal(body, &reqmsg)
	if err != nil {
		Err.Sugar().Errorf("%v,%v", c.ClientIP(), err)
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	// Check email format
	if !tools.VerifyMailboxFormat(reqmsg.Mailbox) {
		Err.Sugar().Errorf("%v,%v", c.ClientIP(), err)
		resp.Msg = Status_400_EmailFormat
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	resp.Code = http.StatusInternalServerError
	db, err := db.GetDB()
	if err != nil {
		Err.Sugar().Errorf("[%v] [%v] %v", c.ClientIP(), reqmsg, err)
		resp.Msg = Status_500_db
		c.JSON(http.StatusInternalServerError, resp)
		return
	}
	data_byte, err := db.Get([]byte(reqmsg.Mailbox))
	if err != nil {
		if err.Error() == "leveldb: not found" {
			captcha := tools.RandomInRange(100000, 999999)
			v := fmt.Sprintf("%v", captcha) + "#" + fmt.Sprintf("%v", time.Now().Add(configs.ValidTimeOfCaptcha).Unix())
			err = db.Put([]byte(reqmsg.Mailbox), []byte(v))
			if err != nil {
				Err.Sugar().Errorf("[%v] [%v] %v", c.ClientIP(), reqmsg, err)
				resp.Msg = Status_500_db
				c.JSON(http.StatusInternalServerError, resp)
				return
			}
			var mail_s string
			b := bytes.NewBuffer(make([]byte, 0))
			bw := bufio.NewWriter(b)
			tpl := template.Must(template.New("tplName").Parse(content_captcha))
			tpl.Execute(bw, map[string]interface{}{"Captcha": captcha})
			bw.Flush()
			mail_s = fmt.Sprintf("%s", b)
			err = email.SendPlainMail(
				configs.C.SMTPHost,
				configs.C.SMTPPort,
				configs.C.EmailAddress,
				configs.C.AuthorizationCode,
				[]string{reqmsg.Mailbox},
				configs.EmailSubject_captcha,
				mail_s,
			)
			if err != nil {
				db.Delete([]byte(reqmsg.Mailbox))
				Err.Sugar().Errorf("[%v] [%v] %v", c.ClientIP(), reqmsg, err)
				resp.Msg = Status_500_EmailSend
				c.JSON(http.StatusInternalServerError, resp)
				return
			}
			resp.Code = http.StatusOK
			resp.Msg = Status_200_default
			c.JSON(http.StatusOK, resp)
			return
		}
		Err.Sugar().Errorf("[%v] [%v] %v", c.ClientIP(), reqmsg, err)
		resp.Msg = Status_500_db
		c.JSON(http.StatusInternalServerError, resp)
		return
	}
	v := strings.Split(string(data_byte), "#")
	if len(v) == 2 {
		vi, err := strconv.ParseInt(v[1], 10, 64)
		if err != nil {
			db.Delete([]byte(reqmsg.Mailbox))
			Err.Sugar().Errorf("[%v] [%v] %v", c.ClientIP(), reqmsg, err)
			resp.Msg = Status_500_unexpected
			c.JSON(http.StatusInternalServerError, resp)
			return
		}
		if time.Now().Unix() >= time.Unix(vi, 0).Unix() {
			Out.Sugar().Infof("[%v] [%v] Captcha has expired and a new captcha has been sent to your mailbox", c.ClientIP(), reqmsg)
			captcha := tools.RandomInRange(100000, 999999)
			v := fmt.Sprintf("%v", captcha) + "#" + fmt.Sprintf("%v", time.Now().Add(configs.ValidTimeOfCaptcha).Unix())
			err = db.Put([]byte(reqmsg.Mailbox), []byte(v))
			if err != nil {
				Err.Sugar().Errorf("[%v] [%v] %v", c.ClientIP(), reqmsg, err)
				resp.Msg = Status_500_db
				c.JSON(http.StatusInternalServerError, resp)
				return
			}
			var mail_s string
			b := bytes.NewBuffer(make([]byte, 0))
			bw := bufio.NewWriter(b)
			tpl := template.Must(template.New("tplName").Parse(content_captcha))
			tpl.Execute(bw, map[string]interface{}{"Captcha": captcha})
			bw.Flush()
			mail_s = fmt.Sprintf("%s", b)
			err = email.SendPlainMail(
				configs.C.SMTPHost,
				configs.C.SMTPPort,
				configs.C.EmailAddress,
				configs.C.AuthorizationCode,
				[]string{reqmsg.Mailbox},
				configs.EmailSubject_captcha,
				mail_s,
			)
			if err != nil {
				Err.Sugar().Errorf("[%v] [%v] %v", c.ClientIP(), reqmsg, err)
				db.Delete([]byte(reqmsg.Mailbox))
				resp.Code = http.StatusBadRequest
				resp.Msg = Status_500_EmailSend
				c.JSON(http.StatusInternalServerError, resp)
				return
			}

			resp.Code = http.StatusOK
			resp.Msg = Status_200_expired
			c.JSON(http.StatusOK, resp)
			return
		}
		vi, err = strconv.ParseInt(v[0], 10, 32)
		if err != nil {
			db.Delete([]byte(reqmsg.Mailbox))
			Err.Sugar().Errorf("[%v] [%v] %v", c.ClientIP(), reqmsg, err)
			resp.Msg = Status_500_unexpected
			c.JSON(http.StatusInternalServerError, resp)
			return
		}
		if reqmsg.Captcha != vi {
			Err.Sugar().Errorf("[%v] [%v] %v", c.ClientIP(), reqmsg, err)
			resp.Msg = Status_400_captcha
			c.JSON(http.StatusBadRequest, resp)
			return
		}
		// Send token to user mailbox
		usertoken, err := token.GenerateNewToken(reqmsg.Mailbox)
		if err != nil {
			Err.Sugar().Errorf("[%v] [%v] %v", c.ClientIP(), reqmsg, err)
			resp.Msg = Status_500_unexpected
			c.JSON(http.StatusInternalServerError, resp)
			return
		}
		err = db.Put([]byte(reqmsg.Mailbox), []byte(usertoken))
		if err != nil {
			Err.Sugar().Errorf("[%v] [%v] %v", c.ClientIP(), reqmsg, err)
			resp.Msg = Status_500_db
			c.JSON(http.StatusInternalServerError, resp)
			return
		}
		var mail_s string
		b := bytes.NewBuffer(make([]byte, 0))
		bw := bufio.NewWriter(b)
		tpl := template.Must(template.New("tplName").Parse(content_token))
		tpl.Execute(bw, map[string]interface{}{"Token": usertoken})
		bw.Flush()
		mail_s = fmt.Sprintf("%s", b)
		err = email.SendPlainMail(
			configs.C.SMTPHost,
			configs.C.SMTPPort,
			configs.C.EmailAddress,
			configs.C.AuthorizationCode,
			[]string{reqmsg.Mailbox},
			configs.EmailSubject_token,
			mail_s,
		)
		if err != nil {
			Err.Sugar().Errorf("[%v] [%v] %v", c.ClientIP(), reqmsg, err)
			resp.Code = http.StatusInternalServerError
			resp.Msg = Status_500_EmailSend
			c.JSON(http.StatusInternalServerError, resp)
			return
		}
		resp.Code = http.StatusOK
		resp.Msg = Status_200_RefreshToken
		c.JSON(http.StatusOK, resp)
		return
	}

	b, err := token.DecryptToken(string(data_byte))
	if err != nil {
		Err.Sugar().Errorf("[%v] [%v] %v", c.ClientIP(), reqmsg, err)
		resp.Msg = Status_500_unexpected
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	var utoken token.TokenMsgType
	err = json.Unmarshal(b, &utoken)
	if err != nil {
		Err.Sugar().Errorf("[%v] [%v] %v", c.ClientIP(), reqmsg, err)
		db.Delete([]byte(reqmsg.Mailbox))
		resp.Msg = Status_500_ReAuth
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	tn := time.Now().Unix()
	if tn > utoken.ExpirationTime {
		resp.Code = http.StatusOK
		resp.Msg = Status_200_TokenExpired
		db.Delete([]byte(reqmsg.Mailbox))
		c.JSON(http.StatusOK, resp)
		return
	}

	if (utoken.ExpirationTime + 300) > (tn + 2592000) {
		resp.Code = http.StatusOK
		resp.Msg = Status_200_NoRefresh
		c.JSON(http.StatusOK, resp)
		return
	}

	newtoken, err := token.RefreshToken(utoken)
	if err != nil {
		Err.Sugar().Errorf("[%v] [%v] %v", c.ClientIP(), reqmsg, err)
		resp.Msg = Status_500_unexpected
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	err = db.Put([]byte(utoken.Mailbox), []byte(newtoken))
	if err != nil {
		Err.Sugar().Errorf("[%v] [%v] %v", c.ClientIP(), reqmsg, err)
		resp.Msg = Status_500_db
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	var mail_s string
	b2 := bytes.NewBuffer(make([]byte, 0))
	bw := bufio.NewWriter(b2)
	tpl := template.Must(template.New("tplName").Parse(content_token))
	tpl.Execute(bw, map[string]interface{}{"Token": newtoken})
	bw.Flush()
	mail_s = fmt.Sprintf("%s", b2)
	err = email.SendPlainMail(
		configs.C.SMTPHost,
		configs.C.SMTPPort,
		configs.C.EmailAddress,
		configs.C.AuthorizationCode,
		[]string{reqmsg.Mailbox},
		configs.EmailSubject_token,
		mail_s,
	)
	if err != nil {
		Err.Sugar().Errorf("[%v] [%v] %v", c.ClientIP(), reqmsg, err)
		resp.Code = http.StatusInternalServerError
		resp.Msg = Status_500_RefreshFailed
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	resp.Code = http.StatusOK
	resp.Msg = Status_200_RefreshToken
	c.JSON(http.StatusOK, resp)
	return
}
