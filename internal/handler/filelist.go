package handler

import (
	"cess-gateway/configs"
	"cess-gateway/internal/chain"
	"cess-gateway/internal/db"
	. "cess-gateway/internal/logger"
	"cess-gateway/internal/token"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

func FilelistHandler(c *gin.Context) {
	var resp = RespMsg{
		Code: http.StatusUnauthorized,
		Msg:  Status_401_token,
	}
	// token
	htoken := c.Request.Header.Get("Authorization")
	if htoken == "" {
		Err.Sugar().Errorf("[%v] head missing token", c.ClientIP())
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	bytes, err := token.DecryptToken(htoken)
	if err != nil {
		Err.Sugar().Errorf("[%v] [%v] DecryptToken error", c.ClientIP(), htoken)
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	var usertoken token.TokenMsgType
	err = json.Unmarshal(bytes, &usertoken)
	if err != nil {
		Err.Sugar().Errorf("[%v] [%v] token format error", c.ClientIP(), htoken)
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	if time.Now().Unix() >= usertoken.ExpirationTime {
		Err.Sugar().Errorf("[%v] token expired", usertoken.Mailbox)
		resp.Msg = Status_401_expired
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	// Parameters
	resp.Code = http.StatusBadRequest
	resp.Msg = Status_400_default
	var page, size = 0, 0
	var showPage, showSize = 0, 30
	sizes := c.Query("size")
	pages := c.Query("page")
	if pages != "" {
		page, err = strconv.Atoi(pages)
		if err != nil {
			Err.Sugar().Errorf("[%v] [%v] filename is empty", c.ClientIP(), usertoken.Mailbox)
			c.JSON(http.StatusBadRequest, resp)
			return
		}
		if page > 0 {
			showPage = page
		}
	}
	if sizes != "" {
		size, err = strconv.Atoi(sizes)
		if err != nil {
			Err.Sugar().Errorf("[%v] [%v] filename is empty", c.ClientIP(), usertoken.Mailbox)
			c.JSON(http.StatusBadRequest, resp)
			return
		}
		if size > 0 {
			showSize = size
			if showSize > 1000 {
				showSize = 1000
			}
		}
	}
	resp.Code = http.StatusInternalServerError
	resp.Msg = Status_500_unexpected
	//query all file meta
	filelist, err := chain.GetUserFileList(configs.C.AccountSeed)
	if err != nil {
		if err.Error() == chain.ERR_Empty {
			resp.Code = http.StatusOK
			resp.Msg = chain.ERR_Empty
			c.JSON(http.StatusOK, resp)
			return
		}
		resp.Code = http.StatusInternalServerError
		resp.Msg = Status_500_unexpected
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	db, err := db.GetDB()
	if err != nil {
		Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
		resp.Code = http.StatusInternalServerError
		resp.Msg = Status_500_db
		c.JSON(http.StatusInternalServerError, resp)
		return
	}
	var flist = make([]string, 0)
	for _, v := range filelist {
		key_fid := usertoken.Mailbox + string(v.File_hash)
		ok, err := db.Has([]byte(key_fid))
		if err != nil {
			Uld.Sugar().Infof("[%v] %v", usertoken.Mailbox, err)
			resp.Code = http.StatusInternalServerError
			resp.Msg = Status_500_db
			c.JSON(http.StatusInternalServerError, resp)
			return
		}
		if ok {
			flist = append(flist, string(v.File_hash))
		}
	}

	//Pagination display
	resp.Code = http.StatusOK
	resp.Msg = "success"
	if showSize >= len(flist) {
		resp.Data = flist
		c.JSON(http.StatusOK, resp)
		return
	}

	//Show last page
	if showPage == 0 {
		resp.Data = flist[len(flist)-showSize:]
		c.JSON(http.StatusOK, resp)
		return
	}

	//Invalid page number, show last page.
	if (showPage-1)*30 > len(flist) {
		if len(flist) > 30 {
			resp.Data = flist[len(flist)-30:]
		} else {
			resp.Data = flist
		}
		c.JSON(http.StatusOK, resp)
		return
	}

	//Display from the specified page number.
	if (showPage-1)*30+showSize >= len(flist) {
		resp.Data = flist[(showPage-1)*30:]
	} else {
		resp.Data = flist[(showPage-1)*30 : (showPage-1)*30+showSize]
	}
	c.JSON(http.StatusOK, resp)
	return
}
