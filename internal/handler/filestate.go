package handler

import (
	"cess-gateway/internal/chain"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Filestate_resp struct {
	Size  uint64
	State string
	Names []string
}

func FilestateHandler(c *gin.Context) {
	var resp = RespMsg{
		Code: http.StatusUnauthorized,
		Msg:  Status_401_token,
	}
	fid := c.Param("fid")
	if fid == "" {
		resp.Code = http.StatusBadRequest
		resp.Msg = Status_400_default
		c.JSON(http.StatusBadRequest, resp)
		return
	}
	//query all file meta
	filestate, err := chain.GetFileMetaInfoOnChain(fid)
	if err != nil {
		if err.Error() == chain.ERR_Empty {
			resp.Code = http.StatusNotFound
			resp.Msg = chain.ERR_Empty
			c.JSON(http.StatusOK, resp)
			return
		}
		resp.Code = http.StatusInternalServerError
		resp.Msg = Status_500_chain
		c.JSON(http.StatusInternalServerError, resp)
		return
	}
	var fs Filestate_resp
	fs.Size = uint64(filestate.FileSize)
	fs.State = string(filestate.FileState)
	for _, v := range filestate.Names {
		var tmp string = string(v)
		fs.Names = append(fs.Names, tmp)
	}
	resp.Code = http.StatusOK
	resp.Msg = Status_200_default
	resp.Data = fs
	c.JSON(http.StatusOK, resp)
	return
}
