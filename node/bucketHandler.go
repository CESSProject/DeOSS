/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package node

// type BucketHandler struct {
// 	chain.Chainer
// 	logger.Logger
// 	*confile.Config
// }

// func NewBucketHandler(cli chain.Chainer, lg logger.Logger) *BucketHandler {
// 	return &BucketHandler{Chainer: cli, Logger: lg}
// }

// func (b *BucketHandler) RegisterRoutes(server *gin.Engine) {
// 	bucketgroup := server.Group("/bucket")
// 	bucketgroup.Use(
// 		func(ctx *gin.Context) {
// 			acc, pk, ok := VerifySignatureMdl(ctx)
// 			if !ok {
// 				ctx.AbortWithStatusJSON(http.StatusOK, RespType{
// 					Code: http.StatusForbidden,
// 					Msg:  ERR_NoPermission,
// 				})
// 				return
// 			}
// 			ctx.Set("account", acc)
// 			ctx.Set("publickey", hex.EncodeToString(pk))
// 			ctx.Next()
// 		},
// 		func(ctx *gin.Context) {
// 			acc, ok := ctx.Get("account")
// 			if !ok {
// 				ctx.AbortWithStatusJSON(http.StatusOK, RespType{
// 					Code: http.StatusForbidden,
// 					Msg:  ERR_NoPermission,
// 				})
// 				return
// 			}
// 			if !CheckPermissionsMdl(fmt.Sprintf("%v", acc), b.Config.Access.Mode, b.Config.User.Account, b.Config.Access.Account) {
// 				ctx.AbortWithStatusJSON(http.StatusOK, RespType{
// 					Code: http.StatusForbidden,
// 					Msg:  ERR_NoPermission,
// 				})
// 				return
// 			}
// 			ctx.Next()
// 		},
// 	)

// 	bucketgroup.PUT(fmt.Sprintf("/:%s", HTTP_ParameterName), b.CreateBucketHandle)
// 	bucketgroup.DELETE(fmt.Sprintf("/:%s", HTTP_ParameterName), b.DeleteBucketHandle)
// 	bucketgroup.GET("", b.GetBucketHandle)
// }

// func (b *BucketHandler) CreateBucketHandle(c *gin.Context) {
// 	clientIp := c.Request.Header.Get("X-Forwarded-For")
// 	if clientIp == "" {
// 		clientIp = c.ClientIP()
// 	}
// 	account := c.Request.Header.Get(HTTPHeader_Account)
// 	bucketName := c.Param(HTTP_ParameterName)
// 	if bucketName == "" {
// 		bucketName = c.Request.Header.Get(HTTPHeader_Bucket)
// 	}

// 	b.Logput("info", utils.StringBuilder(400, clientIp, account, bucketName))

// 	if !chain.CheckBucketName(bucketName) {
// 		b.Logput("err", clientIp+" CheckBucketName: "+bucketName)
// 		ReturnJSON(c, 400, ERR_InvalidBucketName, nil)
// 		return
// 	}

// 	pkeystr, ok := c.Get("publickey")
// 	if !ok {
// 		b.Logput("err", clientIp+" c.Get(publickey) failed")
// 		ReturnJSON(c, 500, ERR_SystemErr, nil)
// 		return
// 	}
// 	pkey, err := hex.DecodeString(fmt.Sprintf("%v", pkeystr))
// 	if err != nil {
// 		b.Logput("err", clientIp+" hex.DecodeString "+fmt.Sprintf("%v", pkeystr)+" "+err.Error())
// 		ReturnJSON(c, 500, ERR_SystemErr, nil)
// 		return
// 	}

// 	if !sutils.CompareSlice(pkey, b.GetSignatureAccPulickey()) {
// 		err = CheckAuthorize(b.Chainer, c, pkey)
// 		if err != nil {
// 			b.Logput("err", clientIp+" CheckAuthorize: "+err.Error())
// 			return
// 		}
// 	}

// 	blockHash, err := b.CreateBucket(pkey, bucketName)
// 	if err != nil {
// 		b.Logput("err", clientIp+" CreateBucket: "+err.Error())
// 		ReturnJSON(c, 400, err.Error(), nil)
// 		return
// 	}
// 	b.Logput("info", clientIp+" create bucket ["+bucketName+"] suc, and the bloack hash is: "+blockHash)
// 	ReturnJSON(c, 200, MSG_OK, nil)
// }

// func (b *BucketHandler) DeleteBucketHandle(c *gin.Context) {
// 	clientIp := c.Request.Header.Get("X-Forwarded-For")
// 	if clientIp == "" {
// 		clientIp = c.ClientIP()
// 	}
// 	account := c.Request.Header.Get(HTTPHeader_Account)
// 	bucketName := c.Param(HTTP_ParameterName)
// 	if bucketName == "" {
// 		bucketName = c.Request.Header.Get(HTTPHeader_Bucket)
// 	}

// 	b.Logdel("info", utils.StringBuilder(400, clientIp, account, bucketName))

// 	if !chain.CheckBucketName(bucketName) {
// 		b.Logput("err", clientIp+" CheckBucketName: "+bucketName)
// 		ReturnJSON(c, 400, ERR_InvalidBucketName, nil)
// 		return
// 	}

// 	pkeystr, ok := c.Get("publickey")
// 	if !ok {
// 		b.Logget("err", clientIp+" c.Get(publickey) failed")
// 		ReturnJSON(c, 500, ERR_SystemErr, nil)
// 		return
// 	}
// 	pkey, err := hex.DecodeString(fmt.Sprintf("%v", pkeystr))
// 	if err != nil {
// 		b.Logget("err", clientIp+" hex.DecodeString "+fmt.Sprintf("%v", pkeystr)+" "+err.Error())
// 		ReturnJSON(c, 500, ERR_SystemErr, nil)
// 		return
// 	}

// 	if !sutils.CompareSlice(pkey, b.GetSignatureAccPulickey()) {
// 		err = CheckAuthorize(b.Chainer, c, pkey)
// 		if err != nil {
// 			b.Logput("err", clientIp+" CheckAuthorize: "+err.Error())
// 			return
// 		}
// 	}

// 	blockHash, err := b.DeleteBucket(pkey, bucketName)
// 	if err != nil {
// 		b.Logdel("err", clientIp+" DeleteBucket failed: "+err.Error())
// 		ReturnJSON(c, 400, "bucket not exist or not empty", nil)
// 		return
// 	}
// 	b.Logdel("info", clientIp+" DeleteBucket suc: "+blockHash)
// 	ReturnJSON(c, 200, MSG_OK, map[string]string{"block hash": blockHash})
// }

// func (b *BucketHandler) GetBucketHandle(c *gin.Context) {
// 	clientIp := c.Request.Header.Get("X-Forwarded-For")
// 	if clientIp == "" {
// 		clientIp = c.ClientIP()
// 	}
// 	account := c.Request.Header.Get(HTTPHeader_Account)
// 	bucketName := c.Request.Header.Get(HTTPHeader_Bucket)

// 	pkeystr, ok := c.Get("publickey")
// 	if !ok {
// 		b.Logget("err", clientIp+" c.Get(publickey) failed")
// 		ReturnJSON(c, 500, ERR_SystemErr, nil)
// 		return
// 	}
// 	pkey, err := hex.DecodeString(fmt.Sprintf("%v", pkeystr))
// 	if err != nil {
// 		b.Logget("err", clientIp+" hex.DecodeString "+fmt.Sprintf("%v", pkeystr)+" "+err.Error())
// 		ReturnJSON(c, 500, ERR_SystemErr, nil)
// 		return
// 	}

// 	if bucketName != "" {
// 		b.Logget("info", clientIp+" get bucket info: "+account+" "+bucketName)
// 		if !chain.CheckBucketName(bucketName) {
// 			b.Logget("err", clientIp+" CheckBucketName: "+bucketName)
// 			ReturnJSON(c, 400, ERR_InvalidBucketName, nil)
// 			return
// 		}
// 		bucketInfo, err := b.QueryBucket(pkey, bucketName, -1)
// 		if err != nil {
// 			if err.Error() == chain.ERR_Empty {
// 				b.Logget("err", clientIp+" get bucket info: NotFount")
// 				ReturnJSON(c, 404, ERR_NotFound, nil)
// 				return
// 			}
// 			b.Logget("err", clientIp+" get bucket info failed: "+err.Error())
// 			ReturnJSON(c, 403, ERR_RPCConnection, nil)
// 			return
// 		}

// 		filesHash := make([]string, len(bucketInfo.FileList))
// 		for i := 0; i < len(bucketInfo.FileList); i++ {
// 			filesHash[i] = string(bucketInfo.FileList[i][:])
// 		}

// 		owners := make([]string, len(bucketInfo.Authority))
// 		for i := 0; i < len(bucketInfo.Authority); i++ {
// 			owners[i], _ = sutils.EncodePublicKeyAsCessAccount(bucketInfo.Authority[i][:])
// 		}

// 		data := struct {
// 			Num    int      `json:"num"`
// 			Owners []string `json:"owners"`
// 			Files  []string `json:"files"`
// 		}{
// 			Num:    len(bucketInfo.FileList),
// 			Owners: owners,
// 			Files:  filesHash,
// 		}
// 		b.Logget("info", clientIp+" get bucket info suc: "+account+" "+bucketName)
// 		ReturnJSON(c, 200, MSG_OK, data)
// 		return
// 	}

// 	b.Logget("info", clientIp+" get bucket list: "+account)

// 	// get bucket list
// 	bucketList, err := b.QueryAllBucketName(pkey, -1)
// 	if err != nil {
// 		if err.Error() == chain.ERR_Empty {
// 			b.Logget("err", clientIp+" get bucket info: NotFount")
// 			ReturnJSON(c, 404, ERR_NotFound, nil)
// 			return
// 		}
// 		b.Logget("err", clientIp+" get bucket list failed: "+err.Error())
// 		ReturnJSON(c, 403, ERR_RPCConnection, nil)
// 		return
// 	}
// 	b.Logget("info", clientIp+" get bucket list suc: "+account)
// 	ReturnJSON(c, 200, MSG_OK, bucketList)
// }
