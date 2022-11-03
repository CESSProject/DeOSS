package handler

const (
	//200
	Status_200_default      = "success"
	Status_200_expired      = "captcha has expired and a new captcha has been sent to your mailbox"
	Status_200_RefreshToken = "A new token has been sent to your mailbox"
	Status_200_NoFiles      = "No files"
	Status_200_TokenExpired = "Token expired, please retrieve."
	Status_200_NoRefresh    = "Please log in to your email to view the token."
	//400
	Status_400_default     = "HTTP Error"
	Status_400_EmailFormat = "Email Format Error"
	Status_400_captcha     = "captcha error"

	Status_400_NotUploaded = "This file has not been uploaded"

	//401
	Status_401_token   = "Unauthorized"
	Status_401_expired = "token expired"

	//403
	Status_403_default        = "Forbidden"
	Status_403_NotEnoughSpace = "The gateway account space is insufficient, please contact the administrator."
	Status_403_dufilename     = "duplicate filename"
	Status_403_hotbackup      = "The file is in hot backup, please try again later."

	//500
	Status_500_db            = "Server internal data error"
	Status_500_chain         = "Server internal chain data error"
	Status_500_unexpected    = "Server unexpected error"
	Status_500_ReAuth        = "Please re-authenticate"
	Status_500_EmailSend     = "Please confirm whether the SMTP service is enabled in your mailbox or contact the gateway administrator."
	Status_500_RefreshFailed = "Please try again in 5 minutes."
	Status_500_Notfound      = "Gateway service is unavailable, please contact administrator."
)

const (
	ERR_404 = "Not found"
)

// http response message
type RespMsg struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data,omitempty"`
}

// http response random number message
type RespRandomMsg struct {
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
	Random1 int    `json:"random1"`
	Random2 int    `json:"random2"`
}

// Request structure when user registers
type ReqGrantMsg struct {
	Mailbox string `json:"mailbox"`
	Captcha int64  `json:"captcha"`
}

// Request structure when user get randomkey
type ReqRandomkeyMsg struct {
	Walletaddr string `json:"walletaddr"`
}

// user state structure
type UserStateMsg struct {
	TotalSpace   string `json:"totalSpace"`
	UsedSpace    string `json:"usedSpace"`
	FreeSpace    string `json:"freeSpace"`
	SpaceDetails []SpaceDetailsMsg
}

// user space details structure
type SpaceDetailsMsg struct {
	Size     uint64 `json:"size"`
	Deadline uint32 `json:"deadline"`
}

// Request structure when user registers
type ReqDeleteFileMsg struct {
	Token    string `json:"token"`
	Filename string `json:"filename"`
}
