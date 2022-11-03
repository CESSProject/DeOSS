package configs

type Configfile struct {
	RpcAddr           string `toml:"RpcAddr"`
	ServicePort       string `toml:"ServicePort"`
	AccountSeed       string `toml:"AccountSeed"`
	EmailAddress      string `toml:"EmailAddress"`
	AuthorizationCode string `toml:"AuthorizationCode"`
	SMTPHost          string `toml:"SMTPHost"`
	SMTPPort          int    `toml:"SMTPPort"`
}

var C = new(Configfile)
var ConfigFilePath string

const ProfileDefault = "conf.toml"
const ProfileTemplete = `#The rpc address of the chain node
RpcAddr           = ""
#The port number on which the cess-gateway service listens
ServicePort       = "8081"
#Phrase or seed for wallet account
AccountSeed       = ""
#Email address
EmailAddress      = ""
#Email authorization code
AuthorizationCode = ""
#Outgoing server address of SMTP service
SMTPHost          = ""
#Outgoing server port number of SMTP service
SMTPPort          = 0`
