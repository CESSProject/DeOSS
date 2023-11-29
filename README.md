# <h1 align="center">DeOSS </br> [![GitHub license](https://img.shields.io/badge/license-Apache2-blue)](#LICENSE) <a href=""><img src="https://img.shields.io/badge/golang-%3E%3D1.20-blue.svg"/></a> [![Go Reference](https://pkg.go.dev/badge/github.com/CESSProject/DeOSS.svg)](https://pkg.go.dev/github.com/CESSProject/DeOSS)  [![build](https://github.com/CESSProject/DeOSS/actions/workflows/build.yml/badge.svg)](https://github.com/CESSProject/DeOSS/actions/workflows/build.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/CESSProject/cess-oss)](https://goreportcard.com/report/github.com/CESSProject/cess-oss)</h1>

DeOSS ( Decentralized Object Storage Service ) is a decentralized object-based mass storage service that provides low-cost, secure and scalable distributed data storage services for the web3 domain.

## 📝 Reporting a Vulnerability
If you find any system errors or you have better suggestions, please submit an issue or submit a pull request. You can also join the [CESS discord](https://discord.gg/mYHTMfBwNS) to communicate with us.

## 📢 Announcement
### CESS test network rpc endpoints
```
wss://testnet-rpc0.cess.cloud/ws/
wss://testnet-rpc1.cess.cloud/ws/
wss://testnet-rpc2.cess.cloud/ws/
```
### CESS test network bootstrap node
```
_dnsaddr.boot-bucket-testnet.cess.cloud
```

### CESS test network public gateway

| Address | `http://deoss-pub-gateway.cess.cloud/`           |
| ------- | ------------------------------------------------- |

| Account | `cXhwBytXqrZLr1qM5NHJhCzEMckSTzNKw17ci2aHft6ETSQm9` |
| ------- | --------------------------------------------------- |

### 🚰 CESS test network faucet
```
https://testnet-faucet.cess.cloud/
```

## :warning: Attention
The following commands are executed with root privileges, if the prompt `Permission denied` appears, you need to switch to root privileges, or add `sudo` at the top of these commands.

## ⚙ System configuration
### System requirements
- Linux 64-bit Intel/AMD

### Install application tools

For the Debian and  ubuntu families of linux systems:

```shell
apt install git curl wget vim util-linux -y
```

For the Fedora, RedHat and CentOS families of linux systems:

```
yum install git curl wget vim util-linux -y
```

### Firewall configuration

By default, DeOSS uses port `8080` to listen for incoming connections and internally uses port `4001` for p2p communication, if your platform blocks these two ports by default, you may need to enable access to these port.

#### ufw
For hosts with ufw enabled (Debian, Ubuntu, etc.), you can use the ufw command to allow traffic to flow to specific ports. Use the following command to allow access to a port:
```
ufw allow 8080
ufw allow 4001
```

#### firewall-cmd
For hosts with firewall-cmd enabled (CentOS), you can use the firewall-cmd command to allow traffic on specific ports. Use the following command to allow access to a port:
```
firewall-cmd --get-active-zones
```
This command gets the active zone(s). Now, apply port rules to the relevant zones returned above. For example if the zone is public, use
```
firewall-cmd --zone=public --add-port=4001/tcp --permanent
firewall-cmd --zone=public --add-port=8080/tcp --permanent
```
Note that permanent makes sure the rules are persistent across firewall start, restart or reload. Finally reload the firewall for changes to take effect.
```
firewall-cmd --reload
```

#### iptables
For hosts with iptables enabled (RHEL, CentOS, etc.), you can use the iptables command to enable all traffic to a specific port. Use the following command to allow access to a port:
```
iptables -A INPUT -p tcp --dport 4001 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
service iptables restart
```

## 🏗 Get the binary program
### Method one
Download the latest release of the binary application directly at：
```
wget https://github.com/CESSProject/DeOSS/releases/download/v0.3.3/DeOSS0.3.3.linux-amd64.tar.gz
```

### Method two
Compile the binary program from the DeOSS source code and follow the process as follows:

**1) install go**

DeOSS requires [Go 1.20](https://golang.org/dl/) or higher, See the [official Golang installation instructions](https://golang.org/doc/install).

Open go mod mode:
```
go env -w GO111MODULE="on"
```

Users in China can add go proxy to speed up the download:
```
go env -w GOPROXY="https://goproxy.cn,direct"
```

**2) clone code**
```
git clone https://github.com/CESSProject/DeOSS.git
```

**3) compile code**
```
cd DeOSS/
go build -o deoss cmd/main.go
```

**4) Grant execute permission**

```shell
chmod +x deoss
```

## 💰 Configure Wallet

### Step 1: create a wallet account
The wallet is your unique identity in the cess network, it allows you to do transactions with the cess chain, provided that you have some balance in your wallet.

Please refer to [Create-CESS-Wallet](https://github.com/CESSProject/cess/wiki/Create-a-CESS-Wallet) to create your cess wallet.

### Step 2: Recharge your wallet

If you are using the test network, Please join the [CESS discord](https://discord.gg/mYHTMfBwNS) to get it for free. If you are using the official network, please buy CESS tokens.

## Configuration file

Use `deoss` to generate configuration file templates directly in the current directory:
```shell
./deoss config
```
The contents of the configuration file template are as follows. The contents inside are the defaults and you will need to modify them as appropriate. By default, `deoss` uses `conf.yaml` in the current directory as the runtime configuration file. You can use `-c` or `-config` to specify the location of the configuration file.

```yaml
# The rpc endpoint of the chain node
Rpc:
  # test network
  - "wss://testnet-rpc0.cess.cloud/ws/"
  - "wss://testnet-rpc1.cess.cloud/ws/"
  - "wss://testnet-rpc2.cess.cloud/ws/"
# Bootstrap Nodes
Boot:
  # test network
  - "_dnsaddr.boot-kldr-testnet.cess.cloud"
# Account mnemonic
Mnemonic: "xxx xxx ... xxx"
# Service workspace
Workspace: /
# P2P communication port
P2P_Port: 4001
# Service listening port
HTTP_Port: 8080
# Access mode: public / private
# In public mode, only users in Accounts can't access it. 
# In private mode, only users in Accounts can access it.
Access: public
# Account black/white list
Accounts:
  - cX...
  - cX...
# If you want to expose your oss service, please configure its domain name
Domain: "http://deoss-pub-gateway.cess.cloud/"
```

## 🟢 Usage for DeOSS
###  start deoss service
Backend operation mode (the default configuration file is in the current directory):
```shell
nohup ./deoss run 2>&1 &
```

### view deoss status
```
./deoss stat
+-------------------+------------------------------------------------------+
| role              | deoss                                                |
| peer id           | 12D3KooWFAcDpT7vTtbsS361P14z8LpgxPMRywQr19sAdNfdDBYE |
| signature account | cXhwBytXqrZLr1qM5NHJhCzEMckSTzNKw17ci2aHft6ETSQm9    |
| domain name       | http://deoss-pub-gateway.cess.cloud/                 |
+-------------------+------------------------------------------------------+
```

### exit the cess network
It is generally not recommended to use this command：
```
./deoss exit
```

# 📖 Usage for DeOSS API

The public API endpoint URL of DeOSS is the server you deploy, All endpoints described in this document should be made relative to this root URL,The following example uses URL instead.

**Before using DeOSS, you must authorize it as follows:** 

1. Create a wallet account and fund it, refer to [Configure Wallet](https://github.com/CESSProject/DeOSS#configure-wallet)

2. Purchase cess storage space:[BuySpace](https://github.com/CESSProject/W3F-illustration/blob/4995c1584006823990806b9d30fa7d554630ec14/deoss/buySpace.png)

3. (Optional operations) The default space purchased is valid for 1 month and can be increased by [RenewalSpace](https://github.com/CESSProject/W3F-illustration/blob/4995c1584006823990806b9d30fa7d554630ec14/deoss/renewalSpace.png).

4. Authorize the use right of the space to DeOSS:[Authorize](https://github.com/CESSProject/W3F-illustration/blob/4995c1584006823990806b9d30fa7d554630ec14/deoss/authorizeOss.png)

> If you feel that you do not have enough space, you can expand it by means of [ExpansionSpace](https://github.com/CESSProject/W3F-illustration/blob/4995c1584006823990806b9d30fa7d554630ec14/deoss/expansionSpace.png).

## Authentication

The DeOSS API uses bearer tokens to authenticate requests. 

Your tokens carry many privileges, so be sure to keep them secure! Do not share your *secret tokens* in publicly accessible locations such as a GitHub repository, client-side code, and so forth.

The bearer token is a cryptic string, usually generated by the server in response to a auth request. The client must send this token in the `Authorization` header when making requests to protected resources:

| Authorization: token  |
| --------------------- |


## Get token

| **POST**  /auth |
| --------------- |

The authorization interface is used to generate user tokens.

- Request Header

| key          | value            |
| ------------ | ---------------- |
| Content-Type | application/json |

- Request Body

| field   | value                         |
| ------- | ----------------------------- |
| account | your account address          |
| message | custom Signature Message      |
| signature | signature data              |

*Reference for signature calculation method: https://github.com/CESSProject/cess-toolset/tree/main/cess-sign*


- Responses

Response schema: `application/json`

| HTTP Code | Message                    | Description                   |
| --------- | -------------------------- | ----------------------------- |
| 200       | token                      | returns a token               |
| 400       | Invalid.Body               | body content error            |
| 400       | InvalidParameter.Account   | account error                 |
| 400       | InvalidParameter.Message   | message error                 |
| 400       | InvalidParameter.Signature | signature error               |
| 403       | NoPermission               | signature verification failed |
| 500       | InternalError              | service internal error        |

- Request example

```shell
# curl -X POST URL/auth -d '{"account": "cXgfFb...bjfR", "message": "123456", "signature": [44,30,117,...,109,141]}' -H "Content-Type: application/json"
```



## Create a bucket

| **PUT**  / |
| ---------- |

The put bucket interface is used to create a bucket. When uploading files, the bucket must be specified for storage.

- Request Header

| key           | value               |
| ------------- | ------------------- |
| Authorization | token               |
| BucketName    | created bucket name |

- Responses

Response schema: `application/json`

| HTTP Code | Message                  | Description               |
| --------- | ------------------------ | ------------------------- |
| 200       | Block hash               | create bucket block hash  |
| 400       | InvalidHead.MissingToken | token is empty            |
| 400       | InvalidHead.Token        | token error               |
| 400       | InvalidParameter.Name    | wrong bucket name         |
| 403       | NoPermission             | token verification failed |
| 500       | InternalError            | service internal error    |

- Request example

```shell
# curl -X PUT URL/ -H "BucketName: bucketname" -H "Authorization: eyJhbGciOiJIUzI1NiIsI......P0Jrg-hX4bXlIyn5I8ML1g"
```

## Upload a file

| **PUT**  / |
| ---------- |

The put file interface is used to upload files to the cess system. You need to submit the file as form data and use provide the specific field.
If the upload is successful, you will get the fid of the file. If you want to encrypt your file, you can specify the `cipher` field in the header and enter your password (the length cannot exceed 32 characters), and the system will automatically encrypt it.

- Request Header

| key           | description        |
| ------------- | ------------------ |
| Authorization | token              |
| BucketName    | stored bucket name |
| cipher        | your cipher        |


- Request Body

| key  | value        |
| ---- | ------------ |
| file | file[binary] |



- Responses

Response schema: `application/json`

| HTTP Code | Message                       | Description               |
| --------- | ----------------------------- | ------------------------- |
| 200       | fid                           | file id                   |
| 400       | InvalidHead.MissingToken      | token is empty            |
| 400       | InvalidHead.MissingBucketName | bucketname is empty       |
| 400       | InvalidHead.BucketName        | wrong bucket name         |
| 400       | InvalidHead.Token             | token error               |
| 400       | Unauthorized                  | DeOSS is not authorized   |
| 400       | InvalidParameter.EmptyFile    | file is empty             |
| 400       | InvalidParameter.FormFile     | form File                 |
| 400       | InvalidParameter.File         | error receiving file      |
| 403       | NoPermission                  | token verification failed |
| 500       | InternalError                 | service internal error    |



- Request example

```shell
# curl -X PUT URL/ -F 'file=@test.log;type=application/octet-stream' -H "Authorization: eyJhbGciOiJIUzI...Iyn5I8ML1g" -H "BucketName: bucket1"
```

## Download a file

| **GET**  /{fid} |
| --------------- |

The get file interface downloads the file in the CESS storage system according to the fid.

- Request Header

| key       | value    |
| --------- | -------- |
| Operation | download |
| Account   | cX...    |

- Responses

The response schema for the normal return status is: `application/octet-stream`

The response schema for the exception return status is: `application/json`, The message returned by the exception is as follows:

| HTTP Code | Message               | Description             |
| --------- | --------------------- | ----------------------- |
| 400       | InvalidHead.Operation | operation error         |
| 403       | BackingUp             | file is being backed up |
| 404       | NotFound              | file not found          |
| 500       | InternalError         | service internal error  |

- Request example

```shell
# curl -X GET -o <savefilename> URL/fid -H "Operation: download"
```

## Delete a file

The delete file interface is used for delete a put file.

| **DELETE**  /{fid} |
| ------------------ |

- Request Header

| key           | value |
| ------------- | ----- |
| Authorization | token |

- Responses

Response schema: `application/json`

| HTTP Code | Message               | Description               |
| --------- | --------------------- | ------------------------- |
| 200       | Block hash            | delete file  block hash   |
| 400       | InvalidHead.MissToken | token is empty            |
| 400       | InvalidHead.Token     | token error               |
| 400       | InvalidParameter.Name | fid is error              |
| 403       | NoPermission          | token verification failed |
| 500       | InternalError         | service internal error    |

- Request example

```shell
# curl -X DELETE URL/fid -H "Authorization: eyJhbGciOiJIUzI1Ni......g-hX4bXlIyn5I8ML1g"
```

## Delete multiple files


| **DELETE**  / |
| ------------- |

- Request Header

| key           | value |
| ------------- | ----- |
| Authorization | token |
| Content-Type | application/json |

- Request Body
```
{
  "files": [
    "filehash1",
    "filehash2",
    "filehash3"
  ]
}
```

- Responses

Response schema: `application/json`

| HTTP Code | Message                   | Description               |
| --------- | ------------------------- | ------------------------- |
| 200       | Block hash                | delete file  block hash   |
| 400       | InvalidHead.MissToken     | token is empty            |
| 400       | InvalidHead.Token         | token error               |
| 400       | ERR_ParseBody             | unable to parse body      |
| 400       | empty files               | deleted files is empty    |
| 403       | InvalidToken.NoPermission | token verification failed |
| 500       | InternalError             | service internal error    |

- Request example

```shell
# curl -X DELETE URL/ -d '{"files": ["filehash1", "filehash2"]}' -H "Content-Type: application/json" -H "Authorization: eyJhbGciOiJIUzI1Ni......g-hX4bXlIyn5I8ML1g"
```

## Delete a bucket

The delete bucket interface is used for delete a bucket, all files in the bucket will also be deleted together.

| **DELETE**  /{BucketName} |
| ------------------------- |

- Request Header

| key           | value |
| ------------- | ----- |
| Authorization | token |

- Responses

Response schema: `application/json`

| HTTP Code | Message               | Description               |
| --------- | --------------------- | ------------------------- |
| 200       | Block hash            | delete bucket  block hash |
| 400       | InvalidHead.MissToken | token is empty            |
| 400       | InvalidHead.Token     | token error               |
| 400       | InvalidParameter.Name | bucket name is error      |
| 403       | NoPermission          | token verification failed |
| 500       | InternalError         | service internal error    |

- Request example

```shell
# curl -X DELETE URL/BucketName -H "Authorization: eyJhbGciOiJIUzI1Ni......g-hX4bXlIyn5I8ML1g"
```

## View bucket info

| **GET**  /{BucketName} |
| ---------------------- |

This interface is used to view bucket information, including the number of stored files and file IDs.

- Request Header

| key     | description     |
| ------- | --------------- |
| Account | account address |

- Responses

Response schema: `application/json`

| HTTP Code | Message                    | Description                                 |
| --------- | -------------------------- | ------------------------------------------- |
| 200       | success                    | total number of files in bucket and file id |
| 400       | InvalidHead.MissingAccount | account is empty                            |
| 400       | InvalidHead.Account        | account is error                            |
| 400       | InvalidParameter.Name      | bucket name is error                        |
| 404       | NotFound                   | bucket not found                            |
| 500       | InternalError              | service internal error                      |

- Request example

```shell
# curl -X GET URL/BucketName -H "Account: cXgfFbnV9H......PMQLoKbjfR"
```

## View bucket list

| **GET**  /* |
| ----------- |

This interface is used to view all buckets.

- Request Header

| key     | description     |
| ------- | --------------- |
| Account | account address |

- Responses

Response schema: `application/json`

| HTTP Code | Message                    | Description            |
| --------- | -------------------------- | ---------------------- |
| 200       | success                    | all bucket names       |
| 400       | InvalidHead.MissingAccount | account is empty       |
| 400       | InvalidHead.Account        | account is error       |
| 400       | InvalidParameter.Name      | * is error             |
| 404       | NotFound                   | bucket not found       |
| 500       | InternalError              | service internal error |

- Request example

```shell
# curl -X GET URL/* -H "Account: cXgfFbnV9H......PMQLoKbjfR"
```

## View file info

| **GET**  /{fid} |
| --------------- |

This interface is used to view the basic information of a file.

- Request Header

| key       | value |
| --------- | ----- |
| Operation | view  |
| Account   | cX... |

- Responses

Response schema: `application/json`

| HTTP Code | Message               | Description               |
| --------- | --------------------- | ------------------------- |
| 200       | success               | file information          |
| 400       | InvalidParameter.Name | fid or operation is error |
| 404       | NotFound              | file not found            |
| 500       | InternalError         | service internal error    |

- Request example

```shell
# curl -X GET URL/fid -H "Operation: view"
```

## License

Licensed under [Apache 2.0](https://github.com/CESSProject/cess-gateway/blob/main/LICENSE)
