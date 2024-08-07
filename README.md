# <h1 align="center">DeOSS </br> [![GitHub license](https://img.shields.io/badge/license-Apache2-blue)](#LICENSE) <a href=""><img src="https://img.shields.io/badge/golang-%3E%3D1.20-blue.svg"/></a> [![Go Reference](https://pkg.go.dev/badge/github.com/CESSProject/DeOSS.svg)](https://pkg.go.dev/github.com/CESSProject/DeOSS)  [![build](https://github.com/CESSProject/DeOSS/actions/workflows/build.yml/badge.svg)](https://github.com/CESSProject/DeOSS/actions/workflows/build.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/CESSProject/cess-oss)](https://goreportcard.com/report/github.com/CESSProject/cess-oss)</h1>

DeOSS ( Decentralized Object Storage Service ) is a decentralized object-based mass storage service that provides low-cost, secure and scalable distributed data storage services for the web3 domain.

## 📝 Reporting a Vulnerability
If you find any system errors or you have better suggestions, please submit an issue or PR, or join the [CESS discord](https://discord.gg/mYHTMfBwNS) to communicate with us.

## 📢 Announcement
### CESS test network rpc endpoints
```
wss://testnet-rpc.cess.cloud/ws/
```
### CESS test network bootstrap node
```
_dnsaddr.boot-miner-testnet.cess.cloud
```

### CESS test network public gateway

| Address | `https://deoss-pub-gateway.cess.cloud/`           |
| ------- | ------------------------------------------------- |

| Account | `cXhwBytXqrZLr1qM5NHJhCzEMckSTzNKw17ci2aHft6ETSQm9` |
| ------- | --------------------------------------------------- |

### 🚰 CESS test network faucet
```
https://www.cess.network/faucet.html
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
wget https://github.com/CESSProject/DeOSS/releases/download/v0.3.7/DeOSS0.3.7.linux-amd64.tar.gz
```

### Method two
Compile the binary program from the DeOSS source code and follow the process as follows:

**1) install go**

DeOSS requires [Go 1.21](https://golang.org/dl/), See the [official Golang installation instructions](https://golang.org/doc/install).

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
# RPC endpoint of the chain node
Rpc:
  # test network
  - "wss://testnet-rpc.cess.cloud/ws/"
# bootstrap nodes
Boot:
  # test network
  - "_dnsaddr.boot-miner-testnet.cess.cloud"
# signature account mnemonic
Mnemonic: "xxx ... xxx"
# service workspace
Workspace: /
# P2P communication port
P2P_Port: 4001
# service listening port
HTTP_Port: 8080
# Access mode: public / private
# In public mode, only users in Accounts can't access it. 
# In private mode, only users in Accounts can access it.
Access: public
# Account black/white list
Accounts:
# If you want to expose your oss service, please configure its domain name
Domain:

# User Files Cacher config
# File cache size, default 512G, (unit is byte)
CacheSize: 10
# File cache expiration time, default 3 hour (unit is minutes)
Expiration:
# Directory to store file cache, default path: Workspace/filecache/
CacheDir:

# Storage Node Selector config
# Used to find better storage node partners for DeOSS to upload or download files
# Two strategies for using your specified storage nodes, "priority" or "fixed", default is "priority"
SelectStrategy: 
# JSON file used to specify the storage node. If it does not exist, it will be automatically created.
# You can configure which storage nodes to use or not use in this file.
NodeFilePath:
# Maximum number of storage nodes allowed for long-term cooperation, default 120
MaxNodeNum:
# Maximum tolerable TTL for communication with storage nodes, default 500 ms (unit is milliseconds)
MaxTTL:
# Available storage node list refresh time, default 4 hours (unit is hours)
RefreshTime:
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
| domain name       | https://deoss-pub-gateway.cess.cloud/                |
+-------------------+------------------------------------------------------+
```

### exit the cess network
It is generally not recommended to use this command：
```
./deoss exit
```

# 📖 Usage for API

The public API endpoint URL of DeOSS is the server you deploy, All endpoints described in this document should be made relative to this root URL,The following example uses URL instead.

**Before using DeOSS, you must authorize it as follows:** 

1. Create a wallet account and fund it, refer to [Configure Wallet](https://github.com/CESSProject/DeOSS#configure-wallet)

2. [Purchase a territory](https://github.com/CESSProject/doc-v2/blob/main/products/deoss/picture/buy_territory.png)

3. Authorize the use right to DeOSS:[Authorize](https://github.com/CESSProject/W3F-illustration/blob/4995c1584006823990806b9d30fa7d554630ec14/deoss/authorizeOss.png)


## Identity signature

Calling some APIs requires authentication of your identity. In web3, your wallet is your identity. Generate your signature data in [the block browser](https://polkadot.js.org/apps/), and then add your signature information in the API request header to authenticate your identity. Please refer to [the signature method](https://github.com/CESSProject/doc-v2/blob/main/products/deoss/picture/sign.png).

The authentication information you need to add in the header:

| Key       | Description    | Example |
| --------- | -------------- | ------- |
| Account   | wallet account | cX...   |
| Message   | signed message | ...     |
| Signature | signature      | 0x...   |

 
## Create a bucket

| **PUT**  /bucket |
| ---------------- |

The put bucket interface is used to create a bucket. When uploading files, the bucket must be specified for storage.

- Request Header

| key           | value               |
| ------------- | ------------------- |
| Bucket        | created bucket name |

_Identity signature required: yes_

- Request example

```shell
# curl -X PUT URL/ -H "Bucket: bucket_name" -H "Account: cX..." -H "Message: ..." -H "Signature: 0x..."
```

## Upload a file

| **PUT**  /file |
| -------------- |

The put file interface is used to upload files to the cess system. You need to submit the file as form data and use provide the specific field.
If the upload is successful, you will get the fid of the file. If you want to encrypt your file, you can specify the `cipher` field in the header and enter your password (the length cannot exceed 32 characters), and the system will automatically encrypt it.

- Request Header

| key              | description        |
| ---------------- | ------------------ |
| Bucket           | bucket name        |
| Territory        | territory name     |
| Cipher(optional) | cipher             |

_Identity signature required: yes_

- Request Body

| key  | value        |
| ---- | ------------ |
| file | file[binary] |

- Request example

```shell
# curl -X PUT URL/file -F 'file=@test.log;type=application/octet-stream' -H "Bucket: bucket_name" -H "Territory: territory_name" -H "Account: cX..." -H "Message: ..." -H "Signature: 0x..."
```

## Upload an object

| **PUT**  /object |
| ---------------- |

This interface is used to upload an object, you can write what you want to store directly in the body instead of specifying a file.
If the upload is successful, you will get the fid of the object. if you want to encrypt the object, you can specify the "Cipher" field in the header of the request and enter a password (the length can not be more than 32 characters), the system will encrypt it automatically.

- Request Header

| key              | description        |
| ---------------- | ------------------ |
| Bucket           | bucket name        |
| Territory        | territory name     |
| Cipher(optional) | cipher             |

_Identity signature required: yes_

- Request Body

[content]


- Request example

```shell
# curl -X PUT URL/object --data "content" -H "Bucket: bucket_name" -H "Territory: territory_name" -H "Account: cX..." -H "Message: ..." -H "Signature: 0x..."
```

## Chunked upload

| **PUT**  /chunks |
| ---------------- |

Compared with uploading the entire file directly, resumable upload has some more parameter requirements, but has the same return result. At the same time, the uploaded file can also be encrypted.

- Request Header

| key           | description        |
| ------------- | ------------------ |
| Bucket        | stored bucket name |
| Territory     | territory name     |
| Cipher(optional)        | your cipher        |
| FileName      | file name or alias  |
| BlockNumber   | The number of chunks the file is to be divided into  |
| BlockIndex    | index of chunk to be uploaded, [0,BlockNumber)  |
| TotalSize     | the byte size of the file, the sum of the sizes of all chunks  |

_Identity signature required: yes_

- Request Body

| key  | value        |
| ---- | ------------ |
| file | file[binary] |

- Request example

```shell
# curl -X PUT URL/chunks -F 'file=@test-chunk0;type=application/octet-stream' -H "Bucket: bucket_name" -H "Territory: territory_name" -H "Account: cX..." -H "Message: ..." -H "Signature: 0x... -H FileName: test.log -H BlockNumber: 5 -H BlockIndex: 0 -H TotalSize: 1000"
```

## Download a file

| **GET**  /download/{fid} |
| ------------------------ |

This interface is used to download a file with a specified fid. If you encrypted the file when you uploaded it, you also need to tell the gateway your cipher to decrypt your file.

- Request Header

| key              | value    |
| ---------------- | -------- |
| Cipher(optional) | cipher   |


- Request example

```shell
# curl -X GET -o <save_file> URL/download/<fid>
```

## Preview a file

| **GET**  /open/{fid} |
| -------------------- |

This interface is used to preview a file, it has two prerequisites: one is that the file is not encrypted, and the other is that the file format supports preview.

- Request example

Open in browser: URL/open/<fid>


## Delete a file

The delete file interface is used for delete a file.

| **DELETE**  /file/{fid} |
| ----------------------- |

- Request Header

_Identity signature required: yes_

- Request example

```shell
# curl -X DELETE URL/file/<fid> -H "Account: cX..." -H "Message: ..." -H "Signature: 0x..."
```

## Delete a bucket

The delete bucket interface is used for delete a bucket, all files in the bucket will also be deleted together.

| **DELETE**  /bucket/{bucket_name} |
| -------------------------------- |

- Request Header

_Identity signature required: yes_

- Request example

```shell
# curl -X DELETE URL/bucket/<bucket_name> -H "Account: cX..." -H "Message: ..." -H "Signature: 0x..."
```

## View bucket info

| **GET**  /bucket |
| ---------------- |

This interface is used to view bucket information, including the number of stored files and file IDs.

- Request Header

| key     | value       |
| ------- | ----------- |
| Account | cX...       |
| Bucket  | bucket_name |

- Request example

```shell
# curl -X GET URL/bucket -H "Account: cX..." -H "Bucket: bucket_name"
```

## View bucket list

| **GET**  /bucket |
| ---------------- |

- Request Header

| key     | value  |
| ------- | ------ |
| Account | cX...  |

This interface is used to view all buckets.

- Request example

```shell
# curl -X GET URL/bucket -H "Account: cX..."
```

## View file metadata

| **GET**  /metadata/{fid} |
| ------------------------ |

This interface is used to view the basic information of a file.

- Request example

```shell
# curl -X GET URL/metadata/<fid>
```

## View version

| **GET**  /version |
| ----------------- |

This interface is used to view the version number of the gateway.

- Request example

```shell
# curl -X GET URL/version
```

## License

Licensed under [Apache 2.0](https://github.com/CESSProject/cess-gateway/blob/main/LICENSE)
