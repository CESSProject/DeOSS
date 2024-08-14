# <h1 align="center">DeOSS </br> [![GitHub license](https://img.shields.io/badge/license-Apache2-blue)](#LICENSE) <a href=""><img src="https://img.shields.io/badge/golang-%3E%3D1.20-blue.svg"/></a> [![Go Reference](https://pkg.go.dev/badge/github.com/CESSProject/DeOSS.svg)](https://pkg.go.dev/github.com/CESSProject/DeOSS)  [![build](https://github.com/CESSProject/DeOSS/actions/workflows/build.yml/badge.svg)](https://github.com/CESSProject/DeOSS/actions/workflows/build.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/CESSProject/cess-oss)](https://goreportcard.com/report/github.com/CESSProject/cess-oss)</h1>

DeOSS ( Decentralized Object Storage Service ) is a decentralized object-based mass storage service that provides low-cost, secure and scalable distributed data storage services for the web3 domain.

## 📝 Reporting a Vulnerability
If you find any system errors or you have better suggestions, please submit an issue or PR, or join the [CESS discord](https://discord.gg/mYHTMfBwNS) to communicate with us.

## 📢 Announcement
### CESS test network rpc endpoints
```
wss://testnet-rpc.cess.network/ws/
```
### CESS test network bootstrap node
```
_dnsaddr.boot-miner-testnet.cess.network
```

### CESS test network public gateway

| Account | Address |
| ------- | ------------------------------------------------- |
| cXf3X3ugTnivQA9iDRYmLNzxSqybgDtpStBjFcBZEoH33UVaz | https://deoss-sgp.cess.network |
| cXjy16zpi3kFU6ThDHeTifpwHop4YjaF3EvYipTeJSbTjmayP | https://deoss-sv.cess.network  |
| cXhkf7fFTToo8476oeRqxyWVnxF8ESsd8b7Yh258v6n26RTkL | https://deoss-fra.cess.network |


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
Download the latest release code directly at： [Releases](https://github.com/CESSProject/DeOSS/releases)

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
application:
  # gateway's workspace
  workspace: "/"
  # gateway's url
  url: ""
  # gateway run mode  [debug | release]
  mode: "release"
  # gateway API communication port
  port: 8080

chain:
  # signature account mnemonic
  # substrate well-known mnemonic:
  #   - https://github.com/substrate-developer-hub/substrate-developer-hub.github.io/issues/613
  mnemonic: "bottom drive obey lake curtain smoke basket hold race lonely fit walk"
  # waiting for transaction timeout, default is 15 seconds
  timeout: 30
  # rpc endpoint list
  rpc:
    # test network
    - "wss://testnet-rpc.cess.network/ws/"

storage:
  # communication ports in the storage network
  port: 4001
  # bootstrap nodes in the storage network
  boot:
    # test network
    - "_dnsaddr.boot-miner-testnet.cess.network"

user:
  # high priority accounts will not be restricted or blacklisted when accessing the gateway
  account:

access:
  # access mode: [public | private]
  # In public mode, only users in account can't access it
  # In private mode, only users in account can access it
  mode: public
  # account black/white list
  account:

# user files cacher config
cacher:
  # file cache size, default 512G, (unit is byte)
  size: 549755813888
  # file cache expiration time, default 3 hour (unit is minutes)
  expiration: 180
  # directory to store file cache, default path: workspace/filecache/
  directory:

# storage mode selector config
selector:
  # used to find better storage node partners for gateway to upload or download files,
  # two strategies for using your specified storage nodes, [priority | fixed]
  strategy: priority
  # storage miner filter file, json format, if it does not exist, it will be automatically created.
  # you can configure which storage nodes to use or not use in this file.
  # default path: workspace/storage_nodes.json
  filter:
  # maximum number of storage nodes allowed for long-term cooperation, default 120
  number: 120
  # maximum tolerable TTL for communication with storage nodes, default 500 ms (unit is milliseconds)
  ttl: 500000000
  # available storage node list refresh time, default 4 hours (unit is hours)
  refresh: 4

shunt:
  # give priority to storing files to miners with these peerids
  peerid:
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
| signature account | cXjy16zpi3kFU6ThDHeTifpwHop4YjaF3EvYipTeJSbTjmayP    |
| domain name       | https://deoss-sv.cess.network                        |
+-------------------+------------------------------------------------------+
```

### exit the cess network
It is generally not recommended to use this command：
```
./deoss exit
```

# 📖 Usage for API

Please refer to [API Description](https://doc.cess.network/products/deoss/api_description)

## License

Licensed under [Apache 2.0](https://github.com/CESSProject/cess-gateway/blob/main/LICENSE)
