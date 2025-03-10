# <h1 align="center">DeOSS </br> [![GitHub license](https://img.shields.io/badge/license-Apache2-blue)](#LICENSE) <a href=""><img src="https://img.shields.io/badge/golang-%3E%3D1.22-blue.svg"/></a> [![Go Reference](https://pkg.go.dev/badge/github.com/CESSProject/DeOSS.svg)](https://pkg.go.dev/github.com/CESSProject/DeOSS)  [![build](https://github.com/CESSProject/DeOSS/actions/workflows/build.yml/badge.svg)](https://github.com/CESSProject/DeOSS/actions/workflows/build.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/CESSProject/cess-oss)](https://goreportcard.com/report/github.com/CESSProject/cess-oss)</h1>

DeOSS (Decentralized Object Storage Service) is a decentralized object-based, low-cost, secure, agile, and scalable distributed mass storage service for the web3 industry. Both enterprises and individuals can use DeOSS to store. Based on blockchain technology, DeOSS effectively utilizes online idle storage resources to build a vast distributed storage network. The mission of DeOSS is to give the data ownership and benefits right back to the data producers, rather than centralized platforms.

### 🙋‍♂️ Reporting a Vulnerability
If you find any system errors or you have better suggestions, please submit an [issue](https://github.com/CESSProject/DeOSS/issues) or [PR](https://github.com/CESSProject/DeOSS/pulls), or join the [CESS discord](https://discord.gg/mYHTMfBwNS) to communicate with us.

### 📢 Announcement
**Test network rpc endpoint**
```
wss://testnet-rpc.cess.network/ws/
```

**Test network public gateway**

| Account | Address |
| ------- | ------------------------------------------------- |
| cXf3X3ugTnivQA9iDRYmLNzxSqybgDtpStBjFcBZEoH33UVaz | https://deoss-sgp.cess.network |
| cXjy16zpi3kFU6ThDHeTifpwHop4YjaF3EvYipTeJSbTjmayP | https://deoss-sv.cess.network  |
| cXhkf7fFTToo8476oeRqxyWVnxF8ESsd8b7Yh258v6n26RTkL | https://deoss-fra.cess.network |


### 🚰 Test network faucet
```
https://www.cess.network/faucet.html
```

### :warning: Attention
The following commands are executed with root privileges, if the prompt `Permission denied` appears, you need to switch to root privileges, or add `sudo` at the top of these commands.

### ⚙ System configuration
**System requirements**

- Linux 64-bit Intel/AMD

**Install application tools**

For the Debian and  ubuntu families of linux systems:

```shell
apt install git curl wget vim util-linux -y
```

For the Fedora, RedHat and CentOS families of linux systems:

```
yum install git curl wget vim util-linux -y
```

**Firewall configuration**

Deoss defaults to listening on port `8080`.  The reference for configuring firewall open ports is as follows:

**· ufw**

For hosts with ufw enabled (Debian, Ubuntu, etc.), you can use the ufw command to allow traffic to flow to specific ports. Use the following command to allow access to a port:
```
ufw allow 8080
```

**· firewall-cmd**

For hosts with firewall-cmd enabled (CentOS), you can use the firewall-cmd command to allow traffic on specific ports. Use the following command to allow access to a port:
```
firewall-cmd --get-active-zones
```
This command gets the active zone(s). Now, apply port rules to the relevant zones returned above. For example if the zone is public, use
```
firewall-cmd --zone=public --add-port=8080/tcp --permanent
```
Note that permanent makes sure the rules are persistent across firewall start, restart or reload. Finally reload the firewall for changes to take effect.
```
firewall-cmd --reload
```

**· iptables**

For hosts with iptables enabled (RHEL, CentOS, etc.), you can use the iptables command to enable all traffic to a specific port. Use the following command to allow access to a port:
```
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
service iptables restart
```

### 🏗 Get the binary program
**method one**

Download the latest release code directly at： [Releases](https://github.com/CESSProject/DeOSS/releases)

**method two**

Compile the binary program from the DeOSS source code and follow the process as follows:

***1) install go***

DeOSS requires [Go 1.22](https://golang.org/dl/), See the [official Golang installation instructions](https://golang.org/doc/install).

Open go mod mode:
```
go env -w GO111MODULE="on"
```

Users in China can add go proxy to speed up the download:
```
go env -w GOPROXY="https://goproxy.cn,direct"
```

***2) clone and compile code***
```
git clone https://github.com/CESSProject/DeOSS.git
go build -o deoss cmd/main.go
chmod +x deoss
```

### 💰 Create CESS Account

The wallet is your unique identity in the cess network, it allows you to do transactions with the cess chain, provided that you have some balance in your wallet.

Please refer to [CESS Account](https://doc.cess.network/user/cess-account) to create your cess wallet.

For test network please claim your free CESS tokens at `https://www.cess.network/faucet.html`.

### 📝 Configuration file

Use `deoss` to generate configuration file templates directly in the current directory:

```shell
./deoss config
```
The generated configuration file template comes with some default content, you need to modify it according to the actual situation. By default, `deoss` uses the `conf.yaml` in the current directory as the runtime configuration file. You can use `-c` or `-config` to specify the location of the configuration file.


### 🟢 Usage for DeOSS
**· start deoss service**
Backend operation mode (the default configuration file is in the current directory):
```shell
nohup ./deoss run 2>&1 &
```

**· view deoss status**
```
./deoss stat
+-------------------+------------------------------------------------------+
| role              | deoss                                                |
| signature account | cXjy16zpi3kFU6ThDHeTifpwHop4YjaF3EvYipTeJSbTjmayP    |
| domain name       | https://deoss-sv.cess.network                        |
+-------------------+------------------------------------------------------+
```

**· exit the cess network**
It is generally not recommended to use this command：
```
./deoss exit
```

### 📖 Usage for API

Please refer to [API Description](https://doc.cess.network/products/deoss/api_description)

### License

Licensed under [Apache 2.0](https://github.com/CESSProject/cess-gateway/blob/main/LICENSE)
