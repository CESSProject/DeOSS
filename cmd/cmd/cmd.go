package cmd

import (
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"

	"github.com/CESSProject/cess-oss/configs"
	"github.com/CESSProject/cess-oss/internal/chain"
	"github.com/CESSProject/cess-oss/internal/handler"
	"github.com/CESSProject/cess-oss/internal/logger"
	"github.com/CESSProject/cess-oss/tools"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Print version number and exit
func Command_Version_Runfunc(cmd *cobra.Command, args []string) {
	fmt.Println(configs.Version)
	os.Exit(0)
}

// start service
func Command_Run_Runfunc(cmd *cobra.Command, args []string) {
	refreshProfile(cmd)
	logger.Log_Init()
	handler.Main()
}

// buy space package
func Command_BuySpace_Runfunc(cmd *cobra.Command, args []string) {
	if len(os.Args) < 3 {
		log.Println("[err] Please enter the correct package type: [1,2,3,4,5]")
		os.Exit(1)
	}
	count := types.NewU128(*big.NewInt(0))
	p_type, err := strconv.Atoi(os.Args[2])
	if err != nil {
		log.Println("[err] Please enter the correct package type: [1,2,3,4,5]")
		os.Exit(1)
	}
	if p_type < 1 || p_type > 5 {
		log.Println("[err] Please enter the correct package type: [1,2,3,4,5]")
		os.Exit(1)
	}
	if p_type == 5 {
		if len(os.Args) < 4 {
			log.Println("[err] Please enter the purchased space size (unit: TB)")
			os.Exit(1)
		}
		si, err := strconv.ParseUint(os.Args[3], 10, 64)
		if err != nil {
			log.Println("[err] Please enter a number greater than 5")
			os.Exit(1)
		}
		if si < 5 {
			log.Println("[err] Please enter a number greater than 5")
			os.Exit(1)
		}
		count.SetUint64(si)
	}
	refreshProfile(cmd)
	logger.Log_Init()
	txhash, err := chain.BuySpacePackage(types.U8(p_type-1), count)
	if err != nil {
		if err.Error() == chain.ERR_Empty {
			log.Println("[err] Please check your wallet balance.")
		} else {
			if txhash != "" {
				msg := configs.HELP_BuySpace1 + fmt.Sprintf(" %v\n", txhash)
				msg += configs.HELP_BuySpace2
				log.Printf("[pending] %v\n", msg)
			} else {
				log.Printf("[err] %v.\n", err)
			}
		}
		os.Exit(1)
	}
	logger.Out.Sugar().Infof("Space purchased successfully: %v", txhash)
	log.Printf("[ok] success\n")
	os.Exit(0)
}

// buy space package
func Command_UpgradePackage_Runfunc(cmd *cobra.Command, args []string) {
	if len(os.Args) < 3 {
		log.Println("[err] Please enter the correct package type: [1,2,3,4,5]")
		os.Exit(1)
	}
	count := types.NewU128(*big.NewInt(0))
	p_type, err := strconv.Atoi(os.Args[2])
	if err != nil {
		log.Println("[err] Please enter the correct package type: [1,2,3,4,5]")
		os.Exit(1)
	}
	if p_type < 1 || p_type > 5 {
		log.Println("[err] Please enter the correct package type: [1,2,3,4,5]")
		os.Exit(1)
	}
	if p_type == 5 {
		if len(os.Args) < 4 {
			log.Println("[err] Please enter the purchased space size (unit: TiB)")
			os.Exit(1)
		}
		si, err := strconv.ParseUint(os.Args[3], 10, 64)
		if err != nil {
			log.Println("[err] Please enter a number greater than 5")
			os.Exit(1)
		}
		if si < 5 {
			log.Println("[err] Please enter a number greater than 5")
			os.Exit(1)
		}
		count.SetUint64(si)
	}
	refreshProfile(cmd)
	logger.Log_Init()
	txhash, err := chain.UpgradeSpacePackage(types.U8(p_type-1), count)
	if err != nil {
		if err.Error() == chain.ERR_Empty {
			log.Println("[err] Please check your wallet balance.")
		} else {
			if txhash != "" {
				msg := configs.HELP_common + fmt.Sprintf(" %v\n", txhash)
				msg += configs.HELP_Upgrade
				log.Printf("[pending] %v\n", msg)
			} else {
				log.Printf("[err] %v.\n", err)
			}
		}
		os.Exit(1)
	}
	logger.Out.Sugar().Infof("Upgrade space package successfully: %v", txhash)
	log.Printf("[ok] success\n")
	os.Exit(0)
}

// Increase space package lease term
func Command_Renewal_Runfunc(cmd *cobra.Command, args []string) {
	refreshProfile(cmd)
	logger.Log_Init()
	txhash, err := chain.Renewal()
	if err != nil {
		if err.Error() == chain.ERR_Empty {
			log.Println("[err] Please check your wallet balance.")
		} else {
			if txhash != "" {
				msg := configs.HELP_common + fmt.Sprintf(" %v\n", txhash)
				msg += configs.HELP_Renewal
				log.Printf("[pending] %v\n", msg)
			} else {
				log.Printf("[err] %v.\n", err)
			}
		}
		os.Exit(1)
	}
	logger.Out.Sugar().Infof("Renewal space package successfully: %v", txhash)
	log.Printf("[ok] success\n")
	os.Exit(0)
}

// Increase space package lease term
func Command_Space_Runfunc(cmd *cobra.Command, args []string) {
	refreshProfile(cmd)
	logger.Log_Init()
	sp, err := chain.GetSpacePackageInfo(configs.C.AccountSeed)
	if err != nil {
		if err.Error() == chain.ERR_Empty {
			log.Println("[ok] No space package purchased.")
		} else {
			log.Printf("[err] %v.\n", err)
		}
		os.Exit(0)
	}

	//print your own details
	fmt.Printf("Total Space: %v byte\nUsed Space: %v byte\nRemaining Space: %v byte\nPackage Type: %v\nDeadline: %v\nState: %v\n",
		sp.Space, sp.Used_space, sp.Remaining_space, sp.Package_type+1, sp.Deadline, string(sp.State))
	os.Exit(0)
}

func refreshProfile(cmd *cobra.Command) {
	configpath1, _ := cmd.Flags().GetString("config")
	configpath2, _ := cmd.Flags().GetString("c")
	if configpath1 != "" {
		configs.ConfigFilePath = configpath1
	} else {
		configs.ConfigFilePath = configpath2
	}
	parseProfile()
}

func parseProfile() {
	var (
		err          error
		confFilePath string
	)
	if configs.ConfigFilePath == "" {
		confFilePath = "./conf.toml"
	} else {
		confFilePath = configs.ConfigFilePath
	}
	f, err := os.Stat(confFilePath)
	if err != nil {
		log.Printf("[err] The '%v' file does not exist.\n", confFilePath)
		os.Exit(1)
	}
	if f.IsDir() {
		log.Printf("[err] The '%v' is not a file.\n", confFilePath)
		os.Exit(1)
	}

	viper.SetConfigFile(confFilePath)
	viper.SetConfigType("toml")

	err = viper.ReadInConfig()
	if err != nil {
		log.Printf("[err] The '%v' file type error.\n", confFilePath)
		os.Exit(1)
	}

	err = viper.Unmarshal(configs.C)
	if err != nil {
		log.Printf("[err] Configuration file error, please use the default command to generate a template.\n")
		os.Exit(1)
	}

	if configs.C.RpcAddr == "" ||
		configs.C.AccountSeed == "" ||
		configs.C.EmailAddress == "" ||
		configs.C.AuthorizationCode == "" ||
		configs.C.SMTPHost == "" {
		log.Printf("[err] The configuration file cannot have empty entries.\n")
		os.Exit(1)
	}

	if !tools.VerifyMailboxFormat(configs.C.EmailAddress) {
		fmt.Printf("[err] '%v' email format error\n", configs.C.EmailAddress)
		os.Exit(1)
	}

	port, err := strconv.Atoi(configs.C.ServicePort)
	if err != nil {
		log.Printf("[err] Please fill in the correct 'ServicePort'.\n")
		os.Exit(1)
	}
	if port < 1024 {
		log.Printf("[err] Prohibit the use of system reserved port: %v.\n", port)
		os.Exit(1)
	}
	if port > 65535 {
		log.Printf("[err] The 'ServicePort' cannot exceed 65535.\n")
		os.Exit(1)
	}

	//
	if configs.C.SMTPPort <= 0 {
		log.Printf("[err] The 'SMTPPort' is invalid.\n")
		os.Exit(1)
	}

	//
	if err := tools.CreatDirIfNotExist(configs.BaseDir); err != nil {
		log.Printf("[err] %v\n", err)
		os.Exit(1)
	}

	if err := tools.CreatDirIfNotExist(configs.LogfileDir); err != nil {
		log.Printf("[err] %v\n", err)
		os.Exit(1)
	}

	if err := tools.CreatDirIfNotExist(configs.DbDir); err != nil {
		log.Printf("[err] %v\n", err)
		os.Exit(1)
	}

	if err := tools.CreatDirIfNotExist(configs.FileCacheDir); err != nil {
		log.Printf("[err] %v\n", err)
		os.Exit(1)
	}

	//
	configs.PublicKey, err = chain.GetPublicKey(configs.C.AccountSeed)
	if err != nil {
		log.Printf("[err] %v\n", err)
		os.Exit(1)
	}
}
