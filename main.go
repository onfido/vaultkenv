package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"

	"vaultkenv/clients"
)

// CLI Flags
var vaultAddr string
var vaultRoleName string
var vaultSecretPath string
var vaultToken string
var command []string
var commandS string

var flagSet *flag.FlagSet

func init() {
	flagSet = flag.NewFlagSet("vaultkenv", flag.ExitOnError)

	flagSet.StringVar(&vaultAddr, "address", "", "the address of the Vault server. Defaults to VAULT_ADDR environment variable.")
	flagSet.StringVar(&vaultRoleName, "role", "", "the Vault Role name to authenticate against. Defaults to VAULT_ROLE environment variable.")
	flagSet.StringVar(&vaultSecretPath, "secret", "", "the Vault Secret path from which to fetch Environment Variables. Defaults to VAULT_SECRET environment variable.")
	flagSet.StringVar(&vaultToken, "token", "", "the Vault Token to use for authentication, disables authentication via Kubernetes Auth Method. Defaults to VAULT_TOKEN environment variable.")

	flagSet.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of vaultkenv [flags...] [command...]:\n\n")
		flagSet.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "\n  [command...] []string\n        the command to run with injected Environment Variables.\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Examples:\n")
		fmt.Fprintf(flag.CommandLine.Output(), "        vaultkenv -secret=kv/data/my-env env\n")
		fmt.Fprintf(flag.CommandLine.Output(), "        vaultkenv -secret=kv/data/my-cli python main.py\n")
		fmt.Fprintf(flag.CommandLine.Output(), "        vaultkenv -secret=kv/data/my-webapp -role=my-webapp python main.py\n\n")
	}

	flagSet.Parse(os.Args[1:])

	mergeEnvWithFlags()

	command = flagSet.Args()
	commandS = strings.Join(command, " ")

	// Enable debug level for logging if DEBUG env var is set
	if strings.ToLower(os.Getenv("DEBUG")) == "true" {
		log.SetLevel(log.DebugLevel)
	}
}

func mergeEnvWithFlags() {
	if vaultAddr == "" {
		vaultAddr = os.Getenv("VAULT_ADDR")
	}

	if vaultRoleName == "" {
		vaultRoleName = os.Getenv("VAULT_ROLE")
	}

	if vaultSecretPath == "" {
		vaultSecretPath = os.Getenv("VAULT_SECRET")
	}

	if vaultToken == "" {
		vaultToken = os.Getenv("VAULT_TOKEN")
	}
}

func runCommand(secrets map[string]string) {
	cmd := exec.Command(command[0], command[1:]...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.Env = os.Environ()
	for k, v := range secrets {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	err := cmd.Run()

	if err != nil {
		log.Println("Command finished with error:", err)
	}
	log.Println("Command finished with exit code:", cmd.ProcessState.ExitCode())
}

func main() {
	c := clients.NewVaultClient()

	if vaultToken == "" {
		c.Authenticate(vaultRoleName)
	} else {
		c.SetToken(vaultToken)
	}

	secrets := c.GetSecret(vaultSecretPath)
	log.Debugln("Secrets:", secrets)

	log.Debugln("Executed comand:", commandS)

	runCommand(secrets)
}
