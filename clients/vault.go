package clients

import (
	"bytes"
	"io/ioutil"
	"net/http"

	"github.com/Jeffail/gabs"
	api "github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

const tokenPath string = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// VaultClient is our derived Vault client type for custom methods
type VaultClient struct {
	*api.Client
}

// NewVaultClient instantiates a new VaultClient
func NewVaultClient() (client *VaultClient) {
	vClient, err := api.NewClient(nil)

	if err != nil {
		log.Panicln("Error instantiating Vault client", err)
	}

	return &VaultClient{vClient}
}

// Authenticate sets up the VaultClient to be authenticated via the Kubernetes Auth Method
func (c *VaultClient) Authenticate(role string) *VaultClient {
	tokenB, err := ioutil.ReadFile(tokenPath)
	token := string(tokenB)

	reqBody := gabs.New()
	reqBody.Set(token, "jwt")
	reqBody.Set(role, "role")

	res, err := http.Post(c.Address()+"/v1/auth/kubernetes/login", "application/json", bytes.NewBuffer(reqBody.Bytes()))

	if err != nil {
		log.Panicln("Error authenticating with Vault server via Kubernetes Service Account", err, res, reqBody)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Panicln("Error reading response from server while authenticating with Vault server via Kubernetes Service Account", err, reqBody)
	}

	resJSON, err := gabs.ParseJSON(body)
	if err != nil {
		log.Panicln("Error parsing JSON response from Vault server when authenticating via Kubernetes Service Account", err, string(body))
	}

	clientToken, ok := resJSON.Path("auth.client_token").Data().(string)
	if ok != true {
		log.Panicln("Error traversing JSON response from Vault server when authenticating via Kubernetes Service Account", string(body))
	}

	log.Debugln("Logged in with token", clientToken)
	c.SetToken(clientToken)

	return c
}

// GetSecret gets a kv2 secret value as a map string -> string
func (c *VaultClient) GetSecret(secret string) map[string]string {

	resp, err := c.Logical().Read(secret)

	if err != nil {
		log.Panicln("Error obtaining secret from Vault server", err)
	}

	log.Debugln("Response payload", resp)

	if resp == nil {
		log.Fatalln("Secret not found in Vault server, exitting:", secret)
	}

	o := map[string]string{}
	data, ok := resp.Data["data"].(map[string]interface{})

	if !ok {
		log.Panicln("Failed coercing secret to map[string]string from Vault server", err)
	}

	for k, v := range data {
		if vs, ok := v.(string); ok {
			o[k] = vs
		}
	}

	return o
}
