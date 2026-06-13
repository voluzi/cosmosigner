package cmd

import (
	"github.com/spf13/cobra"

	"github.com/voluzi/cosmosigner/internal/backend"
	"github.com/voluzi/cosmosigner/internal/config"
)

// registerBackendFlags adds the key-backend selection and access flags. Values
// are read back through the flag set (not bound to vars) so they can overlay a
// defaults+env-loaded config. --help defaults come from the struct defaults.
func registerBackendFlags(cmd *cobra.Command) {
	d := config.Defaults().Backend
	f := cmd.Flags()
	f.String("backend", string(d.Type), "key backend: software | vault | gcpkms")
	f.String("key-file", "", "software backend: priv_validator_key.json path")
	f.String("vault-addr", "", "vault address")
	f.String("vault-token-file", "", "vault token file path")
	f.String("vault-mount", d.Vault.Mount, "vault transit mount path")
	f.String("vault-key", "", "vault transit key name")
	f.String("vault-namespace", "", "vault namespace")
	f.String("vault-ca-cert", "", "vault CA cert path")
	f.String("gcp-key-version", "", "gcp kms cryptoKeyVersion resource name")
	f.String("gcp-credentials-file", "", "gcp service account JSON path (else ADC)")
}

// overlayBackendFlags applies explicitly-set backend flags onto c (highest
// precedence, over env/defaults).
func overlayBackendFlags(cmd *cobra.Command, c *backend.Config) {
	s := func(name string, dst *string) {
		if cmd.Flags().Changed(name) {
			*dst, _ = cmd.Flags().GetString(name)
		}
	}
	s("backend", (*string)(&c.Type))
	s("key-file", &c.SoftwareKeyFile)
	s("vault-addr", &c.Vault.Address)
	s("vault-token-file", &c.Vault.TokenFile)
	s("vault-mount", &c.Vault.Mount)
	s("vault-key", &c.Vault.KeyName)
	s("vault-namespace", &c.Vault.Namespace)
	s("vault-ca-cert", &c.Vault.TLSCACert)
	s("gcp-key-version", &c.GCPKMS.KeyVersion)
	s("gcp-credentials-file", &c.GCPKMS.CredentialsFile)
}
