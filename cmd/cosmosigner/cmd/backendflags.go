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
	f.String("backend", string(d.Type), "key backend: software | vault | gcpkms | awskms | pkcs11")
	f.String("key-file", "", "software backend: priv_validator_key.json path")
	f.String("binding-file", "", "software backend: cluster marker path (default: next to --key-file; set when the key is read-only)")
	f.String("vault-addr", "", "vault address")
	f.String("vault-token-file", "", "vault token file path")
	f.String("vault-mount", d.Vault.Mount, "vault transit mount path")
	f.String("vault-binding-mount", d.Vault.BindingMount, "vault KV v2 mount containing cluster binding records")
	f.String("vault-key", "", "vault transit key name")
	f.Int("vault-key-version", 0, "vault transit key version (0 selects the latest once at startup)")
	f.String("vault-namespace", "", "vault namespace")
	f.String("vault-ca-cert", "", "vault CA cert path")
	f.String("aws-key-id", "", "aws kms key ID, key ARN, alias or alias ARN (pinned to its key ARN at startup)")
	f.String("aws-region", "", "aws region (else the standard AWS SDK region chain)")
	f.String("gcp-key-version", "", "gcp kms cryptoKeyVersion resource name")
	f.String("gcp-credentials-file", "", "gcp service account JSON path (else ADC)")
	f.String("pkcs11-module", "", "PKCS#11 shared library path")
	f.String("pkcs11-token-label", "", "PKCS#11 token label (exclusive with --pkcs11-slot)")
	f.Uint("pkcs11-slot", 0, "PKCS#11 slot number, including 0 (exclusive with --pkcs11-token-label)")
	f.String("pkcs11-key-label", "", "PKCS#11 key label")
	f.String("pkcs11-key-id", "", "PKCS#11 key ID in hexadecimal; combined with key label when both are set")
	f.String("pkcs11-pin-file", "", "PKCS#11 PIN file path")
	f.String("pkcs11-binding-file", "", "PKCS#11 persistent cluster marker path")
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
	s("binding-file", &c.SoftwareBindingFile)
	s("vault-addr", &c.Vault.Address)
	s("vault-token-file", &c.Vault.TokenFile)
	s("vault-mount", &c.Vault.Mount)
	s("vault-binding-mount", &c.Vault.BindingMount)
	s("vault-key", &c.Vault.KeyName)
	if cmd.Flags().Changed("vault-key-version") {
		c.Vault.KeyVersion, _ = cmd.Flags().GetInt("vault-key-version")
	}
	s("vault-namespace", &c.Vault.Namespace)
	s("vault-ca-cert", &c.Vault.TLSCACert)
	s("aws-key-id", &c.AWSKMS.KeyID)
	s("aws-region", &c.AWSKMS.Region)
	s("gcp-key-version", &c.GCPKMS.KeyVersion)
	s("gcp-credentials-file", &c.GCPKMS.CredentialsFile)
	s("pkcs11-module", &c.PKCS11.Module)
	s("pkcs11-token-label", &c.PKCS11.TokenLabel)
	s("pkcs11-key-label", &c.PKCS11.KeyLabel)
	s("pkcs11-key-id", &c.PKCS11.KeyID)
	s("pkcs11-pin-file", &c.PKCS11.PINFile)
	s("pkcs11-binding-file", &c.PKCS11.BindingFile)
	if cmd.Flags().Changed("pkcs11-slot") {
		slot, _ := cmd.Flags().GetUint("pkcs11-slot")
		c.PKCS11.Slot = &slot
	}
	if cmd.Flags().Changed("pkcs11-slot") && !cmd.Flags().Changed("pkcs11-token-label") {
		c.PKCS11.TokenLabel = ""
	}
	if cmd.Flags().Changed("pkcs11-token-label") && !cmd.Flags().Changed("pkcs11-slot") {
		c.PKCS11.Slot = nil
	}

}
