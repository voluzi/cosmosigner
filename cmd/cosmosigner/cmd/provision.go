package cmd

import (
	"context"
	"encoding/base64"
	"fmt"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/spf13/cobra"

	"github.com/voluzi/cosmosigner/internal/backend"
	"github.com/voluzi/cosmosigner/internal/config"
)

// gcpCoords are the Cloud KMS key-location flags for provision/import (distinct
// from backend access config, which selects an existing key version).
type gcpCoords struct {
	project, location, keyring, key, protection, importJob string
}

func (g *gcpCoords) register(cmd *cobra.Command, withImportJob bool) {
	f := cmd.Flags()
	f.StringVar(&g.project, "gcp-project", "", "gcp project id")
	f.StringVar(&g.location, "gcp-location", "global", "kms location")
	f.StringVar(&g.keyring, "gcp-keyring", "", "kms key ring id (created if absent)")
	f.StringVar(&g.key, "gcp-key", "", "kms crypto key id")
	f.StringVar(&g.protection, "gcp-protection", "software", "protection level: software | hsm")
	if withImportJob {
		f.StringVar(&g.importJob, "gcp-import-job", "", "kms import job id (default <key>-import)")
	}
}

func (g *gcpCoords) validate() error {
	if g.project == "" || g.keyring == "" || g.key == "" {
		return fmt.Errorf("gcpkms requires --gcp-project, --gcp-keyring and --gcp-key")
	}
	return nil
}

// NewProvisionCmd builds the `provision` command.
func NewProvisionCmd() *cobra.Command {
	var (
		overwrite bool
		gcp       gcpCoords
	)
	cmd := &cobra.Command{
		Use:   "provision",
		Short: "Generate a new consensus key inside the selected backend",
		Long: `Generate a new consensus key inside the selected backend.

  software: write a priv_validator_key.json-compatible file (--key-file)
  vault:    create a non-exportable ed25519 key in the Transit engine
  gcpkms:   create an EC_SIGN_ED25519 key in Cloud KMS

To migrate an existing validator key, use "cosmosigner import" instead.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			be, err := config.LoadBackend(func(c *backend.Config) { overlayBackendFlags(cmd, c) })
			if err != nil {
				return err
			}
			switch be.Type {
			case backend.TypeSoftware, "":
				if be.SoftwareBindingFile != "" {
					// Provision refuses to overwrite a claimed key by checking and locking the marker
					// next to the key; it cannot see a relocated one.
					return fmt.Errorf("provision does not support --binding-file; provision the key, then claim it with start or claim-key")
				}
				return provisionSoftware(cmd.Context(), be.SoftwareKeyFile, overwrite)
			case backend.TypeVault:
				return provisionVault(be.Vault)
			case backend.TypeGCPKMS:
				return provisionGCP(gcp, be.GCPKMS.CredentialsFile)
			case backend.TypePKCS11:
				return fmt.Errorf("pkcs11 provision is not supported; generate the key with the vendor tool")
			default:
				return fmt.Errorf("unknown backend type %q", be.Type)
			}
		},
	}
	registerBackendFlags(cmd)
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "software backend: overwrite an existing key file")
	gcp.register(cmd, false)
	return cmd
}

func provisionSoftware(ctx context.Context, keyFile string, overwrite bool) error {
	pub, err := backend.ProvisionSoftwareKey(ctx, keyFile, overwrite)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", keyFile)
	printPubKey(pub.Address().String(), pub.Bytes())
	return nil
}

func provisionVault(vc backend.VaultConfig) error {
	if vc.KeyName == "" {
		return fmt.Errorf("vault backend requires --vault-key")
	}
	client, err := backend.NewVaultClient(vc)
	if err != nil {
		return err
	}
	if _, err := client.Logical().Write(fmt.Sprintf("%s/keys/%s", vc.Mount, vc.KeyName), map[string]any{
		"type":       "ed25519",
		"exportable": false,
	}); err != nil {
		return fmt.Errorf("create transit key: %w", err)
	}
	fmt.Printf("provisioned ed25519 transit key %q at mount %q\n", vc.KeyName, vc.Mount)
	return nil
}

func provisionGCP(g gcpCoords, credsFile string) error {
	if err := g.validate(); err != nil {
		return err
	}
	level, err := protectionLevel(g.protection)
	if err != nil {
		return err
	}

	created, err := backend.GCPProvisionKey(context.Background(), backend.GCPProvisionConfig{
		Project:         g.project,
		Location:        g.location,
		KeyRing:         g.keyring,
		Key:             g.key,
		Protection:      level,
		CredentialsFile: credsFile,
	})
	if err != nil {
		return err
	}

	version := created + "/cryptoKeyVersions/1"
	fmt.Printf("provisioned EC_SIGN_ED25519 key\n")
	fmt.Printf("key version: %s\n", version)
	fmt.Printf("run cosmosigner with --backend gcpkms --gcp-key-version %s\n", version)
	return nil
}

func protectionLevel(s string) (kmspb.ProtectionLevel, error) {
	switch s {
	case "software", "":
		return kmspb.ProtectionLevel_SOFTWARE, nil
	case "hsm":
		return kmspb.ProtectionLevel_HSM, nil
	default:
		return 0, fmt.Errorf("unknown protection level %q (software | hsm)", s)
	}
}

func printPubKey(address string, pub []byte) {
	fmt.Printf("address:        %s\n", address)
	fmt.Printf("pubkey (base64): %s\n", base64.StdEncoding.EncodeToString(pub))
}
