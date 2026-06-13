package cmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/cometbft/cometbft/privval"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
				return provisionSoftware(be.SoftwareKeyFile, overwrite)
			case backend.TypeVault:
				return provisionVault(be.Vault)
			case backend.TypeGCPKMS:
				return provisionGCP(gcp, be.GCPKMS.CredentialsFile)
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

func provisionSoftware(keyFile string, overwrite bool) error {
	if keyFile == "" {
		return fmt.Errorf("software backend requires --key-file")
	}
	if _, err := os.Stat(keyFile); err == nil && !overwrite {
		return fmt.Errorf("%s already exists (use --overwrite)", keyFile)
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	pv := privval.GenFilePV(keyFile, "")
	pv.Key.Save()

	pub, err := pv.GetPubKey()
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

	ctx := context.Background()
	opts, err := backend.GCPClientOptions(credsFile)
	if err != nil {
		return err
	}
	client, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return fmt.Errorf("new kms client: %w", err)
	}
	defer client.Close()

	locationName := fmt.Sprintf("projects/%s/locations/%s", g.project, g.location)
	if _, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    locationName,
		KeyRingId: g.keyring,
		KeyRing:   &kmspb.KeyRing{},
	}); err != nil && status.Code(err) != codes.AlreadyExists {
		return fmt.Errorf("create key ring: %w", err)
	}

	created, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      locationName + "/keyRings/" + g.keyring,
		CryptoKeyId: g.key,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_ED25519,
				ProtectionLevel: level,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("create crypto key: %w", err)
	}

	version := created.Name + "/cryptoKeyVersions/1"
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
