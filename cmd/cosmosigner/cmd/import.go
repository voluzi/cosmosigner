package cmd

import (
	"bytes"
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/voluzi/cosmosigner/internal/backend"
	"github.com/voluzi/cosmosigner/internal/config"
)

// NewImportCmd builds the `import` command.
func NewImportCmd() *cobra.Command {
	var (
		from string
		gcp  gcpCoords
	)
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import an existing consensus key (BYOK) into vault or gcpkms",
		Long: `Import an existing priv_validator_key.json into the selected backend,
preserving the validator's on-chain identity.

  vault:  wrap with the Transit mount's RSA wrapping key (CKM_RSA_AES_KEY_WRAP)
  gcpkms: wrap with a Cloud KMS ImportJob key (RSA-OAEP-SHA256)

The key is imported NON-EXPORTABLE. The source file existed outside the
backend: securely destroy all copies of it once the validator is confirmed
signing through cosmosigner.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if from == "" {
				return fmt.Errorf("--from is required (path to priv_validator_key.json)")
			}
			be, err := config.LoadBackend(func(c *backend.Config) { overlayBackendFlags(cmd, c) })
			if err != nil {
				return err
			}
			pkcs8, pub, err := backend.LoadKeyFilePKCS8(from)
			if err != nil {
				return err
			}

			// verifyCfg is filled per backend below; after the import we read
			// the backend's public key back and require it to match the source
			// file, so a wrong-key import fails loudly instead of silently
			// changing the validator identity.
			verifyCfg := be

			switch be.Type {
			case backend.TypeVault:
				if be.Vault.KeyName == "" {
					return fmt.Errorf("vault backend requires --vault-key")
				}
				if err := backend.VaultImportKey(be.Vault, pkcs8); err != nil {
					return err
				}
				fmt.Printf("imported key into transit mount %q as %q (non-exportable)\n", be.Vault.Mount, be.Vault.KeyName)
			case backend.TypeGCPKMS:
				if err := gcp.validate(); err != nil {
					return err
				}
				level, err := protectionLevel(gcp.protection)
				if err != nil {
					return err
				}
				if gcp.importJob == "" {
					gcp.importJob = gcp.key + "-import"
				}
				version, err := backend.GCPImportKey(context.Background(), backend.GCPImportConfig{
					Project:         gcp.project,
					Location:        gcp.location,
					KeyRing:         gcp.keyring,
					Key:             gcp.key,
					ImportJobID:     gcp.importJob,
					Protection:      level,
					CredentialsFile: be.GCPKMS.CredentialsFile,
				}, pkcs8)
				if err != nil {
					return err
				}
				fmt.Printf("imported key version: %s\n", version)
				fmt.Printf("run cosmosigner with --backend gcpkms --gcp-key-version %s\n", version)
				verifyCfg.GCPKMS.KeyVersion = version
			default:
				return fmt.Errorf("import targets vault or gcpkms (the file already IS the software backend)")
			}

			if err := verifyImportedKey(verifyCfg, pub.Bytes()); err != nil {
				return err
			}

			printPubKey(pub.Address().String(), pub.Bytes())
			fmt.Println("reminder: securely destroy all copies of the source key file")
			return nil
		},
	}
	registerBackendFlags(cmd)
	cmd.Flags().StringVar(&from, "from", "", "path to the existing priv_validator_key.json")
	gcp.register(cmd, true)
	return cmd
}

// verifyImportedKey reads the public key back from the target backend and
// requires it to equal the source file's — the on-chain identity must survive
// the import bit-for-bit.
func verifyImportedKey(cfg backend.Config, wantPub []byte) error {
	b, err := backend.New(cfg)
	if err != nil {
		return fmt.Errorf("verify imported key: %w", err)
	}
	defer b.Close()
	got, err := b.PubKey()
	if err != nil {
		return fmt.Errorf("verify imported key: %w", err)
	}
	if !bytes.Equal(got.Bytes(), wantPub) {
		return fmt.Errorf("imported key public key MISMATCH: backend reports a different identity than the source file — do not point the validator at this key")
	}
	fmt.Println("verified: backend public key matches the source file")
	return nil
}
