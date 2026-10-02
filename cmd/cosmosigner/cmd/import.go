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
		Short: "Import an existing consensus key (BYOK) into vault, gcpkms or awskms",
		Long: `Import an existing priv_validator_key.json into the selected backend,
preserving the validator's on-chain identity.

  vault:  wrap with the Transit mount's RSA wrapping key (CKM_RSA_AES_KEY_WRAP)
  gcpkms: wrap with a Cloud KMS ImportJob key (RSA-OAEP-SHA256)
  awskms: wrap PKCS#8 with an AWS KMS RSA_4096 key (RSA-OAEP-SHA256)

The key is imported NON-EXPORTABLE. The source file existed outside the
backend. For Vault and Google Cloud KMS, securely destroy file copies once
the validator is confirmed signing through cosmosigner. For AWS KMS, retain
a protected recovery backup outside AWS, preferably in an HSM; the customer
is responsible for the durability of imported key material.`,
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
			// Accepted material may need a follow-up identity check when the
			// public key is not readable with this identity or within the timeout.
			deferVerify := false

			switch be.Type {
			case backend.TypeVault:
				if be.Vault.KeyName == "" {
					return fmt.Errorf("vault backend requires --vault-key")
				}
				if err := backend.VaultImportKey(be.Vault, pkcs8); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "imported key into transit mount %q as %q (non-exportable)\n", be.Vault.Mount, be.Vault.KeyName)
			case backend.TypeAWSKMS:
				keyARN, ready, err := backend.AWSImportKey(cmd.Context(), be.AWSKMS, pkcs8)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "imported AWS key: %s\nrun cosmosigner with %s\n", keyARN, awsBackendArgs(keyARN, be.AWSKMS.Region))
				verifyCfg.AWSKMS.KeyID = keyARN
				deferVerify = !ready
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
				version, ready, err := backend.GCPImportKey(context.Background(), backend.GCPImportConfig{
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
				fmt.Fprintf(cmd.OutOrStdout(), "imported key version: %s\n", version)
				fmt.Fprintf(cmd.OutOrStdout(), "run cosmosigner with --backend gcpkms --gcp-key-version %s\n", version)
				verifyCfg.GCPKMS.KeyVersion = version
				deferVerify = !ready
			default:
				return fmt.Errorf("import targets vault, gcpkms or awskms (the file already IS the software backend)")
			}

			// A pending import cannot establish the on-chain identity until KMS exposes its public key.
			if deferVerify {
				if be.Type == backend.TypeAWSKMS {
					fmt.Fprintln(cmd.OutOrStdout(), "import accepted, but KMS public key verification is pending — identity not verified yet.")
				} else {
					fmt.Fprintln(cmd.OutOrStdout(), "import accepted, but the key is still finalizing in KMS — identity not verified yet.")
				}
				fmt.Fprintln(cmd.OutOrStdout(), "the backend MUST end up serving this exact identity:")
				printPubKeyTo(cmd.OutOrStdout(), pub.Address().String(), pub.Bytes())
				verifyCmd := fmt.Sprintf("cosmosigner pubkey --backend gcpkms --gcp-key-version %s", verifyCfg.GCPKMS.KeyVersion)
				if verifyCfg.GCPKMS.CredentialsFile != "" {
					verifyCmd += " --gcp-credentials-file " + verifyCfg.GCPKMS.CredentialsFile
				}

				if be.Type == backend.TypeAWSKMS {
					verifyCmd = "cosmosigner pubkey " + awsBackendArgs(verifyCfg.AWSKMS.KeyID, verifyCfg.AWSKMS.Region)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "once the key is enabled, verify it with:\n  %s\n", verifyCmd)
				if be.Type == backend.TypeAWSKMS {
					fmt.Fprintln(cmd.OutOrStdout(), awsImportRecoveryReminder)
				} else {
					fmt.Fprintln(cmd.OutOrStdout(), "destroy the source key file only AFTER that command prints the identity above")
				}
				return nil
			}

			if be.Type == backend.TypeAWSKMS {
				// AWSImportKey verifies the pinned identity before returning ready.
				fmt.Fprintln(cmd.OutOrStdout(), "verified: backend public key matches the source file")
			} else if err := verifyImportedKey(verifyCfg, pub.Bytes()); err != nil {
				return err
			}

			printPubKeyTo(cmd.OutOrStdout(), pub.Address().String(), pub.Bytes())
			if be.Type == backend.TypeAWSKMS {
				fmt.Fprintln(cmd.OutOrStdout(), awsImportRecoveryReminder)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "reminder: securely destroy all copies of the source key file")
			}
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

const awsImportRecoveryReminder = "reminder: retain a protected recovery backup of the original imported material outside AWS, preferably in an HSM; AWS customers are responsible for its durability"
