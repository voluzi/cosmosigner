package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/voluzi/cosmosigner/internal/clusterid"
)

type vaultBindingRecord struct {
	Version      int
	ClusterID    string
	TransitMount string
	KeyName      string
}

// ValidateVaultAddressing rejects Transit or binding paths whose spelling could select a
// different Vault resource than the durable claim describes.
func ValidateVaultAddressing(transitMount, bindingMount, keyName string) error {
	if _, err := normalizeVaultMount(transitMount, "transit mount"); err != nil {
		return err
	}
	if _, err := normalizeVaultMount(bindingMount, "binding mount"); err != nil {
		return err
	}
	_, err := normalizeVaultKeyName(keyName)
	return err
}

func normalizeVaultMount(value, field string) (string, error) {
	value = strings.Trim(value, "/")
	if value == "" {
		return "", fmt.Errorf("vault %s is required", field)
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." || strings.TrimSpace(component) != component {
			return "", fmt.Errorf("vault %s %q contains an ambiguous path component", field, value)
		}
	}
	return value, nil
}

func normalizeVaultKeyName(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("vault backend requires a key name")
	}
	if strings.Contains(value, "/") || value == "." || value == ".." || strings.TrimSpace(value) != value {
		return "", fmt.Errorf("vault key name %q contains an ambiguous path component", value)
	}
	return value, nil
}

func vaultBindingAddress(transitMount, keyName string) string {
	digest := sha256.Sum256([]byte(transitMount + "\x00" + keyName))
	return hex.EncodeToString(digest[:])
}

func (v *Vault) bindingDataPath() string {
	return fmt.Sprintf("%s/data/cluster-bindings/%s", v.bindingMount, vaultBindingAddress(v.mount, v.keyName))
}

func (v *Vault) bindingMetadataPath() string {
	return fmt.Sprintf("%s/metadata/cluster-bindings/%s", v.bindingMount, vaultBindingAddress(v.mount, v.keyName))
}

func (v *Vault) bindingResource() string {
	return fmt.Sprintf("vault://%s/cluster-bindings/%s for transit key %s/%s", v.bindingMount, vaultBindingAddress(v.mount, v.keyName), v.mount, v.keyName)
}

func (v *Vault) ClusterBinding(ctx context.Context) (string, error) {
	secret, err := v.client.Logical().ReadWithContext(ctx, v.bindingDataPath())
	if err != nil {
		return "", fmt.Errorf("%w: read %s: %v", ErrBindingUnreadable, v.bindingResource(), err)
	}
	if secret == nil || secret.Data == nil {
		metadata, metadataErr := v.client.Logical().ReadWithContext(ctx, v.bindingMetadataPath())
		if metadataErr != nil {
			return "", fmt.Errorf("%w: inspect %s metadata: %v", ErrBindingUnreadable, v.bindingResource(), metadataErr)
		}
		if metadata != nil && metadata.Data != nil {
			return "", fmt.Errorf("%w: %s has metadata but no readable current value", ErrBindingCorrupt, v.bindingResource())
		}
		return "", fmt.Errorf("%w: %s", ErrBindingUnclaimed, v.bindingResource())
	}

	metadata, ok := secret.Data["metadata"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("%w: %s response has no metadata", ErrBindingCorrupt, v.bindingResource())
	}
	destroyed, ok := metadata["destroyed"].(bool)
	if !ok {
		return "", fmt.Errorf("%w: %s response metadata has invalid destroyed field", ErrBindingCorrupt, v.bindingResource())
	}
	if destroyed {
		return "", fmt.Errorf("%w: %s current version is destroyed", ErrBindingCorrupt, v.bindingResource())
	}
	deletionTime, ok := metadata["deletion_time"].(string)
	if !ok {
		return "", fmt.Errorf("%w: %s response metadata has invalid deletion_time field", ErrBindingCorrupt, v.bindingResource())
	}
	if deletionTime != "" {
		return "", fmt.Errorf("%w: %s current version is deleted", ErrBindingCorrupt, v.bindingResource())
	}
	data, ok := secret.Data["data"].(map[string]any)
	if !ok || data == nil {
		return "", fmt.Errorf("%w: %s has no current value", ErrBindingCorrupt, v.bindingResource())
	}
	record, err := v.parseBindingRecord(data)
	if err != nil {
		return "", err
	}
	return record.ClusterID, nil
}

func (v *Vault) parseBindingRecord(data map[string]any) (vaultBindingRecord, error) {
	resource := v.bindingResource()
	if len(data) != 4 {
		return vaultBindingRecord{}, fmt.Errorf("%w: %s record has unexpected fields", ErrBindingCorrupt, resource)
	}
	version, err := toInt(data["version"])
	if err != nil || version != 1 {
		return vaultBindingRecord{}, fmt.Errorf("%w: %s record has invalid version", ErrBindingCorrupt, resource)
	}
	id, ok := data["cluster_id"].(string)
	if !ok || clusterid.Validate(id) != nil {
		return vaultBindingRecord{}, fmt.Errorf("%w: %s record has invalid cluster ID", ErrBindingCorrupt, resource)
	}
	mount, mountOK := data["transit_mount"].(string)
	keyName, keyOK := data["key_name"].(string)
	if !mountOK || !keyOK || mount != v.mount || keyName != v.keyName {
		return vaultBindingRecord{}, fmt.Errorf("%w: %s record addresses a different transit key", ErrBindingCorrupt, resource)
	}
	return vaultBindingRecord{Version: version, ClusterID: id, TransitMount: mount, KeyName: keyName}, nil
}

func (v *Vault) ClaimCluster(ctx context.Context, id string) error {
	if err := clusterid.Validate(id); err != nil {
		return fmt.Errorf("invalid cluster ID: %w", err)
	}
	owner, err := v.ClusterBinding(ctx)
	switch {
	case err == nil:
		return requireClaimOwner(v.bindingResource(), id, owner)
	case !errors.Is(err, ErrBindingUnclaimed):
		return err
	}

	payload := map[string]any{
		"data": map[string]any{
			"version": 1, "cluster_id": id, "transit_mount": v.mount, "key_name": v.keyName,
		},
		"options": map[string]any{"cas": 0},
	}
	_, writeErr := v.client.Logical().WriteWithContext(ctx, v.bindingDataPath(), payload)
	owner, readErr := v.ClusterBinding(ctx)
	if readErr == nil {
		return requireClaimOwner(v.bindingResource(), id, owner)
	}
	if writeErr != nil {
		return fmt.Errorf("claim %s with create-only CAS: %v; durable reread: %w", v.bindingResource(), writeErr, readErr)
	}
	return fmt.Errorf("claim %s was not durable: %w", v.bindingResource(), readErr)
}
