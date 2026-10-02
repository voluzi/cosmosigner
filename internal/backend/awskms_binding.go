package backend

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/voluzi/cosmosigner/internal/clusterid"
)

const awsClusterIDTag = "cosmosigner-cluster-id"
const awsConsistencyAttempts = 8
const awsConsistencyDelay = 250 * time.Millisecond

func (a *AWSKMS) bindingResource() string {
	return fmt.Sprintf("AWS KMS key %s tag %s", a.keyARN, awsClusterIDTag)
}

func (a *AWSKMS) ClusterBinding(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	var marker *string
	seen := make(map[string]bool)
	var id string
	found := false
	for {
		resp, err := a.client.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: aws.String(a.keyARN), Marker: marker})
		if err != nil {
			return "", fmt.Errorf("%w: list AWS key %s tags: %w", ErrBindingUnreadable, a.keyARN, err)
		}
		if resp == nil {
			return "", fmt.Errorf("%w: empty AWS tags response", ErrBindingUnreadable)
		}
		for _, tag := range resp.Tags {
			if aws.ToString(tag.TagKey) != awsClusterIDTag {
				continue
			}
			if found {
				return "", fmt.Errorf("%w: duplicate AWS cluster tag", ErrBindingCorrupt)
			}
			found = true
			id = aws.ToString(tag.TagValue)
			if err := clusterid.Validate(id); err != nil {
				return "", fmt.Errorf("%w: AWS key %s cluster tag: %v", ErrBindingCorrupt, a.keyARN, err)
			}
		}
		if !resp.Truncated {
			break
		}
		next := aws.ToString(resp.NextMarker)
		if next == "" || seen[next] {
			return "", fmt.Errorf("%w: missing or repeated AWS tag pagination marker", ErrBindingUnreadable)
		}
		seen[next] = true
		marker = resp.NextMarker
	}
	if !found {
		return "", fmt.Errorf("%w: AWS key %s has no %s tag", ErrBindingUnclaimed, a.keyARN, awsClusterIDTag)
	}
	return id, nil
}

// ClaimCluster requires external serialization: TagResource has no CAS and reads can be stale.
func (a *AWSKMS) ClaimCluster(ctx context.Context, id string) error {
	if err := clusterid.Validate(id); err != nil {
		return fmt.Errorf("invalid cluster ID: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	actual, err := a.ClusterBinding(ctx)
	if err == nil {
		return requireClaimOwner(a.keyARN, id, actual)
	}
	if !errors.Is(err, ErrBindingUnclaimed) {
		return err
	}
	_, err = a.client.TagResource(ctx, &kms.TagResourceInput{KeyId: aws.String(a.keyARN), Tags: []types.Tag{{TagKey: aws.String(awsClusterIDTag), TagValue: aws.String(id)}}})
	if err != nil {
		return fmt.Errorf("tag AWS key %s cluster claim: %w", a.keyARN, err)
	}
	for attempt := 0; attempt < awsConsistencyAttempts; attempt++ {
		actual, err = a.ClusterBinding(ctx)
		if err == nil {
			return requireClaimOwner(a.keyARN, id, actual)
		}
		if !errors.Is(err, ErrBindingUnclaimed) {
			return fmt.Errorf("reread AWS key after claim: %w", err)
		}
		if attempt+1 < awsConsistencyAttempts {
			if err := waitAWSConsistency(ctx); err != nil {
				return fmt.Errorf("wait for AWS cluster claim: %w", err)
			}
		}
	}
	return fmt.Errorf("AWS cluster claim not visible after %d reads; retry with the same cluster ID: %w", awsConsistencyAttempts, err)
}

func waitAWSConsistency(ctx context.Context) error {
	timer := time.NewTimer(awsConsistencyDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
