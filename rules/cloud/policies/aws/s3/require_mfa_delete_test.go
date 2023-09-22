package s3

import (
	"testing"

	defsecTypes "github.com/khulnasoft-lab/defsec/pkg/types"

	"github.com/khulnasoft-lab/defsec/pkg/state"

	"github.com/khulnasoft-lab/defsec/pkg/providers/aws/s3"
	"github.com/khulnasoft-lab/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRequireMFADelete(t *testing.T) {
	tests := []struct {
		name     string
		input    s3.S3
		expected bool
	}{
		{
			name: "RequireMFADelete is not set",
			input: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Versioning: s3.Versioning{
							Metadata:  defsecTypes.NewTestMetadata(),
							Enabled:   defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							MFADelete: defsecTypes.BoolUnresolvable(defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "RequireMFADelete is false",
			input: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Versioning: s3.Versioning{
							Metadata:  defsecTypes.NewTestMetadata(),
							Enabled:   defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							MFADelete: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "RequireMFADelete is true",
			input: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Versioning: s3.Versioning{
							Metadata:  defsecTypes.NewTestMetadata(),
							Enabled:   defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							MFADelete: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.S3 = test.input
			results := CheckRequireMFADelete.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRequireMFADelete.GetRule().LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
