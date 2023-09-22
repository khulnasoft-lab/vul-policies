package compute

import (
	"testing"

	defsecTypes "github.com/khulnasoft-lab/defsec/pkg/types"

	"github.com/khulnasoft-lab/defsec/pkg/state"

	"github.com/khulnasoft-lab/defsec/pkg/providers/google/compute"
	"github.com/khulnasoft-lab/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoDefaultServiceAccount(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Instance service account not specified",
			input: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						ServiceAccount: compute.ServiceAccount{
							Metadata:  defsecTypes.NewTestMetadata(),
							Email:     defsecTypes.String("", defsecTypes.NewTestMetadata()),
							IsDefault: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance service account using the default email",
			input: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						ServiceAccount: compute.ServiceAccount{
							Metadata:  defsecTypes.NewTestMetadata(),
							Email:     defsecTypes.String("1234567890-compute@developer.gserviceaccount.com", defsecTypes.NewTestMetadata()),
							IsDefault: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance service account with email provided",
			input: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						ServiceAccount: compute.ServiceAccount{
							Metadata:  defsecTypes.NewTestMetadata(),
							Email:     defsecTypes.String("proper@email.com", defsecTypes.NewTestMetadata()),
							IsDefault: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
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
			testState.Google.Compute = test.input
			results := CheckNoDefaultServiceAccount.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoDefaultServiceAccount.GetRule().LongID() {
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