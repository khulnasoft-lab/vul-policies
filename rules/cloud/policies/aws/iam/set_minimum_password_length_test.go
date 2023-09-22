package iam

import (
	"testing"

	defsecTypes "github.com/khulnasoft-lab/defsec/pkg/types"

	"github.com/khulnasoft-lab/defsec/pkg/state"

	"github.com/khulnasoft-lab/defsec/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckSetMinimumPasswordLength(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Minimum password length set to 8",
			input: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:      defsecTypes.NewTestMetadata(),
					MinimumLength: defsecTypes.Int(8, defsecTypes.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "Minimum password length set to 15",
			input: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:      defsecTypes.NewTestMetadata(),
					MinimumLength: defsecTypes.Int(15, defsecTypes.NewTestMetadata()),
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := CheckSetMinimumPasswordLength.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckSetMinimumPasswordLength.GetRule().LongID() {
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
