package iam

import (
	"testing"

	defsecTypes "github.com/khulnasoft-lab/defsec/pkg/types"

	"github.com/khulnasoft-lab/defsec/pkg/state"

	"github.com/khulnasoft-lab/defsec/pkg/providers/aws/iam"
	"github.com/khulnasoft-lab/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRootMFAEnabled(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "root user without mfa",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Name:     defsecTypes.String("root", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "other user without mfa",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Name:     defsecTypes.String("other", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "root user with mfa",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Name:     defsecTypes.String("root", defsecTypes.NewTestMetadata()),
						MFADevices: []iam.MFADevice{
							{
								Metadata:  defsecTypes.NewTestMetadata(),
								IsVirtual: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							},
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
			testState.AWS.IAM = test.input
			results := checkRootMFAEnabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == checkRootMFAEnabled.GetRule().LongID() {
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