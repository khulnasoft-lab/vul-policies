package sam

import (
	"testing"

	defsecTypes "github.com/khulnasoft-lab/defsec/pkg/types"

	"github.com/khulnasoft-lab/defsec/pkg/state"

	"github.com/khulnasoft-lab/defsec/pkg/providers/aws/sam"
	"github.com/khulnasoft-lab/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableStateMachineTracing(t *testing.T) {
	tests := []struct {
		name     string
		input    sam.SAM
		expected bool
	}{
		{
			name: "State machine tracing disabled",
			input: sam.SAM{
				StateMachines: []sam.StateMachine{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Tracing: sam.TracingConfiguration{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "State machine tracing enabled",
			input: sam.SAM{
				StateMachines: []sam.StateMachine{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Tracing: sam.TracingConfiguration{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
			testState.AWS.SAM = test.input
			results := CheckEnableStateMachineTracing.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableStateMachineTracing.GetRule().LongID() {
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
