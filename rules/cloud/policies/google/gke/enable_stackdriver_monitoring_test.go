package gke

import (
	"testing"

	defsecTypes "github.com/khulnasoft-lab/defsec/pkg/types"

	"github.com/khulnasoft-lab/defsec/pkg/state"

	"github.com/khulnasoft-lab/defsec/pkg/providers/google/gke"
	"github.com/khulnasoft-lab/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableStackdriverMonitoring(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster missing monitoring service provider",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:          defsecTypes.NewTestMetadata(),
						MonitoringService: defsecTypes.String("", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster with StackDriver monitoring configured",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:          defsecTypes.NewTestMetadata(),
						MonitoringService: defsecTypes.String("monitoring.googleapis.com/kubernetes", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.GKE = test.input
			results := CheckEnableStackdriverMonitoring.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableStackdriverMonitoring.GetRule().LongID() {
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