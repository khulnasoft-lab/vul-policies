package database

import (
	"testing"

	defsecTypes "github.com/khulnasoft-lab/defsec/pkg/types"

	"github.com/khulnasoft-lab/defsec/pkg/state"

	"github.com/khulnasoft-lab/defsec/pkg/providers/azure/database"
	"github.com/khulnasoft-lab/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckPostgresConfigurationLogConnections(t *testing.T) {
	tests := []struct {
		name     string
		input    database.Database
		expected bool
	}{
		{
			name: "PostgreSQL server connection logging disabled",
			input: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Config: database.PostgresSQLConfig{
							Metadata:       defsecTypes.NewTestMetadata(),
							LogConnections: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "PostgreSQL server connection logging enabled",
			input: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Config: database.PostgresSQLConfig{
							Metadata:       defsecTypes.NewTestMetadata(),
							LogConnections: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
			testState.Azure.Database = test.input
			results := CheckPostgresConfigurationLogConnections.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckPostgresConfigurationLogConnections.GetRule().LongID() {
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