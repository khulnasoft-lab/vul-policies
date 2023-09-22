package gke

import (
	"github.com/khulnasoft-lab/defsec/pkg/providers"
	"github.com/khulnasoft-lab/defsec/pkg/scan"
	"github.com/khulnasoft-lab/defsec/pkg/severity"
	"github.com/khulnasoft-lab/defsec/pkg/state"
	"github.com/khulnasoft-lab/vul-policies/internal/rules"
)

var CheckUseClusterLabels = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0051",
		Provider:    providers.GoogleProvider,
		Service:     "gke",
		ShortCode:   "use-cluster-labels",
		Summary:     "Clusters should be configured with Labels",
		Impact:      "Asset management can be limited/more difficult",
		Resolution:  "Set cluster resource labels",
		Explanation: `Labels make it easier to manage assets and differentiate between clusters and environments, allowing the mapping of computational resources to the wider organisational structure.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformUseClusterLabelsGoodExamples,
			BadExamples:         terraformUseClusterLabelsBadExamples,
			Links:               terraformUseClusterLabelsLinks,
			RemediationMarkdown: terraformUseClusterLabelsRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.Metadata.IsUnmanaged() {
				continue
			}
			if cluster.ResourceLabels.Len() == 0 {
				results.Add(
					"Cluster does not use GCE resource labels.",
					cluster.ResourceLabels,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
