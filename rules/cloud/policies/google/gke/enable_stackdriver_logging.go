package gke

import (
	"github.com/khulnasoft-lab/defsec/pkg/providers"
	"github.com/khulnasoft-lab/defsec/pkg/scan"
	"github.com/khulnasoft-lab/defsec/pkg/severity"
	"github.com/khulnasoft-lab/defsec/pkg/state"
	"github.com/khulnasoft-lab/vul-policies/internal/rules"
)

var CheckEnableStackdriverLogging = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0060",
		Provider:    providers.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-stackdriver-logging",
		Summary:     "Stackdriver Logging should be enabled",
		Impact:      "Visibility will be reduced",
		Resolution:  "Enable StackDriver logging",
		Explanation: `StackDriver logging provides a useful interface to all of stdout/stderr for each container and should be enabled for moitoring, debugging, etc.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableStackdriverLoggingGoodExamples,
			BadExamples:         terraformEnableStackdriverLoggingBadExamples,
			Links:               terraformEnableStackdriverLoggingLinks,
			RemediationMarkdown: terraformEnableStackdriverLoggingRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.Metadata.IsUnmanaged() {
				continue
			}
			if cluster.LoggingService.NotEqualTo("logging.googleapis.com/kubernetes") {
				results.Add(
					"Cluster does not use the logging.googleapis.com/kubernetes StackDriver logging service.",
					cluster.LoggingService,
				)
			} else {
				results.AddPassed(&cluster)
			}

		}
		return
	},
)
