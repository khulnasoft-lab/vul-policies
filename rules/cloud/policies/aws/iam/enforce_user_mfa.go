package iam

import (
	"github.com/khulnasoft-lab/defsec/pkg/framework"

	"github.com/khulnasoft-lab/defsec/pkg/severity"

	"github.com/khulnasoft-lab/defsec/pkg/state"

	"github.com/khulnasoft-lab/defsec/pkg/scan"

	"github.com/khulnasoft-lab/vul-policies/internal/rules"

	"github.com/khulnasoft-lab/defsec/pkg/providers"
)

var CheckEnforceUserMFA = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0145",
		Provider:  providers.AWSProvider,
		Service:   "iam",
		ShortCode: "enforce-user-mfa",
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_2: {"1.2"},
			framework.CIS_AWS_1_4: {"1.4"},
		},
		Summary:    "IAM Users should have MFA enforcement activated.",
		Impact:     "User accounts are more vulnerable to compromise without multi factor authentication activated",
		Resolution: "Enable MFA for the user account",
		Explanation: `
IAM user accounts should be protected with multi factor authentication to add safe guards to password compromise.
			`,
		Links: []string{
			"https://console.aws.amazon.com/iam/",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {

		for _, user := range s.AWS.IAM.Users {
			if user.HasLoggedIn() && len(user.MFADevices) == 0 {
				results.Add("User account does not have MFA", &user)
			} else {
				results.AddPassed(&user)
			}
		}

		return
	},
)
