package rules

import (
	"github.com/khulnasoft-lab/defsec/pkg/framework"
	"github.com/khulnasoft-lab/defsec/pkg/scan"
	"github.com/khulnasoft-lab/vul-policies/internal/rules"
	"github.com/khulnasoft-lab/vul-policies/pkg/types"
)

func Register(rule scan.Rule, f scan.CheckFunc) types.RegisteredRule {
	return rules.Register(rule, f)
}

func Deregister(rule types.RegisteredRule) {
	rules.Deregister(rule)
}

func GetRegistered(fw ...framework.Framework) []types.RegisteredRule {
	return rules.GetFrameworkRules(fw...)
}

func GetSpecRules(spec string) []types.RegisteredRule {
	return rules.GetSpecRules(spec)
}
