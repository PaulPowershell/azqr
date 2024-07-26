// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agw

import (
	"strings"

	"github.com/Azure/azqr/internal/scanners"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v5"
)

// GetRecommendations - Returns the rules for the ApplicationGatewayScanner
func (a *ApplicationGatewayScanner) GetRecommendations() map[string]scanners.AzqrRecommendation {
	return map[string]scanners.AzqrRecommendation{
		"agw-005": {
			RecommendationID: "agw-005",
			ResourceType:     "Microsoft.Network/applicationGateways",
			Category:         scanners.CategoryMonitoringAndAlerting,
			Recommendation:   "Application Gateway: Monitor and Log the configurations and traffic",
			Impact:           scanners.ImpactLow,
			Eval: func(target interface{}, scanContext *scanners.ScanContext) (bool, string) {
				service := target.(*armnetwork.ApplicationGateway)
				_, ok := scanContext.DiagnosticsSettings[strings.ToLower(*service.ID)]
				return !ok, ""
			},
			Url: "https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-diagnostics#diagnostic-logging",
		},
		"agw-103": {
			RecommendationID: "agw-103",
			ResourceType:     "Microsoft.Network/applicationGateways",
			Category:         scanners.CategoryHighAvailability,
			Recommendation:   "Application Gateway SLA",
			Impact:           scanners.ImpactHigh,
			Eval: func(target interface{}, scanContext *scanners.ScanContext) (bool, string) {
				return false, "99.95%"
			},
			Url: "https://www.azure.cn/en-us/support/sla/application-gateway/",
		},
		"agw-104": {
			RecommendationID: "agw-104",
			ResourceType:     "Microsoft.Network/applicationGateways",
			Category:         scanners.CategoryHighAvailability,
			Recommendation:   "Application Gateway SKU",
			Impact:           scanners.ImpactHigh,
			Eval: func(target interface{}, scanContext *scanners.ScanContext) (bool, string) {
				g := target.(*armnetwork.ApplicationGateway)
				return false, string(*g.Properties.SKU.Name)
			},
			Url: "https://learn.microsoft.com/en-us/azure/application-gateway/understanding-pricing",
		},
		"agw-105": {
			RecommendationID: "agw-105",
			ResourceType:     "Microsoft.Network/applicationGateways",
			Category:         scanners.CategoryGovernance,
			Recommendation:   "Application Gateway Name should comply with naming conventions",
			Impact:           scanners.ImpactLow,
			Eval: func(target interface{}, scanContext *scanners.ScanContext) (bool, string) {
				g := target.(*armnetwork.ApplicationGateway)
				caf := strings.HasPrefix(*g.Name, "agw")
				return !caf, ""
			},
			Url: "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-abbreviations",
		},
		"agw-106": {
			RecommendationID: "agw-106",
			ResourceType:     "Microsoft.Network/applicationGateways",
			Category:         scanners.CategoryGovernance,
			Recommendation:   "Application Gateway should have tags",
			Impact:           scanners.ImpactLow,
			Eval: func(target interface{}, scanContext *scanners.ScanContext) (bool, string) {
				c := target.(*armnetwork.ApplicationGateway)
				return len(c.Tags) == 0, ""
			},
			Url: "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources?tabs=json",
		},
	}
}
