// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package psql

import (
	"strings"

	"github.com/Azure/azqr/internal/scanners"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers"
)

// GetRecommendations - Returns the rules for the PostgreScanner
func (a *PostgreScanner) GetRecommendations() map[string]scanners.AzqrRecommendation {
	return map[string]scanners.AzqrRecommendation{
		"psql-001": {
			RecommendationID: "psql-001",
			ResourceType:     "Microsoft.DBforPostgreSQL/servers",
			Category:         scanners.CategoryMonitoringAndAlerting,
			Recommendation:   "PostgreSQL should have diagnostic settings enabled",
			Impact:           scanners.ImpactLow,
			Eval: func(target interface{}, scanContext *scanners.ScanContext) (bool, string) {
				service := target.(*armpostgresql.Server)
				_, ok := scanContext.DiagnosticsSettings[strings.ToLower(*service.ID)]
				return !ok, ""
			},
			Url: "https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-server-logs#resource-logs",
		},
		"psql-003": {
			RecommendationID: "psql-003",
			ResourceType:     "Microsoft.DBforPostgreSQL/servers",
			Category:         scanners.CategoryHighAvailability,
			Recommendation:   "PostgreSQL should have a SLA",
			Impact:           scanners.ImpactHigh,
			Eval: func(target interface{}, scanContext *scanners.ScanContext) (bool, string) {
				return false, "99.99%"
			},
			Url: "https://www.azure.cn/en-us/support/sla/postgresql/",
		},
		"psql-004": {
			RecommendationID: "psql-004",
			ResourceType:     "Microsoft.DBforPostgreSQL/servers",
			Category:         scanners.CategorySecurity,
			Recommendation:   "PostgreSQL should have private endpoints enabled",
			Impact:           scanners.ImpactHigh,
			Eval: func(target interface{}, scanContext *scanners.ScanContext) (bool, string) {
				i := target.(*armpostgresql.Server)
				pe := len(i.Properties.PrivateEndpointConnections) > 0
				return !pe, ""
			},
			Url: "https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-data-access-and-security-private-link",
		},
		"psql-005": {
			RecommendationID: "psql-005",
			ResourceType:     "Microsoft.DBforPostgreSQL/servers",
			Category:         scanners.CategoryHighAvailability,
			Recommendation:   "PostgreSQL SKU",
			Impact:           scanners.ImpactHigh,
			Eval: func(target interface{}, scanContext *scanners.ScanContext) (bool, string) {
				i := target.(*armpostgresql.Server)
				return false, *i.SKU.Name
			},
			Url: "https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-pricing-tiers",
		},
		"psql-006": {
			RecommendationID: "psql-006",
			ResourceType:     "Microsoft.DBforPostgreSQL/servers",
			Category:         scanners.CategoryGovernance,
			Recommendation:   "PostgreSQL Name should comply with naming conventions",
			Impact:           scanners.ImpactLow,
			Eval: func(target interface{}, scanContext *scanners.ScanContext) (bool, string) {
				c := target.(*armpostgresql.Server)
				caf := strings.HasPrefix(*c.Name, "psql")
				return !caf, ""
			},
			Url: "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-abbreviations",
		},
		"psql-007": {
			RecommendationID: "psql-007",
			ResourceType:     "Microsoft.DBforPostgreSQL/servers",
			Category:         scanners.CategoryGovernance,
			Recommendation:   "PostgreSQL should have tags",
			Impact:           scanners.ImpactLow,
			Eval: func(target interface{}, scanContext *scanners.ScanContext) (bool, string) {
				c := target.(*armpostgresql.Server)
				return len(c.Tags) == 0, ""
			},
			Url: "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources?tabs=json",
		},
		"psql-008": {
			RecommendationID: "psql-008",
			ResourceType:     "Microsoft.DBforPostgreSQL/servers",
			Category:         scanners.CategorySecurity,
			Recommendation:   "PostgreSQL should enforce SSL",
			Impact:           scanners.ImpactHigh,
			Eval: func(target interface{}, scanContext *scanners.ScanContext) (bool, string) {
				c := target.(*armpostgresql.Server)
				return c.Properties.SSLEnforcement == nil || *c.Properties.SSLEnforcement == armpostgresql.SSLEnforcementEnumDisabled, ""
			},
			Url: "https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-ssl-connection-security#enforcing-tls-connections",
		},
		"psql-009": {
			RecommendationID: "psql-009",
			ResourceType:     "Microsoft.DBforPostgreSQL/servers",
			Category:         scanners.CategorySecurity,
			Recommendation:   "PostgreSQL should enforce TLS >= 1.2",
			Impact:           scanners.ImpactLow,
			Eval: func(target interface{}, scanContext *scanners.ScanContext) (bool, string) {
				c := target.(*armpostgresql.Server)
				return c.Properties.MinimalTLSVersion == nil || *c.Properties.MinimalTLSVersion != armpostgresql.MinimalTLSVersionEnumTLS12, ""
			},
			Url: "https://learn.microsoft.com/en-us/azure/postgresql/single-server/how-to-tls-configurations",
		},
	}
}

// GetRecommendations - Returns the rules for the PostgreFlexibleScanner
func (a *PostgreFlexibleScanner) GetRecommendations() map[string]scanners.AzqrRecommendation {
	return map[string]scanners.AzqrRecommendation{
		"psqlf-001": {
			RecommendationID: "psqlf-001",
			ResourceType:     "Microsoft.DBforPostgreSQL/flexibleServers",
			Category:         scanners.CategoryMonitoringAndAlerting,
			Recommendation:   "PostgreSQL should have diagnostic settings enabled",
			Impact:           scanners.ImpactLow,
			Eval: func(target interface{}, scanContext *scanners.ScanContext) (bool, string) {
				service := target.(*armpostgresqlflexibleservers.Server)
				_, ok := scanContext.DiagnosticsSettings[strings.ToLower(*service.ID)]
				return !ok, ""
			},
			Url: "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/howto-configure-and-access-logs",
		},
		"psqlf-003": {
			RecommendationID: "psqlf-003",
			ResourceType:     "Microsoft.DBforPostgreSQL/flexibleServers",
			Category:         scanners.CategoryHighAvailability,
			Recommendation:   "PostgreSQL should have a SLA",
			Impact:           scanners.ImpactHigh,
			Eval: func(target interface{}, scanContext *scanners.ScanContext) (bool, string) {
				i := target.(*armpostgresqlflexibleservers.Server)
				sla := "99.9%"
				if i.Properties.HighAvailability != nil && *i.Properties.HighAvailability.Mode == armpostgresqlflexibleservers.HighAvailabilityModeZoneRedundant {
					if *i.Properties.HighAvailability.StandbyAvailabilityZone == *i.Properties.AvailabilityZone {
						sla = "99.95%"
					} else {
						sla = "99.99%"
					}
				}
				return false, sla
			},
			Url: "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-compare-single-server-flexible-server",
		},
		"psqlf-004": {
			RecommendationID: "psqlf-004",
			ResourceType:     "Microsoft.DBforPostgreSQL/flexibleServers",
			Category:         scanners.CategorySecurity,
			Recommendation:   "PostgreSQL should have private access enabled",
			Impact:           scanners.ImpactHigh,
			Eval: func(target interface{}, scanContext *scanners.ScanContext) (bool, string) {
				i := target.(*armpostgresqlflexibleservers.Server)
				pe := *i.Properties.Network.PublicNetworkAccess == armpostgresqlflexibleservers.ServerPublicNetworkAccessStateDisabled
				return !pe, ""
			},
			Url: "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-networking#private-access-vnet-integration",
		},
		"psqlf-005": {
			RecommendationID: "psqlf-005",
			ResourceType:     "Microsoft.DBforPostgreSQL/flexibleServers",
			Category:         scanners.CategoryHighAvailability,
			Recommendation:   "PostgreSQL SKU",
			Impact:           scanners.ImpactHigh,
			Eval: func(target interface{}, scanContext *scanners.ScanContext) (bool, string) {
				i := target.(*armpostgresqlflexibleservers.Server)
				return false, *i.SKU.Name
			},
			Url: "https://azure.microsoft.com/en-gb/pricing/details/postgresql/flexible-server/",
		},
		"psqlf-006": {
			RecommendationID: "psqlf-006",
			ResourceType:     "Microsoft.DBforPostgreSQL/flexibleServers",
			Category:         scanners.CategoryGovernance,
			Recommendation:   "PostgreSQL Name should comply with naming conventions",
			Impact:           scanners.ImpactLow,
			Eval: func(target interface{}, scanContext *scanners.ScanContext) (bool, string) {
				c := target.(*armpostgresqlflexibleservers.Server)
				caf := strings.HasPrefix(*c.Name, "psql")
				return !caf, ""
			},
			Url: "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-abbreviations",
		},
		"psqlf-007": {
			RecommendationID: "psqlf-007",
			ResourceType:     "Microsoft.DBforPostgreSQL/flexibleServers",
			Category:         scanners.CategoryGovernance,
			Recommendation:   "PostgreSQL should have tags",
			Impact:           scanners.ImpactLow,
			Eval: func(target interface{}, scanContext *scanners.ScanContext) (bool, string) {
				c := target.(*armpostgresqlflexibleservers.Server)
				return len(c.Tags) == 0, ""
			},
			Url: "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources?tabs=json",
		},
	}
}
