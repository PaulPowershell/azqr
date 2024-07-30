// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package afd

import (
	"github.com/Azure/azqr/internal/azqr"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn"
)

// FrontDoorScanner - Scanner for Front Door
type FrontDoorScanner struct {
	config *azqr.ScannerConfig
	client *armcdn.ProfilesClient
}

// Init - Initializes the FrontDoor Scanner
func (a *FrontDoorScanner) Init(config *azqr.ScannerConfig) error {
	a.config = config
	var err error
	a.client, err = armcdn.NewProfilesClient(config.SubscriptionID, a.config.Cred, a.config.ClientOptions)
	return err
}

// Scan - Scans all Front Doors in a Resource Group
func (a *FrontDoorScanner) Scan(scanContext *azqr.ScanContext) ([]azqr.AzqrServiceResult, error) {
	azqr.LogSubscriptionScan(a.config.SubscriptionID, a.ResourceTypes()[0])

	gateways, err := a.list()
	if err != nil {
		return nil, err
	}
	engine := azqr.RecommendationEngine{}
	rules := a.GetRecommendations()
	results := []azqr.AzqrServiceResult{}

	for _, g := range gateways {
		rr := engine.EvaluateRecommendations(rules, g, scanContext)

		results = append(results, azqr.AzqrServiceResult{
			SubscriptionID:   a.config.SubscriptionID,
			SubscriptionName: a.config.SubscriptionName,
			ResourceGroup:    azqr.GetResourceGroupFromResourceID(*g.ID),
			Location:         *g.Location,
			Type:             *g.Type,
			ServiceName:      *g.Name,
			Recommendations:  rr,
		})
	}
	return results, nil
}

func (a *FrontDoorScanner) list() ([]*armcdn.Profile, error) {
	pager := a.client.NewListPager(nil)

	services := make([]*armcdn.Profile, 0)
	for pager.More() {
		resp, err := pager.NextPage(a.config.Ctx)
		if err != nil {
			return nil, err
		}
		services = append(services, resp.Value...)
	}
	return services, nil
}

func (a *FrontDoorScanner) ResourceTypes() []string {
	return []string{"Microsoft.Cdn/profiles"}
}
