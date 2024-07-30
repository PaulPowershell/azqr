// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package logic

import (
	"github.com/Azure/azqr/internal/azqr"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/logic/armlogic"
)

// LogicAppScanner - Scanner for LogicApp
type LogicAppScanner struct {
	config *azqr.ScannerConfig
	client *armlogic.WorkflowsClient
}

// Init - Initializes the LogicAppScanner
func (c *LogicAppScanner) Init(config *azqr.ScannerConfig) error {
	c.config = config
	var err error
	c.client, err = armlogic.NewWorkflowsClient(config.SubscriptionID, config.Cred, config.ClientOptions)
	return err
}

// Scan - Scans all LogicApps in a Resource Group
func (c *LogicAppScanner) Scan(scanContext *azqr.ScanContext) ([]azqr.AzqrServiceResult, error) {
	azqr.LogSubscriptionScan(c.config.SubscriptionID, c.ResourceTypes()[0])

	vnets, err := c.list()
	if err != nil {
		return nil, err
	}
	engine := azqr.RecommendationEngine{}
	rules := c.GetRecommendations()
	results := []azqr.AzqrServiceResult{}

	for _, w := range vnets {
		rr := engine.EvaluateRecommendations(rules, w, scanContext)

		results = append(results, azqr.AzqrServiceResult{
			SubscriptionID:   c.config.SubscriptionID,
			SubscriptionName: c.config.SubscriptionName,
			ResourceGroup:    azqr.GetResourceGroupFromResourceID(*w.ID),
			ServiceName:      *w.Name,
			Type:             *w.Type,
			Location:         *w.Location,
			Recommendations:  rr,
		})
	}
	return results, nil
}

func (c *LogicAppScanner) list() ([]*armlogic.Workflow, error) {
	pager := c.client.NewListBySubscriptionPager(nil)

	logicApps := make([]*armlogic.Workflow, 0)
	for pager.More() {
		resp, err := pager.NextPage(c.config.Ctx)
		if err != nil {
			return nil, err
		}
		logicApps = append(logicApps, resp.Value...)
	}
	return logicApps, nil
}

func (a *LogicAppScanner) ResourceTypes() []string {
	return []string{"Microsoft.Logic/workflows"}
}
