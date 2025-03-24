// Copyright (c) Zefchain Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(target_arch = "wasm32", no_main)]

mod state;

use std::sync::{Arc, Mutex};

use async_graphql::{EmptySubscription, Object, Request, Response, Schema};
use crowd_funding::{ChainAddresses, ChainPledges, Operation, TokenPrice, TotalChainPledges, ALCHEMY_API_KEY};
use linera_sdk::{base::{ApplicationId, WithServiceAbi}, ensure, graphql::GraphQLMutationRoot, http, views::View, Service, ServiceRuntime};
use state::CrowdFundingState;

pub struct CrowdFundingService {
    state: Arc<CrowdFundingState>,
    runtime: Arc<Mutex<ServiceRuntime<Self>>>,
}

linera_sdk::service!(CrowdFundingService);

impl WithServiceAbi for CrowdFundingService {
    type Abi = crowd_funding::CrowdFundingAbi;
}

impl Service for CrowdFundingService {
    type Parameters = ApplicationId<fungible::FungibleTokenAbi>;

    async fn new(runtime: ServiceRuntime<Self>) -> Self {
        let state = CrowdFundingState::load(runtime.root_view_storage_context())
            .await
            .expect("Failed to load state");
        CrowdFundingService {
            state: Arc::new(state),
            runtime: Arc::new(Mutex::new(runtime)),
        }
    }

    async fn handle_query(&self, request: Request) -> Response {
        let schema = Schema::build(
            QueryRoot{
                state: self.state.clone(),
                runtime: self.runtime.clone(),
            },
            Operation::mutation_root(),
            EmptySubscription,
        )
        .finish();
        schema.execute(request).await
    }
}


struct QueryRoot {
    state: Arc<CrowdFundingState>,
    runtime: Arc<Mutex<ServiceRuntime<CrowdFundingService>>>,
}

#[Object]
impl QueryRoot {
    async fn get_chain_addresses(&self) -> Vec<ChainAddresses> {
        let mut chain_addresses = Vec::new();
        self.state.chain_addresses.for_each_index_value(|chain, address| {
            chain_addresses.push(ChainAddresses {
                chain: chain.clone(),
                address: address.to_string(),
            });
            Ok(())
        }).await.expect("Failed to get chain addresses");
        chain_addresses
    }

    async fn get_chain_pledges(&self) -> Vec<ChainPledges>{
        let mut chain_pledges = Vec::new();
        self.state.individual_pledges.for_each_index_value(|address, balance| {
            chain_pledges.push(ChainPledges {
                deposit_address: address.clone(),
                amount: balance.to_string(),
            });
            Ok(())
        }).await.expect("failed to get chain pledges");
        chain_pledges
    }

    async fn get_total_chain_pledges(&self) -> Vec<TotalChainPledges>{
        let mut chain_pledges = Vec::new();
        self.state.total_chain_pledges.for_each_index_value(|chain, amount| {
            chain_pledges.push(TotalChainPledges {
                chain: chain.clone(),
                amount: amount.to_string(),
            });
            Ok(())
        }).await.expect("failed to get chain pledges");
        chain_pledges
    }

    async fn fetch_token_price(&self,
                            token: String,
    ) -> async_graphql::Result<TokenPrice> {

        let price = self.calculate_rate(token.clone())?;

        Ok(TokenPrice {
            price
        })
    }

    async fn total_pledge_in_usd(&self) -> String {
        let mut total: f64 = 0.0;
        self.state.total_chain_pledges.for_each_index_value(|chain, amount| {
            // Handle the Result explicitly rather than using ?
            match self.calculate_rate(chain.clone()) {
                Ok(price) => {
                    let curr_amt_f64: f64 = amount.parse().unwrap();
                    total += price * curr_amt_f64;
                },
                Err(_) => {} // Skip this chain if price calculation fails
            }
            Ok(())
        }).await.expect("failed to get chain pledges");

        total.to_string()
    }

    // async fn deadline_in_hrf(&self) -> String {
    //     let deadline = self.state.instantiation_argument.get().as_ref().unwrap().deadline.micros() as i64;
    //     let datetime = NaiveDateTime::from_timestamp(deadline, 0);
    //     let datetime_utc: DateTime<Utc> = DateTime::from_utc(datetime, Utc);
    //     let datetime_utc: DateTime<Utc> = DateTime::from_utc(datetime, Utc);
    //
    //     // Format the DateTime<Utc> to a human-readable format
    //     let formatted_time = datetime_utc.format("%Y-%m-%d %H:%M:%S").to_string();
    //     formatted_time
    // }
}

impl QueryRoot {
    fn calculate_rate(
        &self,
        token: String,
    ) -> async_graphql::Result<f64> {
        let url = format!(
            "https://api.g.alchemy.com/prices/v1/tokens/by-symbol?symbols={}",
            token
        );

        let mut runtime = self.runtime
            .try_lock()
            .expect("Services only run in a single thread");

        // Make HTTP request using runtime
        let response = runtime.http_request(
            http::Request::get(&url)
                .with_header("Authorization", format!("Bearer {}", ALCHEMY_API_KEY).as_bytes())
                .with_header("accept", b"application/json")
        );

        ensure!(
            response.status == 200,
            async_graphql::Error::new(format!(
                "Failed to query Alchemy API. Status code: {}",
                response.status
            ))
        );

        // Parse response
        let data: serde_json::Value = serde_json::from_slice(&response.body)
            .map_err(|e| async_graphql::Error::new(format!("Failed to parse response: {}", e)))?;

        // Extract and validate prices
        let from_price = data["data"]
            .as_array()
            .and_then(|tokens| tokens.iter().find(|t| t["symbol"].as_str() == Some(&token)))
            .and_then(|token| token["prices"][0]["value"].as_str())
            .and_then(|price| price.parse::<f64>().ok())
            .ok_or_else(|| async_graphql::Error::new(format!("Price not found for {}", token)))?;

        Ok(from_price)
    }
}
