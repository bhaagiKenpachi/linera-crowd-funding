package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

var (
	chainToToken = map[string]string{
		"ETH": "ethereum",
		"SOL": "solana",
	}
	// RPC endpoints
	EthereumRPC string
	SolanaRPC   string
	CrowdSolver string // Variable to hold the crowd solver URL
	// HTTP client for making requests
	httpClient = &http.Client{}
)

func init() {
	initFlags()
}

func initFlags() {
	// Define command line flags
	solanaRPCURL := flag.String("solana-url", getEnvOrDefault("SOLANA_RPC", "http://localhost:8899"), "Solana RPC endpoint")
	ethereumRPCURL := flag.String("ethereum-url", getEnvOrDefault("ETHEREUM_RPC", "http://localhost:8545"), "Ethereum RPC endpoint")
	crowdSolverURL := flag.String("crowd-solver", getEnvOrDefault("CROWD_SOLVER_URL", "http://localhost:8080"), "Crowd solver URL")

	// Parse flags
	flag.Parse()

	// Initialize RPC endpoints and crowd solver URL
	SolanaRPC = *solanaRPCURL
	EthereumRPC = *ethereumRPCURL
	CrowdSolver = *crowdSolverURL

	// Log configuration
	log.Printf("Initialized with:")
	log.Printf("  Solana RPC: %s", SolanaRPC)
	log.Printf("  Ethereum RPC: %s", EthereumRPC)
	log.Printf("  Crowd Solver URL: %s", CrowdSolver)
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Add CORS middleware
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		origin := r.Header.Get("Origin")
		allowedOrigins := map[string]bool{
			"http://localhost:3000": true,
		}

		if allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Expose-Headers", "Set-Cookie")
		}

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// LoggingMiddleware adds request logging to handlers
func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Started %s %s", r.Method, r.URL.Path)

		// Create a custom response writer to capture status code
		rw := &responseWriter{w, http.StatusOK}
		next(rw, r)

		log.Printf("Completed %s %s with status %d in %v",
			r.Method, r.URL.Path, rw.status, time.Since(start))
	}
}

// Custom response writer to capture status code
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// ChainAddress represents a chain and address pair
type ChainAddress struct {
	Chain   string `json:"chain"`
	Address string `json:"address"`
}

// Global variable to store chain addresses
var chainAddresses []ChainAddress

// ChainAddressBalance represents a chain address with its balance
type ChainAddressBalance struct {
	Address string `json:"address"`
	Balance string `json:"balance"`
}

// GraphQLResponse represents the response structure from the GraphQL query
type GraphQLResponse struct {
	Data struct {
		GetChainAddresses []ChainAddressBalance `json:"getChainAddresses"`
	} `json:"data"`
}

// ChainPledge represents a pledge with deposit address and amount
type ChainPledge struct {
	DepositAddress string `json:"depositAddress"`
	Amount         string `json:"amount"`
}

// ChainPledgesResponse represents the response structure from the GraphQL query
type ChainPledgesResponse struct {
	Data struct {
		GetChainPledges []ChainPledge `json:"getChainPledges"`
	} `json:"data"`
}

// ChainTotalPledge represents total pledges for a chain
type ChainTotalPledge struct {
	Chain  string `json:"chain"`
	Amount string `json:"amount"`
}

// TotalPledgesResponse represents the response structure from the GraphQL query
type TotalPledgesResponse struct {
	Data struct {
		GetTotalChainPledges []ChainTotalPledge `json:"getTotalChainPledges"`
	} `json:"data"`
}

// CollectResponse represents the response structure from the GraphQL mutation
type CollectResponse struct {
	Data struct {
		Collect bool `json:"collect"`
	} `json:"data"`
}

func handleAddChainAddress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request body as an array of ChainAddress
	var chainAddressArray []ChainAddress
	if err := json.NewDecoder(r.Body).Decode(&chainAddressArray); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if len(chainAddressArray) == 0 {
		http.Error(w, "Request body must contain at least one chain address", http.StatusBadRequest)
		return
	}

	successfulAdditions := []ChainAddress{}
	errors := []string{}

	// Process each chain address
	for _, chainAddr := range chainAddressArray {
		// Validate chain
		if chainAddr.Chain == "" {
			errors = append(errors, "Chain is required")
			continue
		}

		// Validate address
		if chainAddr.Address == "" {
			errors = append(errors, fmt.Sprintf("Address is required for chain %s", chainAddr.Chain))
			continue
		}

		// Validate chain is supported
		if _, ok := chainToToken[chainAddr.Chain]; !ok {
			errors = append(errors, fmt.Sprintf("Unsupported chain: %s", chainAddr.Chain))
			continue
		}

		// Build GraphQL mutation
		mutation := fmt.Sprintf(`{"query":"mutation{addChain(chainName:\"%s\",address:\"%s\")}"}`, chainAddr.Chain, chainAddr.Address)

		// Create request
		req, err := http.NewRequest("POST", CrowdSolver, bytes.NewBuffer([]byte(mutation)))
		if err != nil {
			errors = append(errors, fmt.Sprintf("Error creating request for %s: %s", chainAddr.Chain, err.Error()))
			continue
		}

		req.Header.Set("Content-Type", "application/json")

		// Send request
		resp, err := httpClient.Do(req)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Error sending request for %s: %s", chainAddr.Chain, err.Error()))
			continue
		}
		resp.Body.Close()

		// Add to the array
		chainAddresses = append(chainAddresses, chainAddr)
		successfulAdditions = append(successfulAdditions, chainAddr)
	}

	// Prepare response
	response := map[string]interface{}{
		"status":      "success",
		"message":     fmt.Sprintf("Processed %d chain addresses", len(chainAddressArray)),
		"successful":  successfulAdditions,
		"errors":      errors,
		"total_added": len(successfulAdditions),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleGetChainAddresses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Build GraphQL query
	query := `{"query":"query chainAddresses { getChainAddresses { address balance } }"}`

	// Create request
	req, err := http.NewRequest("POST", CrowdSolver, bytes.NewBuffer([]byte(query)))
	if err != nil {
		http.Error(w, "Error creating request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := httpClient.Do(req)
	if err != nil {
		http.Error(w, "Error sending request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Parse response
	var graphqlResp GraphQLResponse
	if err := json.NewDecoder(resp.Body).Decode(&graphqlResp); err != nil {
		http.Error(w, "Error parsing response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Prepare response
	response := map[string]interface{}{
		"status":  "success",
		"message": "Chain addresses retrieved successfully",
		"data":    graphqlResp.Data.GetChainAddresses,
		"count":   len(graphqlResp.Data.GetChainAddresses),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleGetChainPledges(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Build GraphQL query
	query := `{"query":"query chainPledges { getChainPledges { depositAddress amount } }"}`

	// Create request
	req, err := http.NewRequest("POST", CrowdSolver, bytes.NewBuffer([]byte(query)))
	if err != nil {
		http.Error(w, "Error creating request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := httpClient.Do(req)
	if err != nil {
		http.Error(w, "Error sending request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Parse response
	var graphqlResp ChainPledgesResponse
	if err := json.NewDecoder(resp.Body).Decode(&graphqlResp); err != nil {
		http.Error(w, "Error parsing response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Prepare response
	response := map[string]interface{}{
		"status":  "success",
		"message": "Chain pledges retrieved successfully",
		"data":    graphqlResp.Data.GetChainPledges,
		"count":   len(graphqlResp.Data.GetChainPledges),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleTotalPledges(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Build GraphQL query
	query := `{"query":"query totalPledges { getTotalChainPledges { chain amount } }"}`

	// Create request
	req, err := http.NewRequest("POST", CrowdSolver, bytes.NewBuffer([]byte(query)))
	if err != nil {
		http.Error(w, "Error creating request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := httpClient.Do(req)
	if err != nil {
		http.Error(w, "Error sending request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Parse response
	var graphqlResp TotalPledgesResponse
	if err := json.NewDecoder(resp.Body).Decode(&graphqlResp); err != nil {
		http.Error(w, "Error parsing response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for _, pledge := range graphqlResp.Data.GetTotalChainPledges {
		amount := 0.0
		fmt.Sscanf(pledge.Amount, "%f", &amount)
	}

	// Prepare response
	response := map[string]interface{}{
		"status":  "success",
		"message": "Total chain pledges retrieved successfully",
		"data":    graphqlResp.Data.GetTotalChainPledges,
		"count":   len(graphqlResp.Data.GetTotalChainPledges),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleCollect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Build GraphQL mutation
	mutation := `{"query":"mutation collect { collect }"}`

	// Create request
	req, err := http.NewRequest("POST", CrowdSolver, bytes.NewBuffer([]byte(mutation)))
	if err != nil {
		http.Error(w, "Error creating request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := httpClient.Do(req)
	if err != nil {
		http.Error(w, "Error sending request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Parse response
	var graphqlResp CollectResponse
	if err := json.NewDecoder(resp.Body).Decode(&graphqlResp); err != nil {
		http.Error(w, "Error parsing response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Prepare response
	response := map[string]interface{}{
		"status":    "success",
		"message":   "Collection process completed",
		"collected": graphqlResp.Data.Collect,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	// Define routes with CORS and logging middleware
	http.HandleFunc("/post_tx_hash", corsMiddleware(loggingMiddleware(handlePostTxHash)))
	http.HandleFunc("/add_chain_address", corsMiddleware(loggingMiddleware(handleAddChainAddress)))
	http.HandleFunc("/chain_addresses", corsMiddleware(loggingMiddleware(handleGetChainAddresses)))
	http.HandleFunc("/chain_pledges", corsMiddleware(loggingMiddleware(handleGetChainPledges)))
	http.HandleFunc("/total_pledges", corsMiddleware(loggingMiddleware(handleTotalPledges)))
	http.HandleFunc("/collect", corsMiddleware(loggingMiddleware(handleCollect)))

	// Start server
	port := getEnvOrDefault("PORT", "3003")
	log.Printf("Server starting on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}

// makeRPCRequest makes a JSON-RPC request to the specified endpoint
func makeRPCRequest(endpoint string, requestBody interface{}) (interface{}, error) {
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// GetSolanaTransaction fetches transaction details from Solana
func GetSolanaTransaction(txHash string) (interface{}, error) {
	// Prepare the JSON-RPC request
	requestBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "getTransaction",
		"params": []interface{}{
			txHash,
			map[string]interface{}{
				"encoding":                       "json",
				"maxSupportedTransactionVersion": 0,
			},
		},
	}

	// Make the request with retries
	var response interface{}
	var err error
	for i := 0; i < 20; i++ {
		response, err = makeRPCRequest(SolanaRPC, requestBody)
		if responseMap, ok := response.(map[string]interface{}); ok {
			if responseMap["result"] == nil {
				time.Sleep(5 * time.Second)
				continue // Retry if result is nil
			}
		}

		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get Solana transaction after 20 retries: %w", err)
	}

	return response, nil
}

// GetEthereumTransaction fetches transaction details from Ethereum
func GetEthereumTransaction(txHash string) (interface{}, error) {
	client, err := ethclient.Dial(EthereumRPC)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum node: %w", err)
	}
	defer client.Close()

	hash := common.HexToHash(txHash)
	tx, isPending, err := client.TransactionByHash(context.Background(), hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get Ethereum transaction: %w", err)
	}

	// Convert transaction to map for consistent response format
	return map[string]interface{}{
		"hash":      tx.Hash().Hex(),
		"value":     tx.Value().String(),
		"gas":       tx.Gas(),
		"gasPrice":  tx.GasPrice().String(),
		"nonce":     tx.Nonce(),
		"isPending": isPending,
	}, nil
}

// Helper function to get token for chain
func getTokenForChain(chain string) (string, error) {
	token, ok := chainToToken[chain]
	if !ok {
		return "", fmt.Errorf("unsupported chain: %s", chain)
	}
	return token, nil
}

// Helper function to extract amount from transaction
func extractAmountFromTx(tx interface{}) (uint64, error) {
	switch v := tx.(type) {
	case map[string]interface{}:
		// For Ethereum
		if value, ok := v["value"].(string); ok {
			// Parse decimal string to big.Int
			bigValue := new(big.Int)
			if _, success := bigValue.SetString(value, 10); !success {
				return 0, fmt.Errorf("failed to parse decimal value: %s", value)
			}
			// Convert from wei to ETH (divide by 10^18) and check if result fits uint64
			weiPerEth := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
			ethValue := new(big.Int).Div(bigValue, weiPerEth)
			if !ethValue.IsUint64() {
				return 0, fmt.Errorf("converted ETH value exceeds uint64 range: %s", ethValue.String())
			}
			return ethValue.Uint64(), nil
		}
		// For Solana
		if result, ok := v["result"].(map[string]interface{}); ok {
			meta := result
			if meta, ok := meta["meta"].(map[string]interface{}); ok {
				if preBalances, ok := meta["preBalances"].([]interface{}); ok && len(preBalances) > 0 {
					if postBalances, ok := meta["postBalances"].([]interface{}); ok && len(postBalances) > 0 {
						// Get the difference between pre and post balances of sender
						preBalance := uint64(preBalances[0].(float64))
						postBalance := uint64(postBalances[0].(float64))
						if preBalance > postBalance {
							// Convert from lamports to SOL (divide by 10^9)
							lamports := preBalance - postBalance
							solValue := float64(lamports) / 1e9
							if solValue > float64(^uint64(0)) {
								return 0, fmt.Errorf("converted SOL value exceeds uint64 range: %f", solValue)
							}
							return uint64(solValue), nil
						}
					}
				}
			}
		}
	}
	return 0, fmt.Errorf("could not extract amount from transaction")
}

// Helper function to extract from address from transaction
func extractFromAddress(tx interface{}, chain string) (string, error) {
	switch chain {
	case "ethereum":
		if txMap, ok := tx.(map[string]interface{}); ok {
			if from, ok := txMap["from"].(string); ok {
				return from, nil
			}
		}
	case "solana":
		if txMap, ok := tx.(map[string]interface{}); ok {
			if result, ok := txMap["result"].(map[string]interface{}); ok {
				if transaction, ok := result["transaction"].(map[string]interface{}); ok {
					if message, ok := transaction["message"].(map[string]interface{}); ok {
						if accountKeys, ok := message["accountKeys"].([]interface{}); ok && len(accountKeys) > 1 {
							// The first account key is typically the sender
							if from, ok := accountKeys[0].(string); ok {
								return from, nil
							}
						}
					}
				}
			}
		}
	}
	return "", fmt.Errorf("could not extract from address from transaction")
}

func handlePostTxHash(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get parameters from query params
	txHash := r.URL.Query().Get("txHash")
	chain := r.URL.Query().Get("chain")

	// Validate required parameters
	if txHash == "" {
		http.Error(w, "txHash parameter is required", http.StatusBadRequest)
		return
	}

	if chain == "" {
		http.Error(w, "chain parameter is required", http.StatusBadRequest)
		return
	}

	var (
		tx  interface{}
		err error
	)

	// Get transaction details based on chain
	switch chain {
	case "solana":
		tx, err = GetSolanaTransaction(txHash)
	case "ethereum":
		tx, err = GetEthereumTransaction(txHash)
	default:
		http.Error(w, "Invalid chain parameter. Must be 'solana' or 'ethereum'", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, "Error getting transaction: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract from address
	fromAddress, err := extractFromAddress(tx, chain)
	if err != nil {
		http.Error(w, "Error extracting from address: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Get the from token based on chain
	fromToken, err := getTokenForChain(chain)
	if err != nil {
		http.Error(w, "Error getting token for chain: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract amount from transaction
	amount, err := extractAmountFromTx(tx)
	if err != nil {
		http.Error(w, "Error extracting amount from transaction: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert amount to string
	amountStr := fmt.Sprintf("%d", amount)

	// Build GraphQL mutation
	mutation := fmt.Sprintf(`{"query":"mutation calFund{fund(chainName:\"%s\",depositAddress:\"%s\",amount:\"%s\")}"}`, chainToToken[chain], fromAddress, amountStr)

	// Create request
	req, err := http.NewRequest("POST", CrowdSolver, bytes.NewBuffer([]byte(mutation)))
	if err != nil {
		http.Error(w, "Error creating request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := httpClient.Do(req)
	if err != nil {
		http.Error(w, "Error sending request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "Error from GraphQL endpoint", resp.StatusCode)
		return
	}

	response := map[string]interface{}{
		"status":      "success",
		"chain":       chain,
		"fromAddress": fromAddress,
		"fromToken":   fromToken,
		"amount":      amount,
		"data":        tx,
	}

	// Return response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
