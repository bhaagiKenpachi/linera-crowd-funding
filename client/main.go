package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/ethereum/go-ethereum/core/types"
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
		"ethereum": "ETH",
		"solana":   "SOL",
	}
	// RPC endpoints
	EthereumRPC string
	SolanaRPC   string
	CrowdSolver string // Variable to hold the crowd solver URL
	// HTTP client for making requests
	httpClient = &http.Client{}
)

// Logger represents a custom logger with levels and formatting
type Logger struct {
	*log.Logger
}

// LogLevel represents different logging levels
type LogLevel string

const (
	INFO  LogLevel = "INFO"
	ERROR LogLevel = "ERROR"
	DEBUG LogLevel = "DEBUG"
	WARN  LogLevel = "WARN"
)

var logger *Logger

// NewLogger creates a new logger instance
func NewLogger() *Logger {
	return &Logger{
		Logger: log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds),
	}
}

// log formats and writes the log message with the specified level
func (l *Logger) log(level LogLevel, format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	l.Printf("[%s] %s", level, msg)
}

// Info logs an info level message
func (l *Logger) Info(format string, v ...interface{}) {
	l.log(INFO, format, v...)
}

// Error logs an error level message
func (l *Logger) Error(format string, v ...interface{}) {
	l.log(ERROR, format, v...)
}

// Debug logs a debug level message
func (l *Logger) Debug(format string, v ...interface{}) {
	l.log(DEBUG, format, v...)
}

// Warn logs a warning level message
func (l *Logger) Warn(format string, v ...interface{}) {
	l.log(WARN, format, v...)
}

func init() {
	// Initialize the logger
	logger = NewLogger()
	logger.Info("Initializing application...")
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
	logger.Info("Configuration:")
	logger.Info("  Solana RPC: %s", SolanaRPC)
	logger.Info("  Ethereum RPC: %s", EthereumRPC)
	logger.Info("  Crowd Solver URL: %s", CrowdSolver)
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
			"http://localhost:3002":         true,
			"https://market-place.ngrok.io": true,
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
		logger.Info("Request started - Method: %s, Path: %s, RemoteAddr: %s",
			r.Method, r.URL.Path, r.RemoteAddr)

		// Create a custom response writer to capture status code
		rw := &responseWriter{w, http.StatusOK}
		next(rw, r)

		duration := time.Since(start)
		logger.Info("Request completed - Method: %s, Path: %s, Status: %d, Duration: %v",
			r.Method, r.URL.Path, rw.status, duration)
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
	Chain   string `json:"chain"`
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

// TotalPledgeInUsdResponse represents the response structure from the GraphQL query
type TotalPledgeInUsdResponse struct {
	Data struct {
		TotalPledgeInUsd string `json:"totalPledgeInUsd"`
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
	query := `{"query":"query chainAddresses { getChainAddresses { address chain } }"}`

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

func handleTotalPledgeInUsd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Build GraphQL query
	query := `{"query":"query totalPledgeInUsd { totalPledgeInUsd }"}`

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
	var graphqlResp TotalPledgeInUsdResponse
	if err := json.NewDecoder(resp.Body).Decode(&graphqlResp); err != nil {
		http.Error(w, "Error parsing response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert string amount to float for formatting
	amount := 0.0
	fmt.Sscanf(graphqlResp.Data.TotalPledgeInUsd, "%f", &amount)

	// Prepare response
	response := map[string]interface{}{
		"status":   "success",
		"message":  "Total pledge in USD retrieved successfully",
		"amount":   fmt.Sprintf("%f", amount),
		"currency": "USD",
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
	http.HandleFunc("/pledge_in_usd", corsMiddleware(loggingMiddleware(handleTotalPledgeInUsd)))

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

	// Get the sender address
	from, err := types.Sender(types.NewEIP155Signer(tx.ChainId()), tx)
	if err != nil {
		return nil, fmt.Errorf("failed to get sender address: %w", err)
	}

	// Convert transaction to map for consistent response format
	return map[string]interface{}{
		"hash":      tx.Hash().Hex(),
		"value":     tx.Value().String(),
		"gas":       tx.Gas(),
		"gasPrice":  tx.GasPrice().String(),
		"nonce":     tx.Nonce(),
		"isPending": isPending,
		"from":      from.Hex(), // Add the from address
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
func extractAmountFromTx(tx interface{}) (float64, error) {
	switch v := tx.(type) {
	case map[string]interface{}:
		// For Ethereum
		if value, ok := v["value"].(string); ok {
			// Parse decimal string to big.Int
			bigValue := new(big.Int)
			if _, success := bigValue.SetString(value, 10); !success {
				return 0, fmt.Errorf("failed to parse decimal value: %s", value)
			}
			
			// Convert from wei to ETH by dividing by 10^18
			weiPerEth := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
			
			// Convert to float64 before division to preserve decimal places
			fValue, _ := new(big.Float).SetInt(bigValue).Float64()
			fWeiPerEth, _ := new(big.Float).SetInt(weiPerEth).Float64()
			
			ethValue := fValue / fWeiPerEth
			return ethValue, nil
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

							// Extract fee
							fee := uint64(0)
							if feeVal, ok := meta["fee"].(float64); ok {
								fee = uint64(feeVal)
							}

							// Subtract fee from total amount
							actualLamports := lamports - fee
							solValue := float64(actualLamports) / 1e9

							if solValue > float64(^uint64(0)) {
								return 0, fmt.Errorf("converted SOL value exceeds uint64 range: %f", solValue)
							}
							return solValue, nil
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
		logger.Error("Invalid method %s for /post_tx_hash", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get parameters from query params
	txHash := r.URL.Query().Get("txHash")
	chain := r.URL.Query().Get("chain")

	logger.Debug("Processing transaction - Hash: %s, Chain: %s", txHash, chain)

	// Validate required parameters
	if txHash == "" {
		logger.Error("Missing txHash parameter")
		http.Error(w, "txHash parameter is required", http.StatusBadRequest)
		return
	}

	if chain == "" {
		logger.Error("Missing chain parameter")
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
		logger.Debug("Fetching Solana transaction: %s", txHash)
		tx, err = GetSolanaTransaction(txHash)
	case "ethereum":
		logger.Debug("Fetching Ethereum transaction: %s", txHash)
		tx, err = GetEthereumTransaction(txHash)
	default:
		logger.Error("Invalid chain parameter: %s", chain)
		http.Error(w, "Invalid chain parameter. Must be 'solana' or 'ethereum'", http.StatusBadRequest)
		return
	}

	if err != nil {
		logger.Error("Error getting transaction: %v", err)
		http.Error(w, "Error getting transaction: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract from address
	fromAddress, err := extractFromAddress(tx, chain)
	if err != nil {
		logger.Error("Error extracting from address: %v", err)
		http.Error(w, "Error extracting from address: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Get the from token based on chain
	fromToken, err := getTokenForChain(chain)
	if err != nil {
		logger.Error("Error getting token for chain: %v", err)
		http.Error(w, "Error getting token for chain: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract amount from transaction
	amount, err := extractAmountFromTx(tx)
	if err != nil {
		logger.Error("Error extracting amount from transaction: %v", err)
		http.Error(w, "Error extracting amount from transaction: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert amount to string
	amountStr := fmt.Sprintf("%f", amount)

	logger.Info("Transaction processed successfully - Hash: %s, Chain: %s, From: %s, Amount: %s %s",
		txHash, chain, fromAddress, amountStr, fromToken)

	// Build GraphQL mutation
	mutation := fmt.Sprintf(`{"query":"mutation calFund{fund(chainName:\"%s\",depositAddress:\"%s\",amount:\"%s\")}"}`,
		fromToken, fromAddress, amountStr)

	logger.Debug("Sending GraphQL mutation: %s", mutation)

	// Create request
	req, err := http.NewRequest("POST", CrowdSolver, bytes.NewBuffer([]byte(mutation)))
	if err != nil {
		logger.Error("Error creating GraphQL request: %v", err)
		http.Error(w, "Error creating request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Error("Error sending GraphQL request: %v", err)
		http.Error(w, "Error sending request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		logger.Error("Error response from GraphQL endpoint: %d", resp.StatusCode)
		http.Error(w, "Error from GraphQL endpoint", resp.StatusCode)
		return
	}

	logger.Info("Successfully processed fund request - Chain: %s, From: %s, Amount: %s %s",
		chain, fromAddress, amountStr, fromToken)

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
