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

func main() {
	// Define routes with CORS and logging middleware
	http.HandleFunc("/post_tx_hash", corsMiddleware(loggingMiddleware(handlePostTxHash)))

	// Start server
	port := getEnvOrDefault("PORT", "3001")
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

	// Build GraphQL mutation
	mutation := fmt.Sprintf(`
		mutation {
			fund(
				chainName: "%s", 
				depositAddress: "%s",
				amount: "%s"
			)
		}
	`, chainToToken[chain], fromAddress, amount)

	// Create GraphQL request
	graphqlReq := struct {
		Query string `json:"query"`
	}{
		Query: mutation,
	}

	// Convert request to JSON
	jsonData, err := json.Marshal(graphqlReq)
	if err != nil {
		http.Error(w, "Error creating GraphQL request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Send mutation to Linera node
	resp, err := http.Post(CrowdSolver, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		http.Error(w, "Error sending GraphQL mutation: "+err.Error(), http.StatusInternalServerError)
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
