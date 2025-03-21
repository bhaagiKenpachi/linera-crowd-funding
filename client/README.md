# Crowd-Funding Client

This is a Go client for the Linera crowd-funding application. It provides HTTP endpoints and WebSocket support for interacting with the crowd-funding service.

## Setup

1. Make sure you have Go 1.21 or later installed
2. Install dependencies:
   ```bash
   go mod download
   ```
3. Set the required environment variables:
   ```bash
   export LINERA_PATH=/path/to/linera/executable
   export PORT=3001  # Optional, defaults to 3001
   ```

## Running the Client

Run the client with the required Linera path:

```bash
go run main.go -linera-path=/path/to/linera/executable
```

## API Endpoints

### Create Campaign
- **Endpoint**: `/create_campaign`
- **Method**: POST
- **Body**:
  ```json
  {
    "title": "Campaign Title",
    "description": "Campaign Description",
    "goal": 1000,
    "deadline": 1234567890
  }
  ```

### List Campaigns
- **Endpoint**: `/list_campaigns`
- **Method**: GET
- **Response**: Array of campaign objects

### Contribute to Campaign
- **Endpoint**: `/contribute`
- **Method**: POST
- **Body**:
  ```json
  {
    "campaign_id": "campaign-id",
    "amount": 100
  }
  ```

### Get Campaign Status
- **Endpoint**: `/campaign_status`
- **Method**: GET
- **Query Parameters**:
  - `campaign_id`: ID of the campaign to check

### WebSocket Connection
- **Endpoint**: `/ws`
- **Protocol**: WebSocket
- Supports real-time updates for campaign status and contributions

## Development

The client is structured with the following components:
- `main.go`: Main server implementation with HTTP handlers and WebSocket support
- Middleware for CORS and request logging
- Campaign management endpoints
- WebSocket connection handling

## Testing

To test the endpoints, you can use curl or any HTTP client:

```bash
# Create a campaign
curl -X POST http://localhost:3001/create_campaign \
  -H "Content-Type: application/json" \
  -d '{"title":"Test Campaign","description":"Test Description","goal":1000,"deadline":1234567890}'

# List campaigns
curl http://localhost:3001/list_campaigns

# Contribute to a campaign
curl -X POST http://localhost:3001/contribute \
  -H "Content-Type: application/json" \
  -d '{"campaign_id":"test-id","amount":100}'

# Get campaign status
curl "http://localhost:3001/campaign_status?campaign_id=test-id"
``` 