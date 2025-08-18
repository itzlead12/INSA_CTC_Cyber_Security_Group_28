import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_request(client_name: str, endpoint: str):
    """
    Log details of incoming requests.
    """
    logging.info(f"Request received from {client_name} at {endpoint}")
