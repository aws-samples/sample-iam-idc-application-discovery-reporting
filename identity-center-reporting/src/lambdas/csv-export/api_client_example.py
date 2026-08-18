"""
Example API client for IAM Identity Center CSV Export API

This module demonstrates how to interact with the CSV export API Gateway endpoints
using AWS IAM authentication.
"""

import boto3
import requests
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import json
from typing import Dict, Any, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IAMIdentityCenterExportClient:
    """
    Client for interacting with IAM Identity Center CSV Export API
    """
    
    def __init__(self, api_url: str, region: str = 'us-east-1'):
        """
        Initialize the export client
        
        Args:
            api_url: API Gateway URL (e.g., https://abc123.execute-api.us-east-1.amazonaws.com/prod)
            region: AWS region where the API is deployed
        """
        self.api_url = api_url.rstrip('/')
        self.region = region
        self.session = boto3.Session()
        self.credentials = self.session.get_credentials()
        
    def _make_signed_request(self, method: str, path: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Make a signed request to the API Gateway
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: API path (e.g., /export/applications)
            params: Query parameters
            
        Returns:
            API response as dictionary
        """
        url = f"{self.api_url}{path}"
        
        # Create AWS request
        request = AWSRequest(method=method, url=url, params=params)
        
        # Sign the request
        SigV4Auth(self.credentials, 'execute-api', self.region).add_auth(request)
        
        # Make the request
        response = requests.request(
            method=request.method,
            url=request.url,
            headers=dict(request.headers),
            params=request.params
        )
        
        # Handle response
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"API request failed: {response.status_code} - {response.text}")
            response.raise_for_status()
    
    def export_applications(self, filters: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Export applications data to CSV
        
        Args:
            filters: Optional filters to apply
                - account_id: AWS account ID (12 digits)
                - region: AWS region (e.g., us-east-1)
                - application_name: Application name to search for
                - date_from: Start date (ISO format)
                - date_to: End date (ISO format)
                
        Returns:
            Export response with download URL
        """
        logger.info("Requesting applications export")
        return self._make_signed_request('GET', '/export/applications', filters)
    
    def export_assignments(self, filters: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Export assignments data to CSV
        
        Args:
            filters: Optional filters to apply
                - account_id: AWS account ID (12 digits)
                - region: AWS region (e.g., us-east-1)
                - principal_type: USER or GROUP
                - date_from: Start date (ISO format)
                - date_to: End date (ISO format)
                
        Returns:
            Export response with download URL
        """
        logger.info("Requesting assignments export")
        return self._make_signed_request('GET', '/export/assignments', filters)
    
    def export_full(self, filters: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Export full dataset to CSV
        
        Args:
            filters: Optional filters to apply (combination of all filter types)
                
        Returns:
            Export response with download URL
        """
        logger.info("Requesting full export")
        return self._make_signed_request('GET', '/export/full', filters)
    
    def download_csv(self, download_url: str, filename: str) -> None:
        """
        Download CSV file from pre-signed URL
        
        Args:
            download_url: Pre-signed S3 URL from export response
            filename: Local filename to save the CSV
        """
        logger.info(f"Downloading CSV to {filename}")
        
        response = requests.get(download_url, verify=True, timeout=30)
        response.raise_for_status()
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            f.write(response.text)
        
        logger.info(f"CSV downloaded successfully: {filename}")

def main():
    """
    Example usage of the export client
    """
    # Initialize client (replace with your actual API URL)
    api_url = "https://your-api-id.execute-api.us-east-1.amazonaws.com/prod"
    client = IAMIdentityCenterExportClient(api_url)
    
    try:
        # Example 1: Export all applications
        print("Exporting all applications...")
        response = client.export_applications()
        print(f"Export generated: {response['filename']}")
        print(f"Download URL: {response['download_url']}")
        
        # Download the file
        client.download_csv(response['download_url'], response['filename'])
        
        # Example 2: Export applications for specific account
        print("\nExporting applications for specific account...")
        filters = {
            'account_id': '123456789012',
            'region': 'us-east-1'
        }
        response = client.export_applications(filters)
        print(f"Filtered export generated: {response['filename']}")
        
        # Example 3: Export user assignments only
        print("\nExporting user assignments...")
        filters = {
            'principal_type': 'USER'
        }
        response = client.export_assignments(filters)
        print(f"User assignments export: {response['filename']}")
        
        # Example 4: Export full dataset with date range
        print("\nExporting full dataset with date range...")
        filters = {
            'date_from': '2024-01-01',
            'date_to': '2024-01-31'
        }
        response = client.export_full(filters)
        print(f"Full export with date filter: {response['filename']}")
        
    except Exception as e:
        logger.error(f"Export failed: {e}")

if __name__ == "__main__":
    main()