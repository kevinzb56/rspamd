#!/usr/bin/env python3
"""
Example test script for multi-class classification API

This script demonstrates how to test the new /learn endpoint
with the Class header parameter.

Requirements:
  - requests library: pip install requests
  - rspamd running on localhost:11334
"""

import requests
import sys

# Configuration
RSPAMD_URL = "http://localhost:11334"
PASSWORD = "q1"  # Default password from test config

# Sample email message
SAMPLE_EMAIL = """From: sender@example.com
To: recipient@example.com
Subject: Test message
Date: Mon, 11 Nov 2024 10:00:00 +0000
Message-ID: <test@example.com>

This is a test message for multi-class classification.
"""


def test_learn_endpoint(class_name, message=SAMPLE_EMAIL):
    """
    Test the /learn endpoint with a specific class
    
    Args:
        class_name: The class to learn (e.g., 'spam', 'ham')
        message: Email message content
        
    Returns:
        True if successful, False otherwise
    """
    url = f"{RSPAMD_URL}/learn"
    headers = {
        "Password": PASSWORD,
        "Class": class_name,
        "Content-Type": "text/plain"
    }
    
    try:
        response = requests.post(url, headers=headers, data=message)
        response.raise_for_status()
        
        result = response.json()
        if result.get("success"):
            print(f"✓ Successfully learned message as '{class_name}'")
            return True
        else:
            error = result.get("error", "Unknown error")
            print(f"✗ Failed to learn: {error}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"✗ Request failed: {e}")
        return False
    except ValueError as e:
        print(f"✗ Invalid JSON response: {e}")
        return False


def test_backward_compatibility():
    """
    Test that the old /learnspam and /learnham endpoints still work
    """
    print("\nTesting backward compatibility...")
    
    # Test /learnspam
    url = f"{RSPAMD_URL}/learnspam"
    headers = {
        "Password": PASSWORD,
        "Content-Type": "text/plain"
    }
    
    try:
        response = requests.post(url, headers=headers, data=SAMPLE_EMAIL)
        response.raise_for_status()
        result = response.json()
        
        if result.get("success"):
            print("✓ /learnspam endpoint works")
        else:
            print(f"✗ /learnspam failed: {result.get('error')}")
            
    except Exception as e:
        print(f"✗ /learnspam request failed: {e}")
    
    # Test /learnham
    url = f"{RSPAMD_URL}/learnham"
    try:
        response = requests.post(url, headers=headers, data=SAMPLE_EMAIL)
        response.raise_for_status()
        result = response.json()
        
        if result.get("success"):
            print("✓ /learnham endpoint works")
        else:
            print(f"✗ /learnham failed: {result.get('error')}")
            
    except Exception as e:
        print(f"✗ /learnham request failed: {e}")


def test_invalid_class():
    """
    Test that invalid class names are properly rejected
    """
    print("\nTesting invalid class names...")
    
    # Currently, only 'spam' and 'ham' are supported
    invalid_classes = ["phishing", "malware", "invalid"]
    
    for invalid_class in invalid_classes:
        url = f"{RSPAMD_URL}/learn"
        headers = {
            "Password": PASSWORD,
            "Class": invalid_class,
            "Content-Type": "text/plain"
        }
        
        try:
            response = requests.post(url, headers=headers, data=SAMPLE_EMAIL)
            result = response.json()
            
            if "error" in result:
                print(f"✓ Correctly rejected invalid class '{invalid_class}'")
            else:
                print(f"✗ Should have rejected invalid class '{invalid_class}'")
                
        except Exception as e:
            print(f"✓ Request with invalid class '{invalid_class}' failed as expected")


def test_missing_class_header():
    """
    Test that /learn endpoint requires Class header
    """
    print("\nTesting missing Class header...")
    
    url = f"{RSPAMD_URL}/learn"
    headers = {
        "Password": PASSWORD,
        "Content-Type": "text/plain"
    }
    
    try:
        response = requests.post(url, headers=headers, data=SAMPLE_EMAIL)
        result = response.json()
        
        if response.status_code == 400 or "error" in result:
            print("✓ Correctly rejected request without Class header")
        else:
            print("✗ Should have rejected request without Class header")
            
    except Exception as e:
        print(f"✓ Request without Class header failed as expected: {e}")


def main():
    """
    Run all tests
    """
    print("=" * 60)
    print("Multi-Class Classification API Tests")
    print("=" * 60)
    
    print("\nTesting /learn endpoint with valid classes...")
    
    # Test with 'spam' class
    test_learn_endpoint("spam")
    
    # Test with 'ham' class
    test_learn_endpoint("ham")
    
    # Test backward compatibility
    test_backward_compatibility()
    
    # Test error handling
    test_invalid_class()
    test_missing_class_header()
    
    print("\n" + "=" * 60)
    print("Tests completed")
    print("=" * 60)


if __name__ == "__main__":
    main()
