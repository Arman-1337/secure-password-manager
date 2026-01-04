"""
Breach Detection using HaveIBeenPwned API
"""
import hashlib
import requests
from typing import Dict, Optional

class BreachChecker:
    """Check if passwords have been compromised in data breaches."""
    
    HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
    
    @staticmethod
    def check_password_breach(password: str) -> Dict:
        """
        Check if password appears in known data breaches.
        
        Uses k-Anonymity: Only first 5 chars of SHA-1 hash are sent.
        
        Args:
            password: Password to check
            
        Returns:
            Dictionary with breach status and count
        """
        try:
            # Hash the password
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            
            # Get first 5 characters (prefix)
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Query HIBP API
            response = requests.get(
                f"{BreachChecker.HIBP_API_URL}{prefix}",
                timeout=5
            )
            
            if response.status_code != 200:
                return {
                    "is_breached": False,
                    "breach_count": 0,
                    "error": "Unable to check breach status"
                }
            
            # Parse response
            hashes = response.text.splitlines()
            
            for hash_line in hashes:
                hash_suffix, count = hash_line.split(':')
                
                if hash_suffix == suffix:
                    return {
                        "is_breached": True,
                        "breach_count": int(count),
                        "severity": BreachChecker._get_severity(int(count)),
                        "message": f"⚠️ This password has been found in {count} data breaches!"
                    }
            
            # Not found in breaches
            return {
                "is_breached": False,
                "breach_count": 0,
                "message": "✅ Password not found in known breaches"
            }
            
        except requests.RequestException as e:
            return {
                "is_breached": False,
                "breach_count": 0,
                "error": f"Network error: {str(e)}"
            }
        except Exception as e:
            return {
                "is_breached": False,
                "breach_count": 0,
                "error": f"Error checking breach: {str(e)}"
            }
    
    @staticmethod
    def _get_severity(count: int) -> str:
        """Determine breach severity based on count."""
        if count >= 100000:
            return "CRITICAL"
        elif count >= 10000:
            return "HIGH"
        elif count >= 1000:
            return "MEDIUM"
        else:
            return "LOW"
    
    @staticmethod
    def check_email_breach(email: str) -> Optional[Dict]:
        """
        Check if email appears in data breaches.
        
        Note: Requires API key for full functionality.
        This is a placeholder for future implementation.
        """
        # This would require HIBP API key
        # For now, just return None
        return None