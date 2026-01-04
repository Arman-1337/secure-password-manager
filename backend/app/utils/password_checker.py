"""
Password Strength Checker and Validator
"""
import re
import math
from typing import Dict

class PasswordChecker:
    """Analyzes password strength and provides security recommendations."""
    
    @staticmethod
    def check_strength(password: str) -> Dict:
        """
        Analyze password strength.
        
        Args:
            password: Password to check
            
        Returns:
            Dictionary with score and feedback
        """
        score = 0
        feedback = []
        
        # Length check
        length = len(password)
        if length < 8:
            feedback.append("Password should be at least 8 characters")
        elif length < 12:
            score += 1
            feedback.append("Consider using 12+ characters for better security")
        elif length < 16:
            score += 2
        else:
            score += 3
            feedback.append("Excellent length!")
        
        # Character variety
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
        
        variety_count = sum([has_lower, has_upper, has_digit, has_symbol])
        
        if variety_count == 1:
            feedback.append("Use a mix of uppercase, lowercase, numbers, and symbols")
        elif variety_count == 2:
            score += 1
            feedback.append("Add more character variety")
        elif variety_count == 3:
            score += 2
        else:
            score += 3
            feedback.append("Great character variety!")
        
        # Common patterns check
        common_patterns = [
            r'12345', r'password', r'qwerty', r'abc123',
            r'letmein', r'welcome', r'monkey', r'admin'
        ]
        
        for pattern in common_patterns:
            if re.search(pattern, password.lower()):
                score = max(0, score - 2)
                feedback.append("Avoid common patterns and words")
                break
        
        # Sequential characters
        if re.search(r'(abc|bcd|cde|def|123|234|345|456)', password.lower()):
            score = max(0, score - 1)
            feedback.append("Avoid sequential characters")
        
        # Repeated characters
        if re.search(r'(.)\1{2,}', password):
            score = max(0, score - 1)
            feedback.append("Avoid repeating characters")
        
        # Calculate entropy
        entropy = PasswordChecker._calculate_entropy(password)
        
        if entropy < 30:
            score = max(0, score - 1)
        elif entropy > 60:
            score += 1
        
        # Determine strength level
        if score <= 2:
            strength = "Weak"
            color = "red"
        elif score <= 4:
            strength = "Fair"
            color = "orange"
        elif score <= 6:
            strength = "Good"
            color = "yellow"
        else:
            strength = "Strong"
            color = "green"
        
        return {
            "score": min(score, 10),
            "strength": strength,
            "color": color,
            "entropy": round(entropy, 2),
            "feedback": feedback if feedback else ["Password looks good!"]
        }
    
    @staticmethod
    def _calculate_entropy(password: str) -> float:
        """Calculate password entropy (bits)."""
        # Determine character set size
        charset_size = 0
        
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0
        
        # Entropy = log2(charset_size^length)
        entropy = len(password) * math.log2(charset_size)
        
        return entropy
    
    @staticmethod
    def estimate_crack_time(password: str) -> str:
        """
        Estimate time to crack password.
        
        Assumes 10 billion guesses per second (modern GPU).
        """
        entropy = PasswordChecker._calculate_entropy(password)
        
        # Number of possible combinations
        combinations = 2 ** entropy
        
        # Guesses per second (10 billion)
        guesses_per_second = 10_000_000_000
        
        # Time in seconds
        seconds = combinations / guesses_per_second
        
        # Convert to human-readable
        if seconds < 60:
            return f"{seconds:.2f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.2f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.2f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.2f} days"
        elif seconds < 3153600000:
            return f"{seconds/31536000:.2f} years"
        else:
            return "Centuries+"