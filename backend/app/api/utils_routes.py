"""
Utility API Endpoints - Password generation, strength checking, breach detection
"""
from fastapi import APIRouter, HTTPException, status
from backend.app.api.schemas import (
    PasswordGenerateRequest, PasswordGenerateResponse,
    PasswordStrengthRequest, PasswordStrengthResponse,
    PasswordBreachRequest, PasswordBreachResponse
)
from backend.app.security.encryption import EncryptionEngine
from backend.app.utils.password_checker import PasswordChecker
from backend.app.utils.breach_checker import BreachChecker

router = APIRouter(prefix="/api/utils", tags=["Utilities"])

@router.post("/generate-password", response_model=PasswordGenerateResponse)
def generate_password(request: PasswordGenerateRequest):
    """Generate a secure random password."""
    
    try:
        # Generate password
        password = EncryptionEngine.generate_secure_password(
            length=request.length,
            use_uppercase=request.use_uppercase,
            use_lowercase=request.use_lowercase,
            use_digits=request.use_digits,
            use_symbols=request.use_symbols
        )
        
        # Check strength
        strength = PasswordChecker.check_strength(password)
        strength['crack_time'] = PasswordChecker.estimate_crack_time(password)
        
        return {
            "password": password,
            "strength": strength
        }
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/check-strength", response_model=PasswordStrengthResponse)
def check_password_strength(request: PasswordStrengthRequest):
    """Check password strength and get recommendations."""
    
    strength = PasswordChecker.check_strength(request.password)
    crack_time = PasswordChecker.estimate_crack_time(request.password)
    
    return {
        "score": strength['score'],
        "strength": strength['strength'],
        "color": strength['color'],
        "entropy": strength['entropy'],
        "feedback": strength['feedback'],
        "crack_time": crack_time
    }

@router.post("/check-breach", response_model=PasswordBreachResponse)
def check_password_breach(request: PasswordBreachRequest):
    """Check if password has been compromised in data breaches."""
    
    result = BreachChecker.check_password_breach(request.password)
    
    if "error" in result:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=result["error"]
        )
    
    return {
        "is_breached": result["is_breached"],
        "breach_count": result["breach_count"],
        "severity": result.get("severity"),
        "message": result["message"]
    }