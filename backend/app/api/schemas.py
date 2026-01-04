"""
Pydantic Schemas for Request/Response Validation
"""
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List
from datetime import datetime

# ============= USER SCHEMAS =============

class UserCreate(BaseModel):
    """Schema for user registration."""
    email: EmailStr
    master_password: str = Field(..., min_length=8, max_length=128)
    
    @validator('master_password')
    def validate_master_password(cls, v):
        if len(v) < 8:
            raise ValueError('Master password must be at least 8 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Master password must contain uppercase letters')
        if not any(c.islower() for c in v):
            raise ValueError('Master password must contain lowercase letters')
        if not any(c.isdigit() for c in v):
            raise ValueError('Master password must contain digits')
        return v

class UserLogin(BaseModel):
    """Schema for user login."""
    email: EmailStr
    master_password: str
    totp_token: Optional[str] = None  # For 2FA

class UserResponse(BaseModel):
    """Schema for user response."""
    id: int
    email: str
    is_2fa_enabled: bool
    created_at: datetime
    last_login: Optional[datetime]
    
    class Config:
        from_attributes = True

class TokenResponse(BaseModel):
    """Schema for JWT token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse

# ============= PASSWORD ENTRY SCHEMAS =============

class PasswordEntryCreate(BaseModel):
    """Schema for creating password entry."""
    website_name: str = Field(..., min_length=1, max_length=255)
    website_url: Optional[str] = None
    username: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=1, max_length=1000)
    category: str = "General"
    notes: Optional[str] = None
    is_favorite: bool = False

class PasswordEntryUpdate(BaseModel):
    """Schema for updating password entry."""
    website_name: Optional[str] = Field(None, min_length=1, max_length=255)
    website_url: Optional[str] = None
    username: Optional[str] = Field(None, min_length=1, max_length=255)
    password: Optional[str] = Field(None, min_length=1, max_length=1000)
    category: Optional[str] = None
    notes: Optional[str] = None
    is_favorite: Optional[bool] = None

class PasswordEntryResponse(BaseModel):
    """Schema for password entry response (without decrypted password)."""
    id: int
    website_name: str
    website_url: Optional[str]
    username: str
    category: str
    notes: Optional[str]
    is_favorite: bool
    is_compromised: bool
    created_at: datetime
    updated_at: datetime
    last_used: Optional[datetime]
    
    class Config:
        from_attributes = True

class PasswordEntryDecrypted(PasswordEntryResponse):
    """Schema for password entry with decrypted password."""
    password: str

# ============= 2FA SCHEMAS =============

class TwoFactorSetup(BaseModel):
    """Schema for 2FA setup response."""
    qr_code: str  # Base64 encoded QR code
    secret: str
    message: str

class TwoFactorEnable(BaseModel):
    """Schema for enabling 2FA."""
    totp_token: str = Field(..., min_length=6, max_length=6)

class TwoFactorVerify(BaseModel):
    """Schema for verifying 2FA token."""
    totp_token: str = Field(..., min_length=6, max_length=6)

# ============= PASSWORD GENERATION SCHEMAS =============

class PasswordGenerateRequest(BaseModel):
    """Schema for password generation request."""
    length: int = Field(16, ge=8, le=128)
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True

class PasswordGenerateResponse(BaseModel):
    """Schema for password generation response."""
    password: str
    strength: dict

# ============= PASSWORD ANALYSIS SCHEMAS =============

class PasswordStrengthRequest(BaseModel):
    """Schema for password strength check."""
    password: str

class PasswordStrengthResponse(BaseModel):
    """Schema for password strength response."""
    score: int
    strength: str
    color: str
    entropy: float
    feedback: List[str]
    crack_time: str

class PasswordBreachRequest(BaseModel):
    """Schema for breach check request."""
    password: str

class PasswordBreachResponse(BaseModel):
    """Schema for breach check response."""
    is_breached: bool
    breach_count: int
    severity: Optional[str] = None
    message: str

# ============= STATISTICS SCHEMAS =============

class VaultStats(BaseModel):
    """Schema for vault statistics."""
    total_passwords: int
    weak_passwords: int
    compromised_passwords: int
    favorite_passwords: int
    categories: dict
    recent_activity: List[dict]