"""
Authentication API Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from datetime import timedelta, datetime

from backend.app.database.connection import get_db
from backend.app.models.user import User
from backend.app.api.schemas import (
    UserCreate, UserLogin, UserResponse, TokenResponse,
    TwoFactorSetup, TwoFactorEnable, TwoFactorVerify
)
from backend.app.security.auth import AuthManager
from backend.app.security.encryption import EncryptionEngine
from backend.app.config import settings

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

# ============= SECURITY & CURRENT USER (MUST BE BEFORE ENDPOINTS) =============

security = HTTPBearer()

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Get current authenticated user from JWT token."""
    
    token = credentials.credentials
    
    # Verify token
    payload = AuthManager.verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    # Get user
    user_email = payload.get("sub")
    user = db.query(User).filter(User.email == user_email).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )
    
    return user

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    """Register a new user."""
    
    # Check if user already exists
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Hash master password
    master_password_hash = AuthManager.hash_password(user_data.master_password)
    
    # Generate salt for encryption
    salt = EncryptionEngine.generate_salt()
    
    # Create user
    new_user = User(
        email=user_data.email,
        master_password_hash=master_password_hash,
        salt=salt
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user

@router.post("/login", response_model=TokenResponse)
def login_user(credentials: UserLogin, db: Session = Depends(get_db)):
    """Login user and return JWT token."""
    
    # Find user
    user = db.query(User).filter(User.email == credentials.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Verify password
    if not AuthManager.verify_password(credentials.master_password, user.master_password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Check if 2FA is enabled
    if user.is_2fa_enabled:
        if not credentials.totp_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="2FA token required",
                headers={"X-2FA-Required": "true"}
            )
        
        # Verify TOTP
        if not AuthManager.verify_totp(user.totp_secret, credentials.totp_token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid 2FA token"
            )
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()
    
    # Create access token
    access_token = AuthManager.create_access_token(
        data={"sub": user.email, "user_id": user.id},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": user
    }

@router.post("/2fa/setup", response_model=TwoFactorSetup)
def setup_2fa(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Setup 2FA for user (generate QR code)."""
    
    # Generate TOTP secret
    totp_secret = AuthManager.generate_totp_secret()
    
    # Generate QR code
    qr_code = AuthManager.generate_qr_code(current_user.email, totp_secret)
    
    # Store secret (but don't enable yet)
    current_user.totp_secret = totp_secret
    db.commit()
    
    return {
        "qr_code": qr_code,
        "secret": totp_secret,
        "message": "Scan QR code with your authenticator app, then verify to enable 2FA"
    }

@router.post("/2fa/enable")
def enable_2fa(
    data: TwoFactorEnable,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Enable 2FA after verification."""
    
    if not current_user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA not set up. Call /2fa/setup first"
        )
    
    # Verify token
    if not AuthManager.verify_totp(current_user.totp_secret, data.totp_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid 2FA token"
        )
    
    # Enable 2FA
    current_user.is_2fa_enabled = True
    db.commit()
    
    return {"message": "2FA enabled successfully"}

@router.post("/2fa/disable")
def disable_2fa(
    data: TwoFactorVerify,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Disable 2FA."""
    
    if not current_user.is_2fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled"
        )
    
    # Verify token before disabling
    if not AuthManager.verify_totp(current_user.totp_secret, data.totp_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid 2FA token"
        )
    
    # Disable 2FA
    current_user.is_2fa_enabled = False
    current_user.totp_secret = None
    db.commit()
    
    return {"message": "2FA disabled successfully"}

# # ============= DEPENDENCY FOR GETTING CURRENT USER =============

# from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# security = HTTPBearer()

# def get_current_user(
#     credentials: HTTPAuthorizationCredentials = Depends(security),
#     db: Session = Depends(get_db)
# ) -> User:
#     """Get current authenticated user from JWT token."""
    
#     token = credentials.credentials
    
#     # Verify token
#     payload = AuthManager.verify_token(token)
#     if not payload:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid or expired token"
#         )
    
#     # Get user
#     user_email = payload.get("sub")
#     user = db.query(User).filter(User.email == user_email).first()
    
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="User not found"
#         )
    
#     if not user.is_active:
#         raise HTTPException(
#             status_code=status.HTTP_403_FORBIDDEN,
#             detail="User account is inactive"
#         )
    
#     return user

# so we needed to shift this part up cuz it needed to be called before endpoints