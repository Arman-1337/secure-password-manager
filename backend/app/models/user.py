"""
User and Password Entry Models
"""
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class User(Base):
    """User model with encrypted master password."""
    
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    master_password_hash = Column(String, nullable=False)  # Bcrypt hash
    salt = Column(LargeBinary, nullable=False)  # For key derivation
    
    # 2FA
    totp_secret = Column(String, nullable=True)
    is_2fa_enabled = Column(Boolean, default=False)
    
    # Account management
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    password_entries = relationship("PasswordEntry", back_populates="owner", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User {self.email}>"


class PasswordEntry(Base):
    """Encrypted password entry in user's vault."""
    
    __tablename__ = "password_entries"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Encrypted data
    website_name = Column(String, nullable=False)
    website_url = Column(String, nullable=True)
    username = Column(String, nullable=False)
    encrypted_password = Column(LargeBinary, nullable=False)  # AES-256 encrypted
    
    # Metadata
    category = Column(String, default="General")
    notes = Column(String, nullable=True)
    
    # Tracking
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_used = Column(DateTime, nullable=True)
    
    # Security
    is_favorite = Column(Boolean, default=False)
    is_compromised = Column(Boolean, default=False)  # From breach detection
    
    # Relationships
    owner = relationship("User", back_populates="password_entries")
    
    def __repr__(self):
        return f"<PasswordEntry {self.website_name} for user {self.user_id}>"