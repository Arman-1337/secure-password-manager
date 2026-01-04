"""
Password Vault API Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from backend.app.database.connection import get_db
from backend.app.models.user import User, PasswordEntry
from backend.app.api.schemas import (
    PasswordEntryCreate, PasswordEntryUpdate,
    PasswordEntryResponse, PasswordEntryDecrypted,
    VaultStats
)
from backend.app.api.auth_routes import get_current_user
from backend.app.security.encryption import EncryptionEngine
from backend.app.utils.password_checker import PasswordChecker
from backend.app.utils.breach_checker import BreachChecker

router = APIRouter(prefix="/api/vault", tags=["Password Vault"])

@router.post("/passwords", response_model=PasswordEntryResponse, status_code=status.HTTP_201_CREATED)
def create_password_entry(
    entry_data: PasswordEntryCreate,
    master_password: str = Query(..., description="Master password for encryption"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new password entry."""
    
    # Verify master password
    from backend.app.security.auth import AuthManager
    if not AuthManager.verify_password(master_password, current_user.master_password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid master password"
        )
    
    # Encrypt password
    encrypted_password = EncryptionEngine.encrypt_password(
        entry_data.password,
        master_password,
        current_user.salt
    )
    
    # Check for breach
    breach_result = BreachChecker.check_password_breach(entry_data.password)
    is_compromised = breach_result.get("is_breached", False)
    
    # Create entry
    new_entry = PasswordEntry(
        user_id=current_user.id,
        website_name=entry_data.website_name,
        website_url=entry_data.website_url,
        username=entry_data.username,
        encrypted_password=encrypted_password,
        category=entry_data.category,
        notes=entry_data.notes,
        is_favorite=entry_data.is_favorite,
        is_compromised=is_compromised
    )
    
    db.add(new_entry)
    db.commit()
    db.refresh(new_entry)
    
    return new_entry

@router.get("/passwords", response_model=List[PasswordEntryResponse])
def get_all_passwords(
    category: Optional[str] = None,
    search: Optional[str] = None,
    favorites_only: bool = False,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all password entries for current user."""
    
    query = db.query(PasswordEntry).filter(PasswordEntry.user_id == current_user.id)
    
    # Apply filters
    if category:
        query = query.filter(PasswordEntry.category == category)
    
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (PasswordEntry.website_name.ilike(search_pattern)) |
            (PasswordEntry.username.ilike(search_pattern))
        )
    
    if favorites_only:
        query = query.filter(PasswordEntry.is_favorite == True)
    
    # Order by most recently used
    query = query.order_by(PasswordEntry.last_used.desc().nullslast())
    
    return query.all()

@router.get("/passwords/{password_id}", response_model=PasswordEntryDecrypted)
def get_password_by_id(
    password_id: int,
    master_password: str = Query(..., description="Master password for decryption"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get a specific password entry (with decrypted password)."""
    
    # Verify master password
    from backend.app.security.auth import AuthManager
    if not AuthManager.verify_password(master_password, current_user.master_password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid master password"
        )
    
    # Get entry
    entry = db.query(PasswordEntry).filter(
        PasswordEntry.id == password_id,
        PasswordEntry.user_id == current_user.id
    ).first()
    
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Password entry not found"
        )
    
    # Decrypt password
    try:
        decrypted_password = EncryptionEngine.decrypt_password(
            entry.encrypted_password,
            master_password,
            current_user.salt
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decrypt password"
        )
    
    # Update last used
    entry.last_used = datetime.utcnow()
    db.commit()
    
    # Return with decrypted password
    entry_dict = {
        "id": entry.id,
        "website_name": entry.website_name,
        "website_url": entry.website_url,
        "username": entry.username,
        "password": decrypted_password,
        "category": entry.category,
        "notes": entry.notes,
        "is_favorite": entry.is_favorite,
        "is_compromised": entry.is_compromised,
        "created_at": entry.created_at,
        "updated_at": entry.updated_at,
        "last_used": entry.last_used
    }
    
    return entry_dict

@router.put("/passwords/{password_id}", response_model=PasswordEntryResponse)
def update_password_entry(
    password_id: int,
    entry_data: PasswordEntryUpdate,
    master_password: str = Query(..., description="Master password for encryption"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update a password entry."""
    
    # Verify master password
    from backend.app.security.auth import AuthManager
    if not AuthManager.verify_password(master_password, current_user.master_password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid master password"
        )
    
    # Get entry
    entry = db.query(PasswordEntry).filter(
        PasswordEntry.id == password_id,
        PasswordEntry.user_id == current_user.id
    ).first()
    
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Password entry not found"
        )
    
    # Update fields
    if entry_data.website_name:
        entry.website_name = entry_data.website_name
    if entry_data.website_url is not None:
        entry.website_url = entry_data.website_url
    if entry_data.username:
        entry.username = entry_data.username
    if entry_data.password:
        # Re-encrypt with new password
        entry.encrypted_password = EncryptionEngine.encrypt_password(
            entry_data.password,
            master_password,
            current_user.salt
        )
        # Check for breach
        breach_result = BreachChecker.check_password_breach(entry_data.password)
        entry.is_compromised = breach_result.get("is_breached", False)
    
    if entry_data.category:
        entry.category = entry_data.category
    if entry_data.notes is not None:
        entry.notes = entry_data.notes
    if entry_data.is_favorite is not None:
        entry.is_favorite = entry_data.is_favorite
    
    entry.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(entry)
    
    return entry

@router.delete("/passwords/{password_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_password_entry(
    password_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a password entry."""
    
    entry = db.query(PasswordEntry).filter(
        PasswordEntry.id == password_id,
        PasswordEntry.user_id == current_user.id
    ).first()
    
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Password entry not found"
        )
    
    db.delete(entry)
    db.commit()
    
    return None

@router.get("/stats", response_model=VaultStats)
def get_vault_statistics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get vault statistics."""
    
    all_entries = db.query(PasswordEntry).filter(
        PasswordEntry.user_id == current_user.id
    ).all()
    
    total = len(all_entries)
    weak = 0
    compromised = sum(1 for e in all_entries if e.is_compromised)
    favorites = sum(1 for e in all_entries if e.is_favorite)
    
    # Count by category
    categories = {}
    for entry in all_entries:
        categories[entry.category] = categories.get(entry.category, 0) + 1
    
    # Recent activity
    recent = sorted(all_entries, key=lambda x: x.last_used or datetime.min, reverse=True)[:5]
    recent_activity = [
        {
            "website": e.website_name,
            "username": e.username,
            "last_used": e.last_used
        }
        for e in recent if e.last_used
    ]
    
    return {
        "total_passwords": total,
        "weak_passwords": weak,
        "compromised_passwords": compromised,
        "favorite_passwords": favorites,
        "categories": categories,
        "recent_activity": recent_activity
    }