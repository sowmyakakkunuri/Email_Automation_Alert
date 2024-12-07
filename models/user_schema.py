from pydantic import BaseModel, EmailStr, constr
from typing import Optional, Dict, Any
from datetime import datetime

class UserSchema(BaseModel): # type: ignore
    email: EmailStr
    phone_number: Optional[str] = None  
    oauth_credentials: Dict[str, Any]
    created_time: datetime  # Timestamp for when the user was created

    # class Config:
    #     orm_mode = True  # Makes it compatible with ORM models
