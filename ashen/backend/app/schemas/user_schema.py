# making a user schema

from pydantic import BaseModel, EmailStr, Field

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    #the hashing bycrypt we using doesnot allow more than 72 bytes 
    #so we are limiting it
    password: str = Field(..., max_length=72, min_length=6)


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(..., max_length=72)

