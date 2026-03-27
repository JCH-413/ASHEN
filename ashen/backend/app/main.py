from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import auth, users, admin, scan_requests, scans, vulns, exploits
from app.core.db import init_db

init_db()

app = FastAPI(
    title="ASHEN Backend",
    description="Automated Security & Host Exploitation Navigator",
    version="1.0.0",
)

# CORS — allow React dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", 
        "http://localhost:3000", 
        "http://localhost:8080"
        ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(auth.router,          prefix="/auth",   tags=["Authentication"])
app.include_router(users.router,         prefix="/users",  tags=["User Management"])
app.include_router(admin.router,         prefix="/admin",  tags=["Admin Controls"])
app.include_router(scan_requests.router,                   tags=["Scan Requests"])
app.include_router(scans.router,                           tags=["Scanning"])
app.include_router(vulns.router,                           tags=["Vulnerabilities"])
app.include_router(exploits.router,                        tags=["Exploit Validation"])

@app.get("/")
def root():
    return {"message": "ASHEN backend running..."}