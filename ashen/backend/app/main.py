from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import auth, users, admin, scan_requests, scans, vulns, exploits, ai, reports
from app.core.db import init_db
from app.core.csrf import CSRFMiddleware

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
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://192.168.28.128:8080",
        ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# CSRF — require X-CSRF-Token header on state-changing requests
app.add_middleware(CSRFMiddleware)

# Routes
app.include_router(auth.router,          prefix="/auth",   tags=["Authentication"])
app.include_router(users.router,         prefix="/users",  tags=["User Management"])
app.include_router(admin.router,         prefix="/admin",  tags=["Admin Controls"])
app.include_router(scan_requests.router,                   tags=["Scan Requests"])
app.include_router(scans.router,                           tags=["Scanning"])
app.include_router(vulns.router,                           tags=["Vulnerabilities"])
app.include_router(exploits.router,                        tags=["Exploit Validation"])
app.include_router(ai.router,                              tags=["AI Engine"])
app.include_router(reports.router,                         tags=["Reports"])

@app.get("/")
def root():
    return {"message": "ASHEN backend running..."}

@asynccontextmanager
async def lifespan(app: FastAPI):
    # On startup: runs before accepting any requests
    db = next(get_db())
    stuck_scans = db.query(Scan).filter(Scan.status == "running").all()
    for scan in stuck_scans:
        scan.status = "failed"
        scan.completed_at = datetime.utcnow()
    db.commit()
    db.close()
    yield
    # On shutdown: runs after last request
