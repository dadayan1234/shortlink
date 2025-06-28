import asyncio
import io
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
import sqlite3
import secrets
import uvicorn
from datetime import datetime, timedelta
from fastapi import WebSocket, WebSocketDisconnect
import qrcode

# Tambahkan di bagian import
from typing import List

# JWT Configuration
SECRET_KEY = "shortenapp"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Configurable redirect base URL
REDIRECT_PREFIX = "https://nggo.site"  # FE akan render ini
ACTUAL_REDIRECT_DOMAIN = "https://link.nggo.site"  # yang digunakan FastAPI untuk redirect


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

# Konfigurasi Jinja2 untuk folder templates
templates = Jinja2Templates(directory="templates")

# Route untuk render halaman UI
@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://linklite-a9vfnajzx-dians-projects-d1953d13.vercel.app",
                   "http://localhost:3000", 
                   "https://link.penaku.site",
                   "http://localhost:5173",
                   "https://nggo.site"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database Setup
conn = sqlite3.connect("shortlinks.db", check_same_thread=False)
cursor = conn.cursor()

# Enhanced database schema
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    short_code TEXT UNIQUE,
    original_url TEXT,
    user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    visits INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
""")
conn.commit()

class User(BaseModel):
    username: str
    password: str

class Link(BaseModel):
    original_url: str
    custom_code: str = None # type: ignore

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(username: str):
    cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if user:
        return {"id": user[0], "username": user[1], "password": user[2]}
    return None

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub") # type: ignore
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = get_user(username)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/register")
def register(user: User):
    hashed_password = get_password_hash(user.password)
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user.username, hashed_password))
        conn.commit()
        return {"message": "User created successfully"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already taken")

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token = create_access_token({"sub": user["username"]})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/validate_token")
def validate_token(user: dict = Depends(get_current_user)):
    return {"username": user["username"]}

@app.post("/shorten")
def shorten_url(link: Link, user: dict = Depends(get_current_user)):
    short_code = link.custom_code if link.custom_code else secrets.token_urlsafe(6)
    try:
        cursor.execute("INSERT INTO links (short_code, original_url, user_id) VALUES (?, ?, ?)", 
                       (short_code, link.original_url, user["id"]))
        conn.commit()
        return {"short_url": f"{REDIRECT_PREFIX}/{short_code}"}

    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Custom code already in use")

@app.get("/user/links")
def get_user_links(user: dict = Depends(get_current_user)):
    try:
        # Fetch all links created by the current user
        cursor.execute("""
            SELECT short_code, original_url, visits, created_at, 
                ? || '/' || short_code AS short_url
            FROM links 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        """, (REDIRECT_PREFIX, user["id"]))

        
        # Fetch all results
        links = cursor.fetchall()
        
        # Convert to list of dictionaries for easier JSON serialization
        user_links = [
            {
                "short_code": link[0],
                "original_url": link[1],
                "visits": link[2],
                "created_at": link[3],
                "short_url": link[4]
            } for link in links
        ]
        
        return user_links
    except Exception as e:
        # Log the error (in a real application, use proper logging)
        print(f"Error fetching user links: {e}")
        raise HTTPException(status_code=500, detail="Unable to fetch links")

@app.get("/{short_code}")
def redirect_from_subdomain(short_code: str, request: Request):
    # Hanya proses redirect jika domain-nya link.nggo.site
    if request.url.hostname not in ("link.nggo.site", "localhost"):
        raise HTTPException(status_code=404, detail="Invalid redirect access")

    # Update visit count
    cursor.execute("UPDATE links SET visits = visits + 1 WHERE short_code = ?", (short_code,))
    conn.commit()

    cursor.execute("SELECT original_url FROM links WHERE short_code = ?", (short_code,))
    result = cursor.fetchone()
    if result:
        return RedirectResponse(url=result[0], status_code=302)

    raise HTTPException(status_code=404, detail="Short link not found")


# --- KODE BARU UNTUK QR CODE ---
@app.get("/qr/{short_code}")
def generate_qr_code(short_code: str):
    link_url = f"{ACTUAL_REDIRECT_DOMAIN}/{short_code}"
    cursor.execute("SELECT id FROM links WHERE short_code = ?", (short_code,))
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="Link not found")
    
    img = qrcode.make(link_url)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    buf.seek(0)
    
    return StreamingResponse(buf, media_type="image/png")
    
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            await connection.send_json(message)

# Inisialisasi connection manager
manager = ConnectionManager()

# Tambahkan route WebSocket
@app.websocket("/ws/link-views/{short_code}")
async def websocket_endpoint(websocket: WebSocket, short_code: str):
    await manager.connect(websocket)
    try:
        while True:
            # Ambil jumlah views terkini
            cursor.execute("SELECT visits FROM links WHERE short_code = ?", (short_code,))
            result = cursor.fetchone()
            
            if result:
                # Kirim jumlah views ke client
                await websocket.send_json({"views": result[0]})
            
            # Tunggu sebentar sebelum update berikutnya
            await asyncio.sleep(5)  # Update setiap 5 detik
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        
@app.put("/links/{short_code}")
def update_link(
    short_code: str, 
    link: Link, 
    user: dict = Depends(get_current_user)
):
    try:
        # Check if a custom code is provided
        if link.custom_code and link.custom_code != short_code:
            # Check if the new custom code is already in use
            cursor.execute("SELECT id FROM links WHERE short_code = ?", (link.custom_code,))
            if cursor.fetchone():
                raise HTTPException(status_code=400, detail="Custom code already in use")
        
        # Update with optional custom code
        if link.custom_code and link.custom_code != short_code:
            # Update both URL and short code
            cursor.execute("""
                UPDATE links 
                SET original_url = ?, short_code = ?
                WHERE short_code = ? AND user_id = ?
            """, (link.original_url, link.custom_code, short_code, user["id"]))
        else:
            # Only update URL
            cursor.execute("""
                UPDATE links 
                SET original_url = ?
                WHERE short_code = ? AND user_id = ?
            """, (link.original_url, short_code, user["id"]))
        
        conn.commit()
        
        # Check if update was successful
        cursor.execute("SELECT id FROM links WHERE short_code = ? AND user_id = ?", (short_code, user["id"]))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Link not found or unauthorized")
        
        return {"message": "Link updated successfully"}
    
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Custom code already in use")
    except Exception as e:
        print(f"Error updating link: {e}")
        raise HTTPException(status_code=500, detail="Error updating link")

@app.delete("/links/{short_code}")
def delete_link(
    short_code: str, 
    user: dict = Depends(get_current_user)
):
    try:
        # Hapus link milik user yang sedang login
        cursor.execute("""
            DELETE FROM links 
            WHERE short_code = ? AND user_id = ?
        """, (short_code, user["id"]))
        
        conn.commit()
        
        # Cek apakah delete berhasil
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Link not found or unauthorized")
        
        return {"message": "Link deleted successfully"}
    
    except Exception as e:
        print(f"Error deleting link: {e}")
        raise HTTPException(status_code=500, detail="Error deleting faking fak link")
    
if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)