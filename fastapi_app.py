from fastapi import FastAPI
from pydantic import BaseModel
import requests
import os
from dotenv import load_dotenv

load_dotenv()  # load variables from .env

app = FastAPI()
API_KEY = os.environ.get("OPENAI_API_KEY")  # now loaded from .env

class ChatRequest(BaseModel):
    message: str

@app.post("/chat")
def chat(req: ChatRequest):
    response = requests.post(
        "https://api.yourcompany.com/chat",
        headers={"Authorization": f"Bearer {API_KEY}"},
        json={"prompt": req.message}
    )
    return response.json()
