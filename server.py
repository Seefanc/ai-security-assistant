from fastapi import FastAPI
from pydantic import BaseModel
from openai import OpenAI
from fastapi.staticfiles import StaticFiles 

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

client = OpenAI(
    api_key="sk-40472ccecd2a43c89c30b29c28a91e6e",
    base_url="https://api.deepseek.com"
)


@app.get("/")
def hello():
    return {"message": "你好，这是我的第一个后端服务"}


@app.get("/hello/{name}")
def say_hello(name: str):
    return {"message": f"你好{name},欢迎来到我的后端"}


class ChatRequest(BaseModel):
    message: str
    level: str 


@app.post("/api/chat")
def chat(req: ChatRequest):
 user_input = req.message

 response = client.chat.completions.create(
    model = "deepseek-chat",
    messages=[
       {"role": "system","content": "你是一个安全助手，帮用户分析安全问题。"},
       {"role":"user","content":user_input}
    ]
)
 
 ai_reply = response.choices[0].message.content
 return {"reply": ai_reply}

class PraticeReq(BaseModel):
    name: str


@app.post("/api/Test")
def Test(req: PraticeReq):
    n = req.name
    return {"greeting": f"你好,{n}"}