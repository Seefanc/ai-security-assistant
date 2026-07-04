from fastapi import FastAPI
from pydantic import BaseModel
from openai import OpenAI
from scanner import check_headers, summarize, check_exposed_files, check_xss,check_sqli,check_open_ports,check_cookie_flags,check_redirect_trap,check_path_traversal,check_cors_misconfig 
from fastapi.staticfiles import StaticFiles 
import asyncio

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

client = OpenAI(
    api_key="sk-40472ccecd2a43c89c30b29c28a91e6e",
    base_url="https://api.deepseek.com"
)


class ChatRequest(BaseModel):
    message: str
    level: str 


class ScanRequest(BaseModel):
    url:str

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



@app.post("/api/scan")
async def scan(req: ScanRequest):
    target = req.url.strip()
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target

    t1 = asyncio.to_thread(check_headers, target)
    t2 = asyncio.to_thread(check_exposed_files, target)
    t3 = asyncio.to_thread(check_xss, target)
    t4 = asyncio.to_thread(check_sqli, target)
    t5 = asyncio.to_thread(check_open_ports, target)
    t6 = asyncio.to_thread(check_cookie_flags, target)
    t7 = asyncio.to_thread(check_redirect_trap, target)
    t8 = asyncio.to_thread(check_path_traversal, target)
    t9 = asyncio.to_thread(check_cors_misconfig, target)

    header_results, exposed_results, check_xss_result, check_sqli_result, \
    check_port_result, check_cookie_result, check_redirect_result, \
    check_traversal_result, check_cors_result = await asyncio.gather(
        t1, t2, t3, t4, t5, t6, t7, t8, t9
    )

    stats = summarize(header_results)
    return {"target": target, "findings": header_results, "exposed": exposed_results,
             "stats": stats, "check_xss":check_xss_result, "check_sqli":check_sqli_result,
             "check_open_ports":check_port_result,"check_cookie_flags":check_cookie_result,
             "check_redirect_trap":check_redirect_result,
             "check_path_traversal":check_traversal_result,
             "check_cors_misconfig":check_cors_result
             }
