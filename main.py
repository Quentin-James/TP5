from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI(description="TP5 API")

@app.get("/")
async def root():
    return {}
@app.get("/miscellaneous/addition")
async def addition(a: float, b: float):
    return {"result": a + b}

@app.exception_handler(ValueError)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=200,
        content={"message": "invalid input"},
    )

