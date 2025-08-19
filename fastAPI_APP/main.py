from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from routers.requests import router as request_router

# Initialize FastAPI
app = FastAPI(title="Core Request Handler API", version="1.0")

# Include API routes
app.include_router(request_router, prefix="/api")

# Custom animated home page
@app.get("/", response_class=HTMLResponse)
def home():
    html_content = """
    <html>
        <head>
            <title>Core Request Handler API</title>
            <style>
                /* Reset and body */
                body {
                    margin: 0;
                    padding: 0;
                    font-family: 'Arial', sans-serif;
                    background: linear-gradient(-45deg, #667eea, #764ba2, #ff6a00, #ff0080);
                    background-size: 400% 400%;
                    animation: gradientBG 15s ease infinite;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    overflow: hidden;
                }

                /* Background animation */
                @keyframes gradientBG {
                    0% {background-position: 0% 50%;}
                    50% {background-position: 100% 50%;}
                    100% {background-position: 0% 50%;}
                }

                /* Container */
                .container {
                    background-color: rgba(255, 255, 255, 0.95);
                    padding: 60px 100px;
                    border-radius: 25px;
                    text-align: center;
                    box-shadow: 0 15px 35px rgba(0,0,0,0.3);
                    transform: scale(0.9);
                    animation: zoomIn 1s forwards;
                }

                @keyframes zoomIn {
                    0% {transform: scale(0.7);}
                    100% {transform: scale(1);}
                }

                h1 {
                    font-size: 2.5em;
                    color: #333;
                    margin-bottom: 20px;
                    animation: fadeIn 1s ease-in-out;
                }

                p {
                    color: #555;
                    font-size: 1.2em;
                    margin-bottom: 35px;
                    animation: fadeIn 1.5s ease-in-out;
                }

                a.button {
                    display: inline-block;
                    padding: 15px 35px;
                    background: #4CAF50;
                    color: white;
                    font-weight: bold;
                    text-decoration: none;
                    border-radius: 12px;
                    transition: 0.3s;
                    animation: fadeIn 2s ease-in-out;
                }

                a.button:hover {
                    background: #45a049;
                    transform: translateY(-3px);
                    box-shadow: 0 10px 20px rgba(0,0,0,0.2);
                }

                .footer {
                    margin-top: 25px;
                    font-size: 0.9em;
                    color: #777;
                    animation: fadeIn 2.5s ease-in-out;
                }

                @keyframes fadeIn {
                    0% {opacity: 0;}
                    100% {opacity: 1;}
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Welcome to Core Request Handler API</h1>
                <p>Send requests and receive processed data securely and efficiently.</p>
                <a href="/docs" class="button">Go to API Docs</a>
                <div class="footer">Powered by FastAPI</div>
            </div>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content)
