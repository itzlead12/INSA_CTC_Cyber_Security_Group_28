# middleware.py
from fastapi import Request, WebSocket
from fastapi.responses import JSONResponse, Response
import httpx
from typing import Dict, Optional, List
from rules import RuleEngine, WAFResult
from services import DjangoAPIClient
import asyncio
import logging
import json
from datetime import datetime, timedelta

BLOCKED_PAGE_HTML = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Access Denied</title>
  <style>
    body {
    display: flex;
    flex-direction: row;
    justify-content: space-evenly;
    align-items: center;
    height: 100dvh;
    margin: 0;
    padding: 0;
    background: linear-gradient(45deg, #355c6b 0%, #0299e5 100%);
    overflow: hidden;
    font-family: 'Vollkorn', serif;
}
    #httpresponse{display: flex;flex-direction: column;align-items: self-start;}
    h1{font-size:6em;margin:0;text-shadow:0 2px 10px rgba(0,0,0,0.3)}
    h2{font-size:2em;margin-top:0;text-shadow:0 1px 5px rgba(0,0,0,0.3)}
    .reason{font-size:1.2em;color:#ffd700;max-width:80%; margin:20px 20px 20px 0px;word-wrap:break-word}
    #policeman{width:350px;}
    @media (max-width:720px){#policeman{width:280px} h1{font-size:4em} h2{font-size:1.5em} body{display:flex; flex-direction: column; align-items: center;} }
  </style>
</head>
<body>
  <div id="httpresponse">
    <h1>403</h1>
    <h2>Access denied</h2>
    <div class="reason">{{REASON}}</div>
  </div>
  
  <svg id="policeman" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 610.53 718.27"><defs><style>.cls-1{fill:#c1c1c1;}.cls-2{fill:#e6a964;}.cls-3{fill:#fcc082;}.cls-4{fill:#009edc;}.cls-5{fill:#d39d29;}.cls-6{fill:#fff;}</style></defs><title>Fichier 7access_denied_animated</title><g id="Calque_2" data-name="Calque 2"><g id="access_denied"><g id="policemang"><path class="cls-1" d="M310.37,506.64l69.5-88.87,25.74,7L380.84,538.17Z"/><path class="cls-1" d="M397.94,429.41l-21.46,99.73L320.9,504.3l61.44-79.19Z"/><path class="cls-1" d="M204.72,424.72l5.92-1.62,15.41-4.49,4.09-1.1,70.09,89-70.8,31.66Z"/><path class="cls-1" d="M290,504l-55.84,25.16-21.72-99.8,15.28-4.23Z"/><path class="cls-2" d="M234.63,413V384l9.23,4.36a109.68,109.68,0,0,0,46.74,10.79h29.58a110,110,0,0,0,46-10.08l9.23-4.22v28.54l-70,89.19Z"/><path class="cls-2" d="M368.81,394.62v16.19L305.36,492l-64.23-81.26V394.17a117.06,117.06,0,0,0,49.47,11.44h29.58A117,117,0,0,0,368.81,394.62Z"/><path class="cls-3" d="M448.84,258.68A17.75,17.75,0,0,1,431.09,241V214.22l3.91-3.64a67.71,67.71,0,0,0,8.84-11.84l2-3.38h3.9a17.75,17.75,0,0,1,16.84,17.69v28A17.74,17.74,0,0,1,448.84,258.68Z"/><path class="cls-3" d="M460.09,213v28a11.25,11.25,0,0,1-22.49,0V217.08l2.21-2.21a74.17,74.17,0,0,0,9.62-13A11.25,11.25,0,0,1,460.09,213Z"/><path class="cls-3" d="M290.6,392.61A104.53,104.53,0,0,1,186.2,287.94V220.52l9.81,5.72c25.23,14.83,62.09,22.3,109.42,22.3s84.06-7.41,109.35-22.23l9.82-5.72v67.28A104.55,104.55,0,0,1,320.25,392.61H290.6Z"/><path class="cls-3" d="M418.1,231.9v56a98.06,98.06,0,0,1-97.85,98.24H290.6a98,98,0,0,1-97.9-98.17v-56c26,15.41,64,23.21,112.73,23.21S391.83,247.31,418.1,231.9Z"/><path class="cls-3" d="M162,258.68A17.75,17.75,0,0,1,144.2,241V213a17.73,17.73,0,0,1,16.9-17.68h4l2,3.44a63.56,63.56,0,0,0,8.65,11.7l4,4v26.78A17.74,17.74,0,0,1,162,258.68Z"/><path class="cls-3" d="M173.19,217.08V241.2a11.25,11.25,0,0,1-22.49,0V213a11.25,11.25,0,0,1,10.72-11.18a70.46,70.46,0,0,0,9.56,13Z"/><path class="cls-1" d="M305.43,242.11c-74.9,0-109-19.51-124.37-35.7a57.17,57.17,0,0,1-14.43-25.16l-2.15-8.12H446.31l-2.15,8.12a57.42,57.42,0,0,1-14.43,25.16C414.32,222.67,380.26,242.11,305.43,242.11Z"/><path class="cls-1" d="M437.86,179.63a50.85,50.85,0,0,1-13,22.3c-14.57,15.41-47.14,33.68-119.56,33.68s-104.93-18.53-119.5-33.68a50.89,50.89,0,0,1-13-22.3Z"/><path class="cls-4" d="M163.05,166.63l-59.61-45,1.94-4.68c6.5-16.06,28.74-55.59,85.17-74.7a637.77,637.77,0,0,1,114-29.19h1.69a641.28,641.28,0,0,1,114.1,29.19c56.82,19.5,78.54,58.51,85.17,74.7l1.95,4.68-59.49,45ZM303.87,53.38a59.45,59.45,0,0,1-24.77,6.5,3.32,3.32,0,0,0-2.86,1.69l-8.65,15.28a3.18,3.18,0,0,0-.33,2.47,37.68,37.68,0,0,1,0,20.74s-8.84,21.77,8.72,32.5l10.66,6.5a99.22,99.22,0,0,1,13.72,9l1.29,1.17.53,1.69a3.25,3.25,0,0,0,6.5,0l.52-1.69,1.3-1.17a96.33,96.33,0,0,1,13-8.71l1.88-1.1c2.93-1.69,6-3.51,9.24-5.46,14.1-8.59,11.76-25.36,8.51-33a37.27,37.27,0,0,1,0-20.15,3.2,3.2,0,0,0,0-2.54l-8.64-15.41A3.19,3.19,0,0,0,331.62,60a59.38,59.38,0,0,1-24.76-6.51,3.37,3.37,0,0,0-3,0Z"/><path class="cls-4" d="M418.29,48.43A635.45,635.45,0,0,0,305.43,19.5A631.82,631.82,0,0,0,192.57,48.43c-54.16,18.34-75,56.31-81.27,71.13l53.9,40.63H445.59l54-40.63C493.51,104.67,472.77,66.9,418.29,48.43ZM338.13,138c-3.25,2-6.5,3.83-9.3,5.52a127.94,127.94,0,0,0-14.11,9a9.75,9.75,0,0,1-18.65,0a124.25,124.25,0,0,0-14.05-9L272.47,138c-17.56-10.8-15-31.4-11.06-40.7A30.6,30.6,0,0,0,261,81a9.72,9.72,0,0,1,.9-7.48l8.65-15.35A9.83,9.83,0,0,1,279,53.24a56,56,0,0,0,21.84-5.59,9.85,9.85,0,0,1,8.91,0a56.06,56.06,0,0,0,21.85,5.59,9.75,9.75,0,0,1,8.51,4.94l8.65,15.35a9.72,9.72,0,0,1,.91,7.48a30.29,30.29,0,0,0-.52,15.92C353.28,106.56,355.88,127.16,338.13,138Z"/><path class="cls-5" d="M301.66,140.36c-3.39-2.4-7.87-5.07-13-8.06l-2.6-1.5-6.5-4c-10.2-6.5-8.45-18.59-6.11-24.32A38.08,38.08,0,0,0,274.55,81l-.46-2.35,7-12.41,3.31-.39A71.67,71.67,0,0,0,303,61.05l2.47-1,2.47,1A71,71,0,0,0,326.55,66l3.32.39,7,12.42-.46,2.34a35.66,35.66,0,0,0,1.11,20.8c3.18,8.19,3.44,19.5-5.92,25l-9.23,5.65-1,.58c-4.81,2.8-8.91,5.21-12,7.48l-3.77,2.73Z"/><path class="cls-6" d="M328,121.31l-9,5.4c-5.33,3.12-9.95,5.79-13.52,8.39-3.64-2.6-8.19-5.27-13.53-8.39l-9.1-5.4c-7.8-4.74-3.83-15.47-3.51-16.25a44,44,0,0,0,1.5-25.23l4.16-7.4A78.1,78.1,0,0,0,305.43,67a77.5,77.5,0,0,0,20.41,5.4l4.16,7.4a43,43,0,0,0,1.37,24.84C331.82,105.84,335.79,116.57,328,121.31Z"/><path class="cls-4" d="M538.17,716.57v-6.5a3.32,3.32,0,0,0,3.25-3.25V618.46a3.31,3.31,0,0,0-3.25-3.25H393.59a3.32,3.32,0,0,0-3.26,3.25v88.36a3.32,3.32,0,0,0,3.26,3.25v6.5H217.21v-6.5a3.26,3.26,0,0,0,3.25-3.25V618.46a3.26,3.26,0,0,0-3.25-3.25H72.62a3.31,3.31,0,0,0-3.25,3.25v88.36a3.32,3.32,0,0,0,3.25,3.25v6.5H12l19.5-141.21c0-.72,10.14-75.68,44.21-100.57,23.27-16.91,75.93-34.53,116.05-46.36l6.5-1.95,25.48,117A3.27,3.27,0,0,0,227,546a2.88,2.88,0,0,0,1.17,0L305,511.39l76.72,34.26a3.12,3.12,0,0,0,1.36,0,2.89,2.89,0,0,0,1.37,0,3.12,3.12,0,0,0,1.75-2.14l25.49-117,6.5,1.95c39.85,11.7,92.25,29.19,115.65,46.22,34.27,25,44.21,100.19,44.28,100.9l19.5,140.89Zm-6.5-128.08v-8.13H400.08v8.13Z"/><path class="cls-4" d="M538.17,716.57h52l-18.53-140.3c0-.78-9.75-72.95-41.6-96.22-22.95-16.71-76.2-34.26-113.65-45.51L392.74,544.8a9.5,9.5,0,0,1-5.14,6.51,9.26,9.26,0,0,1-4.35,1,9.85,9.85,0,0,1-4-.84l-74.24-33-73.85,33.09a9.2,9.2,0,0,1-4,.84,9.74,9.74,0,0,1-9.55-7.67l-24-110.13c-37.45,11.05-91,28.67-114,45.51-26.52,19.5-39,76-41.6,96.16L19.44,716.69H72.62a9.74,9.74,0,0,1-9.75-9.75V618.46a9.75,9.75,0,0,1,9.75-9.75H217.21a9.76,9.76,0,0,1,9.75,9.75v88.36a9.76,9.76,0,0,1-9.75,9.75H393.59a9.76,9.76,0,0,1-9.76-9.75V618.46a9.76,9.76,0,0,1,9.76-9.75H538.17a9.76,9.76,0,0,1,9.75,9.75v88.36A9.76,9.76,0,0,1,538.17,716.57Zm0-121.58H393.59V573.86H538.17Z"/><path class="cls-1" d="M396.84,621.71H534.92v81.85H396.84Z"/><path class="cls-1" d="M403.33,628.22H528.42v68.84H403.33Z"/><path class="cls-1" d="M75.87,621.71H214v81.85H75.87Z"/><path class="cls-1" d="M82.37,628.22H207.45v68.84H82.37Z"/><path d="M349.24,96.93A30.5,30.5,0,0,1,349.76,81a9.68,9.68,0,0,0-.91-7.48l-8.64-15.35a9.8,9.8,0,0,0-8.52-4.94,56,56,0,0,1-21.84-5.59,9.85,9.85,0,0,0-8.91,0,56,56,0,0,1-22,5.59,9.83,9.83,0,0,0-8.52,4.94L261.8,73.53a9.72,9.72,0,0,0-.91,7.48,30.6,30.6,0,0,1,.39,16.25c-3.9,9.36-6.5,29.9,11.25,40.7l9.36,5.59a123.24,123.24,0,0,1,14,9,9.75,9.75,0,0,0,18.66,0,127,127,0,0,1,14.11-9c2.92-1.69,6.05-3.51,9.29-5.52C355.88,127.16,353.28,106.56,349.24,96.93ZM328,121.31l-9,5.4c-5.33,3.12-9.95,5.79-13.52,8.39-3.64-2.6-8.19-5.27-13.53-8.39l-9.1-5.4c-7.8-4.74-3.83-15.47-3.51-16.25a44,44,0,0,0,1.5-25.23l4.16-7.4A78.1,78.1,0,0,0,305.43,67a77.5,77.5,0,0,0,20.41,5.4l4.16,7.4a43,43,0,0,0,1.37,24.84C331.82,105.84,335.79,116.57,328,121.31Z"/><path d="M610.53,716.57l-18.85-143c-.46-3.32-10.79-81.2-49.54-109.42-27.57-19.5-90.11-39.59-128.73-50.64a8.74,8.74,0,0,0-1.88-.59h-.46l-22.75-6.5V383.31a117,117,0,0,0,49.28-95.44V269.54a30.69,30.69,0,0,0,42-28.54V213a30.75,30.75,0,0,0-22.69-29.51,53.23,53.23,0,0,0,1.49-8.59l58.51-44.14a9.74,9.74,0,0,0,3.51-10.4c-.71-2.61-18.66-64.17-96-90.44C351,5,308.22.2,306.47,0h-2.15c-1.75,0-44.53,5-118.06,29.9-77.36,26-95.31,87.83-96,90.44a9.81,9.81,0,0,0,3.51,10.4l58.51,44.14a53.23,53.23,0,0,0,1.49,8.59A30.75,30.75,0,0,0,131.06,213v28a30.75,30.75,0,0,0,42,28.54v18.33a117,117,0,0,0,48.43,94.79v23.93c-27,7.08-118.64,32.44-153.36,57.53-38.68,28.41-49.21,106.3-49.21,109.55L0,716.69H19.5L38,576.34c2.6-20.16,15.08-76.78,41.61-96.16,23-16.71,76.58-34.32,114-45.51l24,110.13a9.74,9.74,0,0,0,9.3,7.67,9.19,9.19,0,0,0,4-.84L305,518.54l74,33.09a9.65,9.65,0,0,0,4,.84,9.19,9.19,0,0,0,4.36-1,9.45,9.45,0,0,0,5.13-6.5l24-110c37.45,11,90.7,28.54,113.64,45.51,31.86,23.28,41.55,95.44,41.61,96.22L590.31,717h19.5ZM460.09,213v28a11.25,11.25,0,0,1-22.49,0V217.08l2.21-2.21a74.17,74.17,0,0,0,9.62-13A11.25,11.25,0,0,1,460.09,213ZM111.3,119.56c6.5-14.76,27.11-52.73,81.27-71.06A631.82,631.82,0,0,1,305.43,19.57A634.81,634.81,0,0,1,418.29,48.5c54.48,18.4,75.22,56.17,81.26,71.06l-54,40.63H165.2Zm61.89,121.51a11.25,11.25,0,0,1-22.49,0V213a11.24,11.24,0,0,1,10.72-11.18,70.46,70.46,0,0,0,9.56,13l2.21,2.21Zm0-61.38H437.86a50.79,50.79,0,0,1-13,22.3c-14.57,15.41-47.14,33.68-119.56,33.68s-104.93-18.59-119.5-33.74a50.9,50.9,0,0,1-12.87-22.3ZM192.7,287.94v-56c26,15.41,64,23.21,112.73,23.21s86.4-7.8,112.66-23.21v56a98,98,0,0,1-97.84,98.24H290.6a98,98,0,0,1-97.9-98.17v0Zm41.41,241.2-21.72-99.8,15.28-4.23L290,503.91Zm7-118.2V394.17a117.06,117.06,0,0,0,49.47,11.44h29.58A117.08,117.08,0,0,0,368.81,395v15.86L305.36,492Zm135.35,118.2L320.9,504.3l61.44-79.19,15.6,4.23Z"/><path d="M393.59,573.86H538.17V595H393.59Z"/><path d="M217.21,608.71H72.62a9.75,9.75,0,0,0-9.75,9.75v88.36a9.75,9.75,0,0,0,9.75,9.75H217.21a9.76,9.76,0,0,0,9.75-9.75V618.46A9.76,9.76,0,0,0,217.21,608.71Zm-9.76,88.35H82.37V628.22H207.45Z"/><path d="M538.17,608.71H393.59a9.76,9.76,0,0,0-9.76,9.75v88.36a9.76,9.76,0,0,0,9.76,9.75H538.17a9.76,9.76,0,0,0,9.75-9.75V618.46A9.76,9.76,0,0,0,538.17,608.71Zm-9.75,88.35H403.33V628.22H528.42Z"/></g><g id="hand"><path d="M152.56,393.69a26,26,0,0,0-26.33,25.84l-.56,59.7a25.42,25.42,0,0,0-14.45-4.77,26.73,26.73,0,0,0-26.28,21.18,24.75,24.75,0,0,0-2.88-1.74,25.83,25.83,0,0,0-19.7-1.35l-.59.58a25.43,25.43,0,0,0-17.61,23.6,27.72,27.72,0,0,0-16.81-.16A26.45,26.45,0,0,0,10.24,548.3C9,555.24,3,579.53,2.8,601c-.38,40.58.12,48.7,16.72,71.46l-.2,21.45c-.12,12.75,9.64,23.28,22.39,23.4l104.91,1a23.26,23.26,0,0,0,23.41-23l.19-20.87c6.43-5.74,23.42-24.13,23.64-48.47v-.58c.17-18-1.45-30.74-17-43.06L178.4,420A26,26,0,0,0,152.56,393.69ZM14.39,601.09a181.66,181.66,0,0,1,3.35-30.38l13.37,39.81C35.62,623.9,50.62,631.57,64,627.06a26.53,26.53,0,0,0,17.29-19.75,25.52,25.52,0,0,0,18.83,1l1.16-.57a33.83,33.83,0,0,0,6-3.12c13.38,15.73,28.22,29.95,36.66,33.66a5.71,5.71,0,1,0,4.74-10.39c-7.15-3-22.09-17.83-35.2-33.75a6.53,6.53,0,0,0-1-2c-10.89-13.43-18.89-25.68-21.72-32.66a11.13,11.13,0,0,1-.59-2c-.65-4.61.67-9.49,3.62-11.9,4.67-3.43,12.19-1.62,21.41,4.26,8.3,5.83,28.29,21.17,46.48,35.32l5.32,4.59.57.58c13.83,9.4,14.91,17.53,14.74,35.5v.58c-.81,23.76-21.26,41-21.26,41a5.28,5.28,0,0,0-2.36,4.61l-.22,23.19a11.63,11.63,0,0,1-11.7,11.49l-104.91-1c-5.8-.05-11-5.32-10.91-11.69l.22-23.19A8.27,8.27,0,0,0,30,667.32C14.55,646.31,14,641.67,14.39,601.09Zm56.22,1.11a11.64,11.64,0,0,1-1.8,6.36A14.75,14.75,0,0,1,60.63,616a14.72,14.72,0,0,1-18.47-9.45L22.63,548.39a14.39,14.39,0,0,1-.2-1.72c-2.82-8.14,1.31-16.22,8.87-18.46a14.55,14.55,0,0,1,11,.68,18.53,18.53,0,0,1,2,1.23A15.09,15.09,0,0,1,49,536.67l5.24,15.52,15.22,45.36A10.84,10.84,0,0,1,70.61,602.2ZM90.4,531.66a31.94,31.94,0,0,0-8.91,11.61,25,25,0,0,0-2.9,11.47c0,.32,0,.64,0,1a22.64,22.64,0,0,0,1.64,8.91c.15.4.31.82.49,1.23.06.16.13.33.20.49,3.28,7.6,10.08,17.89,18.22,28.34l1.08,1.44a4.36,4.36,0,0,1-2.33,1.13l-1.16.57a14.24,14.24,0,0,1-17.89-8.86L65.32,548.83,61.08,536.2a6.39,6.39,0,0,0-.26-3.08l-4-11.63a14.49,14.49,0,0,1,1.65-12.26,14,14,0,0,1,6.62-4.48l1.17-.56c3.49-1.13,7.55-1.09,10.43.67A13.72,13.72,0,0,1,83.62,513Zm21.87-45.59a16.61,16.61,0,0,1,10.4,4.15,13.67,13.67,0,0,1,4,9.31L125.23,543c-1.33-.91-2.55-1.71-3.61-2.38-7.36-5-13.61-7.21-18.75-7.84a5.72,5.72,0,0,0-.3-1l-4.43-13a7.48,7.48,0,0,0,.52-2.65l-1.61-13.35,0-2.31C97.14,492.3,104.16,486,112.27,486.07Zm40.18-80.79a14.36,14.36,0,0,1,14.36,14.63l-1.44,153.4c-9.64-7.56-20.11-15.68-28.86-22.19a6.06,6.06,0,0,0,.09-1.06l.46-49.27,0-1.16.74-80A14.36,14.36,0,0,1,152.45,405.28Z"/><path class="cls-3" d="M44.36,530.12A15.09,15.09,0,0,1,49,536.67l5.24,15.52,15.22,45.36a10.84,10.84,0,0,1,1.12,4.65,11.64,11.64,0,0,1-1.8,6.36A14.75,14.75,0,0,1,60.63,616a14.72,14.72,0,0,1-18.47-9.45L22.63,548.39a14.39,14.39,0,0,1-.2-1.72c-2.82-8.14,1.31-16.22,8.87-18.46a14.55,14.55,0,0,1,11,.68A18.53,18.53,0,0,1,44.36,530.12Z"/><path class="cls-3" d="M83.62,513l6.78,18.62a31.94,31.94,0,0,0-8.91,11.61,25,25,0,0,0-2.9,11.47c0,.32,0,.64,0,1a22.64,22.64,0,0,0,1.64,8.91c.15.4.31.82.49,1.23.06.16.13.33.20.49,3.28,7.6,10.08,17.89,18.22,28.34l1.08,1.44a4.36,4.36,0,0,1-2.33,1.13l-1.16.57a14.24,14.24,0,0,1-17.89-8.86L65.32,548.83,61.08,536.2a6.39,6.39,0,0,0-.26-3.08l-4-11.63a14.49,14.49,0,0,1,1.65-12.26,14,14,0,0,1,6.62-4.48l1.17-.56c3.49-1.13,7.55-1.09,10.43.67A13.72,13.72,0,0,1,83.62,513Z"/><path class="cls-3" d="M64,627.06a26.53,26.53,0,0,0,17.29-19.75,25.52,25.52,0,0,0,18.83,1l1.16-.57a33.83,33.83,0,0,0,6-3.12c13.38,15.73,28.22,29.95,36.66,33.66a5.71,5.71,0,1,0,4.74-10.39c-7.15-3-22.09-17.83-35.2-33.75a6.53,6.53,0,0,0-1-2c-10.89-13.43-18.89-25.68-21.72-32.66a11.13,11.13,0,0,1-.59-2c-.65-4.61.67-9.49,3.62-11.9,4.67-3.43,12.19-1.62,21.41,4.26,8.3,5.83,28.29,21.17,46.48,35.32l5.32,4.59.57.58c13.83,9.4,14.91,17.53,14.74,35.5v.58c-.81,23.76-21.26,41-21.26,41a5.28,5.28,0,0,0-2.36,4.61l-.22,23.19a11.63,11.63,0,0,1-11.7,11.49l-104.91-1c-5.8-.05-11-5.32-10.91-11.69l.22-23.19A8.27,8.27,0,0,0,30,667.32c-15.45-21-16-25.65-15.61-66.23a181.66,181.66,0,0,1,3.35-30.38l13.37,39.81C35.62,623.9,50.62,631.57,64,627.06Z"/><path class="cls-3" d="M126.64,499.53,125.23,543c-1.33-.91-2.55-1.71-3.61-2.38-7.36-5-13.61-7.21-18.75-7.84a5.72,5.72,0,0,0-.3-1l-4.43-13a7.48,7.48,0,0,0,.52-2.65l-1.61-13.35,0-2.31c.07-8.12,7.09-14.43,15.2-14.35a16.61,16.61,0,0,1,10.4,4.15A13.67,13.67,0,0,1,126.64,499.53Z"/><path class="cls-3" d="M166.81,419.91l-1.44,153.4c-9.64-7.56-20.11-15.68-28.86-22.19a6.06,6.06,0,0,0,.09-1.06l.46-49.27,0-1.16.74-80a14.5,14.5,0,0,1,29,.27Z"/></g><path d="M296.31,105.7h-1.76V109H290V105.7H284.1v-2l7.42-10.62h3v10.8h1.76Zm-10.14-1.79h3.93V97.82Z"/><path d="M305,92.87q6.66,0,6.66,8.2T305,109.28q-6.66,0-6.66-8.21T305,92.87Zm0,1.27q-1.82,0-1.81,6.93T305,108q1.81,0,1.81-6.94T305,94.14Z"/><path d="M313.53,103.78l2.13-.12a7,7,0,0,0-.3,1.65c-.08,1.7.82,2.55,2.69,2.55s2.77-1,2.77-3.11-1.1-3.15-3.3-3.15l-1.26,0V99.74l.91,0q3.46,0,3.47-2.94,0-2.55-2.46-2.55c-1.62,0-2.42.75-2.42,2.25a6.36,6.36,0,0,0,.14,1.27l-2.14-.45c0-3,1.75-4.51,5.25-4.51q6,0,6.05,4.13c0,1.8-1.14,3-3.42,3.67q3.87.89,3.87,4c0,3.1-2.14,4.65-6.44,4.65q-5.74,0-5.74-3.84A8.37,8.37,0,0,1,313.53,103.78Z"/></g></g></svg>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/1.20.3/TweenMax.min.js"></script>
  <script>
    
    TweenMax.set('#hand',{transformOrigin:"center bottom",y:50});
    TweenMax.fromTo('#hand',0.3,{rotation:-10},{rotation:10,yoyo:true,repeat:-1,ease:Power1.easeInOut});
  </script>
</body>
</html>
"""

logger = logging.getLogger(__name__)


class PureWebSocketManager:
    """
    Pure WebSocket manager - broadcasts real-time data to both admin and client dashboards
    """
    
    def __init__(self):
        self.active_connections = []
        self.api_base_url = "http://django:8000"
        self.stats_cache = {}
        self.last_api_fetch = None
        self.request_timestamps = []

    async def connect(self, websocket: WebSocket, connection_type: str = "admin", client_id: str = None):
        """Accept and track new WebSocket connection for both admin and client dashboards"""
        await websocket.accept()
        
        connection_info = {
            'websocket': websocket,
            'type': connection_type,  # 'admin' or 'client'
            'client_id': client_id,   # Only for client connections
            'connected_at': datetime.now()
        }
        self.active_connections.append(connection_info)
        
        logger.info(f"New {connection_type} WebSocket connection. Total: {len(self.active_connections)}")
        
        # Send appropriate dashboard data
        if connection_type == "admin":
            await self.send_admin_dashboard_data(websocket)
        else:
            await self.send_client_dashboard_data(websocket, client_id)

    def disconnect(self, websocket: WebSocket):
        """Remove disconnected WebSocket"""
        for connection_info in self.active_connections:
            if connection_info['websocket'] == websocket:
                self.active_connections.remove(connection_info)
                logger.info(f"WebSocket disconnected. Total: {len(self.active_connections)}")
                break

    async def send_admin_dashboard_data(self, websocket: WebSocket):
        """Send admin dashboard data"""
        try:
            dashboard_data = await self.fetch_admin_dashboard_data()
            
            full_data = {
                "type": "dashboard_data",
                "dashboard_type": "admin",
                "global_stats": dashboard_data.get("global_stats", {}),
                "charts_data": dashboard_data.get("charts_data", {}),
                "recent_activity": dashboard_data.get("recent_activity", []),
                "timestamp": datetime.now().isoformat()
            }
            
            await websocket.send_text(json.dumps(full_data))
            logger.info("📊 Sent admin dashboard data to WebSocket client")
        except Exception as e:
            logger.error(f"Error sending admin dashboard data: {e}")

    async def send_client_dashboard_data(self, websocket: WebSocket, client_id: str):
        """Send client dashboard data"""
        try:
            client_data = await self.fetch_client_dashboard_data(client_id)
            
            client_dashboard_data = {
                "type": "client_dashboard_data",
                "dashboard_type": "client",
                "global_stats": client_data.get("global_stats", {}),
                "charts_data": client_data.get("charts_data", {}),
                "recent_activity": client_data.get("recent_activity", []),
                "client_info": client_data.get("client_info", {}),
                "timestamp": datetime.now().isoformat()
            }
            
            await websocket.send_text(json.dumps(client_dashboard_data))
            logger.info(f"📊 Sent client dashboard data for client {client_id}")
        except Exception as e:
            logger.error(f"Error sending client dashboard data: {e}")

    async def fetch_admin_dashboard_data(self) -> Dict:
        """Fetch admin dashboard data from Django API"""
        try:
            stats_url = f"{self.api_base_url}/api/stats/"
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(stats_url)
                response.raise_for_status()
                api_data = response.json()
            
            dashboard_data = self.process_admin_api_data(api_data)
            self.stats_cache = dashboard_data
            self.last_api_fetch = datetime.now()
            
            return dashboard_data
            
        except Exception as e:
            logger.error(f"Error fetching admin dashboard data: {e}")
            return self.stats_cache or self.get_admin_fallback_data()

    async def fetch_client_dashboard_data(self, client_id: str) -> Dict:
        """Fetch client dashboard data from Django API"""
        try:
            stats_url = f"{self.api_base_url}/clients/api/{client_id}/stats/"
            async with httpx.AsyncClient(timeout=10.0) as client:
                headers = {"X-Internal-Secret": "your-secret-key-123"}
                response = await client.get(stats_url, headers=headers)
                response.raise_for_status()
                api_data = response.json()
            
            return self.process_client_api_data(api_data)
            
        except Exception as e:
            logger.error(f"Error fetching client dashboard data for {client_id}: {e}")
            return self.get_client_fallback_data()

    def process_admin_api_data(self, api_data: Dict) -> Dict:
        """Process admin API data into dashboard format"""
        global_stats = api_data.get("global_stats", {})
        charts_data = api_data.get("charts_data", {})
        recent_activity = api_data.get("recent_activity", [])

        # FIX: Use prepare_traffic_chart_data to ensure 24 hours of data
        requests_by_hour = charts_data.get("requests_by_hour", [])
        traffic_chart_data = self.prepare_traffic_chart_data(requests_by_hour)
    
        # Admin threat data uses "threat_types" format
        threat_types = charts_data.get("threat_types", [])
        threat_chart_data = {
            "labels": [t.get('reason', 'Unknown') for t in threat_types],
            "series": [t.get('count', 0) for t in threat_types]
        }

        logger.info(f"📊 Admin API - Traffic: {len(traffic_chart_data)} hours, Threats: {len(threat_types)} types")

        return {
            "global_stats": {
                "total_requests": global_stats.get("total_requests", 0),
                "total_blocked": global_stats.get("total_blocked", 0),
                "total_allowed": global_stats.get("total_allowed", 0),
                "requests_per_second": self.calculate_current_rps(),
                "total_clients": global_stats.get("total_clients", 0),
                "total_rules": global_stats.get("total_rules", 0),
                "recent_threats": global_stats.get("recent_threats", 0)
            },
            "charts_data": {
                "traffic_data": traffic_chart_data,
                "threat_data": threat_chart_data,
                "top_ips": charts_data.get("top_blocked_ips", [])
            },
            "recent_activity": recent_activity
        }

    def process_client_api_data(self, api_data: Dict) -> Dict:
        """Process client API data into dashboard format"""
        global_stats = api_data.get("global_stats", {})
        charts_data = api_data.get("charts_data", {})
        recent_activity = api_data.get("recent_activity", [])

        # FIX: Use prepare_traffic_chart_data for client data too
        traffic_data = charts_data.get("traffic_data", [])
        traffic_chart_data = self.prepare_traffic_chart_data(traffic_data)
    
        # Client threat data is already in the right format
        threat_chart_data = charts_data.get("threat_data", {"labels": [], "series": []})

        logger.info(f"📊 Client API - Traffic: {len(traffic_chart_data)} hours, Threats: {len(threat_chart_data.get('labels', []))} types")

        return {
            "global_stats": {
                "total_requests": global_stats.get("total_requests", 0),
                "total_blocked": global_stats.get("total_blocked", 0),
                "total_allowed": global_stats.get("total_allowed", 0),
                "requests_per_second": self.calculate_current_rps(),
                "total_clients": 1,
                "total_rules": global_stats.get("total_rules", 0),
                "recent_threats": global_stats.get("recent_threats", 0)
            },
            "charts_data": {
                "traffic_data": traffic_chart_data,
                "threat_data": threat_chart_data,
                "top_ips": charts_data.get("top_ips", [])
            },
            "recent_activity": recent_activity,
            "client_info": {
                "name": api_data.get("client_name", "Unknown Client")
            }
        }

    def prepare_traffic_chart_data(self, requests_by_hour: List[Dict]) -> List[Dict]:
        """Prepare traffic chart data with 24 hours"""
        logger.info(f"📊 Preparing traffic chart data: {len(requests_by_hour)} hours")
    
        # Ensure we have data for all 24 hours (fill missing hours with zeros)
        chart_data = []
        for hour in range(24):
            # Find data for this hour, or create empty data
            hour_data = next((item for item in requests_by_hour if item.get('hour') == hour), None)
            if hour_data:
                chart_data.append(hour_data)
            else:
                chart_data.append({
                    "hour": hour,
                    "blocked": 0,
                    "allowed": 0,
                    "total": 0
                })
        return chart_data

    def prepare_threat_chart_data(self, threat_types: List[Dict]) -> Dict:
        """Prepare threat distribution chart data"""
        labels = []
        series = []
        
        for threat in threat_types:
            reason = threat.get("reason", "Unknown")
            if not reason or reason == "None":
                reason = "Other"
            labels.append(reason)
            series.append(threat.get("count", 0))
        
        return {
            "labels": labels,
            "series": series
        }

    def get_admin_fallback_data(self) -> Dict:
        """Return fallback data for admin dashboard"""
        return {
            "global_stats": {
                "total_requests": 0,
                "total_blocked": 0,
                "total_allowed": 0,
                "requests_per_second": 0,
                "total_clients": 1,
                "total_rules": 3,
                "recent_threats": 0
            },
            "charts_data": {
                "traffic_data": [],
                "threat_data": {"labels": [], "series": []},
                "top_ips": []
            },
            "recent_activity": []
        }

    def get_client_fallback_data(self) -> Dict:
        """Return fallback data for client dashboard"""
        return {
            "global_stats": {
                "total_requests": 0,
                "total_blocked": 0,
                "total_allowed": 0,
                "requests_per_second": 0,
                "total_clients": 1,
                "total_rules": 0,
                "recent_threats": 0
            },
            "charts_data": {
                "traffic_data": [],
                "threat_data": {"labels": [], "series": []},
                "top_ips": []
            },
            "recent_activity": [],
            "client_info": {
                "name": "Unknown Client"
            }
        }

    def update_request_timestamps(self):
        """Update request timestamps for RPS calculation"""
        now = datetime.now()
        self.request_timestamps.append(now)
        
        self.request_timestamps = [
            ts for ts in self.request_timestamps 
            if (now - ts).total_seconds() < 10
        ]

    def calculate_current_rps(self) -> float:
        """Calculate current requests per second based on recent requests"""
        if not self.request_timestamps:
            return 0.0
        
        now = datetime.now()
        recent_requests = [
            ts for ts in self.request_timestamps 
            if (now - ts).total_seconds() <= 5
        ]
        
        return len(recent_requests) / 5.0
    
    async def broadcast_to_all(self, message: dict):
        """Broadcast message to all connected WebSockets (both admin and client)"""
        if not self.active_connections:
            return
            
        disconnected = []
        
        for connection_info in self.active_connections:
            try:
                await connection_info['websocket'].send_text(json.dumps(message))
                logger.debug(f"📢 Broadcasted {message.get('type')} to {connection_info['type']} dashboard")
            except Exception as e:
                logger.error(f"Error broadcasting to WebSocket: {e}")
                disconnected.append(connection_info)
        
        # Clean up disconnected clients
        for connection_info in disconnected:
            self.disconnect(connection_info['websocket'])

    async def broadcast_to_admins(self, message: dict):
        """Broadcast message only to admin dashboards"""
        admin_connections = [
            conn for conn in self.active_connections 
            if conn.get('type') == 'admin'
        ]
        
        if not admin_connections:
            return
            
        disconnected = []
        
        for connection_info in admin_connections:
            try:
                await connection_info['websocket'].send_text(json.dumps(message))
                logger.debug(f"📢 Broadcasted to admin dashboard")
            except Exception as e:
                logger.error(f"Error broadcasting to admin WebSocket: {e}")
                disconnected.append(connection_info)
        
        for connection_info in disconnected:
            self.disconnect(connection_info['websocket'])

    async def broadcast_to_client(self, client_id: str, message: dict):
        """Broadcast message only to specific client dashboard"""
        client_connections = [
            conn for conn in self.active_connections 
            if conn.get('type') == 'client' and conn.get('client_id') == client_id
        ]
        
        if not client_connections:
            return
            
        disconnected = []
        
        for connection_info in client_connections:
            try:
                await connection_info['websocket'].send_text(json.dumps(message))
                logger.debug(f"🔴 Broadcasted to client {client_id}")
            except Exception as e:
                logger.error(f"Error broadcasting to client WebSocket: {e}")
                disconnected.append(connection_info)
        
        for connection_info in disconnected:
            self.disconnect(connection_info['websocket'])

    async def broadcast_request_event(self, request_data: dict):
        """Broadcast a new request event to both admin and relevant client dashboards"""
        try:
            
            self.update_request_timestamps()
            
            
            admin_dashboard_data = await self.fetch_admin_dashboard_data()
            admin_dashboard_data["global_stats"]["requests_per_second"] = self.calculate_current_rps()
            
            # Create admin event message
            admin_event = {
                "type": "request_event",
                "dashboard_type": "admin",
                "request_data": request_data,
                "global_stats": admin_dashboard_data["global_stats"],
                "charts_data": admin_dashboard_data["charts_data"],
                "timestamp": datetime.now().isoformat()
            }
            
            # Broadcast to all admin dashboards
            await self.broadcast_to_admins(admin_event)
            
            # If this request is for a specific client, also broadcast to that client's dashboard
            client_id = request_data.get('client_id')
            if client_id:
                try:
                    # Fetch client-specific data
                    client_dashboard_data = await self.fetch_client_dashboard_data(client_id)
                    client_dashboard_data["global_stats"]["requests_per_second"] = self.calculate_current_rps()
                    
                    # Create client event message
                    client_event = {
                        "type": "request_event", 
                        "dashboard_type": "client",
                        "request_data": request_data,
                        "global_stats": client_dashboard_data["global_stats"],
                        "charts_data": client_dashboard_data["charts_data"],
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    # Broadcast to this specific client's dashboard
                    await self.broadcast_to_client(client_id, client_event)
                    
                except Exception as e:
                    logger.error(f"Error broadcasting to client {client_id}: {e}")
            
            logger.info(f"🔴 Broadcasted real-time event for {request_data['client_ip']} to both dashboards")
            
        except Exception as e:
            logger.error(f"Error broadcasting request event: {e}")

    async def send_personal_message(self, message: str, websocket: WebSocket):
        """Send message to specific WebSocket"""
        try:
            await websocket.send_text(message)
        except Exception as e:
            logger.error(f"Error sending message to WebSocket: {e}")
            self.disconnect(websocket)

    def get_connection_count(self) -> int:
        """Get number of active connections"""
        return len(self.active_connections)

    def get_admin_connection_count(self) -> int:
        """Get number of active admin connections"""
        return len([conn for conn in self.active_connections if conn.get('type') == 'admin'])

    def get_client_connection_count(self) -> int:
        """Get number of active client connections"""
        return len([conn for conn in self.active_connections if conn.get('type') == 'client'])

    async def health_check(self) -> Dict:
        """Health check method"""
        return {
            "total_connections": self.get_connection_count(),
            "admin_connections": self.get_admin_connection_count(),
            "client_connections": self.get_client_connection_count(),
            "last_api_fetch": self.last_api_fetch.isoformat() if self.last_api_fetch else None,
            "current_rps": self.calculate_current_rps(),
            "cache_updated": bool(self.stats_cache)
        }



class WAFMiddleware:
    """
    Professional WAF Middleware with real-time WebSocket updates to both admin and client dashboards
    """
    
    def __init__(self, websocket_manager):
        self.rule_engine = RuleEngine()
        self.api_client = DjangoAPIClient()
        self.websocket_manager = websocket_manager
        self.logger = logging.getLogger(__name__)
    
    async def process_request(self, request: Request, call_next):
        """
        Process incoming request through WAF pipeline with real-time updates to both dashboards
        """
        client_host = request.headers.get("host", "").split(':')[0]
        client_ip = self._get_client_ip(request)
        
        self.logger.info(f"Processing request: {request.method} {request.url.path} from {client_ip} to {client_host}")
        
        # Skip WAF for health checks and internal endpoints
        if self._should_skip_waf(request):
            response = await call_next(request)
            return response
        
        # Get client configuration
        client_config = await self.api_client.get_client_configuration(client_host)
        
        if not client_config or client_config.get('error') == 'not_found':
            self.logger.warning(f"No WAF configuration found for host: {client_host}")
            return JSONResponse(
                status_code=404,
                content={
                    'error': 'Service not configured',
                    'detail': f'No WAF configuration found for {client_host}'
                }
            )
        
        # Perform WAF analysis
        waf_result = await self._analyze_request(request, client_config, client_ip)
        
        # Send real-time update via WebSocket to both dashboards (non-blocking)
        asyncio.create_task(
            self._send_real_time_update(request, client_config, client_ip, waf_result)
        )
        
        if waf_result.blocked:
            return await self._handle_blocked_request(request, waf_result, client_config, client_ip)
        else:
            return await self._handle_allowed_request(request, client_config, client_ip, call_next)

    def _get_client_ip(self, request: Request) -> str:
        """
        Extract real client IP address from headers.
        This gets the actual request sender's IP address, not Docker internal IPs.
        """
        # Common headers that contain real client IP in proxy environments
        ip_headers = [
            'x-real-ip',           # Nginx
            'x-forwarded-for',     # Most proxies (including Docker)
            'x-forwarded',
            'forwarded-for', 
            'forwarded',
            'x-cluster-client-ip',
            'proxy-client-ip',
            'true-client-ip',
            'cf-connecting-ip',    # Cloudflare
        ]
        
        # Check each header in order
        for header in ip_headers:
            ip = request.headers.get(header)
            if ip:
                # x-forwarded-for can contain multiple IPs (client, proxy1, proxy2)
                if ',' in ip:
                    ip = ip.split(',')[0].strip()
                
                # Validate IP format
                if self._is_valid_ip(ip):
                    self.logger.info(f"Found real client IP {ip} in header {header}")
                    return ip
        
        # Fallback to direct connection IP
        direct_ip = request.client.host if request.client else "0.0.0.0"
        self.logger.info(f"Using direct connection IP: {direct_ip}")
        return direct_ip

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal"""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False

    def _is_ip_in_range(self, ip: str, ip_range: str) -> bool:
        """Check if IP is in CIDR range"""
        import ipaddress
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj in network
        except ValueError:
            return False

    def _should_skip_waf(self, request: Request) -> bool:
        skip_paths = ['/health', '/metrics', '/docs', '/redoc', '/ws', '/static/','/verify-recaptcha', '/favicon.ico' ]
        return any(request.url.path.startswith(path) for path in skip_paths)
    
    async def _analyze_request(self, request: Request, client_config: dict, client_ip: str) -> WAFResult:
        """Analyze request against WAF rules including country and IP blocking"""
        try:
            # NEW: Check IP blacklist first
            ip_block_result = self._check_ip_blacklist(client_ip, client_config)
            if ip_block_result.blocked:
                return ip_block_result
            
            # NEW: Check country blocking
            country_block_result = await self._check_country_blocking(client_ip, client_config)
            if country_block_result.blocked:
                return country_block_result
            
            # Existing WAF rules check
            request_context = await self._extract_request_context(request, client_ip)
            return self.rule_engine.check_request(
                request_context, 
                client_config.get("rules", [])
            )
        except Exception as e:
            self.logger.error(f"Error during WAF analysis: {e}")
            return WAFResult(blocked=False, reason="Analysis error")

    def _check_ip_blacklist(self, client_ip: str, client_config: dict) -> WAFResult:
        """NEW: Check if IP is in blacklist"""
        if not client_config.get('enable_ip_blacklist', False):
            return WAFResult(blocked=False)
        
        blacklisted_ips = client_config.get('ip_blacklist', [])
        
        # Check exact IP match
        if client_ip in blacklisted_ips:
            return WAFResult(blocked=True, reason=f"IP {client_ip} is blacklisted")
        
        # Check IP range (CIDR) - e.g., "192.168.1.0/24"
        for ip_range in blacklisted_ips:
            if '/' in ip_range and self._is_ip_in_range(client_ip, ip_range):
                return WAFResult(blocked=True, reason=f"IP {client_ip} is in blacklisted range {ip_range}")
        
        return WAFResult(blocked=False)

    async def _check_country_blocking(self, client_ip: str, client_config: dict) -> WAFResult:
        """NEW: Check if country is blocked"""
        if not client_config.get('enable_country_blocking', False):
            return WAFResult(blocked=False)
        
        # Skip private IPs
        if self._is_private_ip(client_ip):
            return WAFResult(blocked=False)
        
        # Get geolocation data via API call to Django
        try:
            country_data = await self.api_client.get_ip_geolocation(client_ip)
            
            if not country_data or 'country_code' not in country_data:
                return WAFResult(blocked=False)
            
            country_code = country_data['country_code']
            
            blocked_countries = client_config.get('blocked_countries', [])
            allowed_countries = client_config.get('allowed_countries', [])
            
            # Allow list mode (only allowed countries can access)
            if allowed_countries:
                if country_code not in allowed_countries:
                    return WAFResult(blocked=True, reason=f"Country {country_code} not in allowed list")
            
            # Block list mode (block specific countries)
            elif blocked_countries:
                if country_code in blocked_countries:
                    return WAFResult(blocked=True, reason=f"Country {country_code} is blocked")
            
            return WAFResult(blocked=False)
            
        except Exception as e:
            self.logger.error(f"Error checking country blocking: {e}")
            return WAFResult(blocked=False)
    
    async def _extract_request_context(self, request: Request, client_ip: str) -> dict:
        """Extract request context for WAF analysis"""
        body = ""
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                body_bytes = await request.body()
                body = body_bytes.decode('utf-8', errors='ignore')
            except Exception as e:
                self.logger.warning(f"Error reading request body: {e}")
        
        return {
            "method": request.method,
            "path": str(request.url.path),
            "query_string": str(request.query_params),
            "headers": dict(request.headers),
            "body": body,
            "client_ip": client_ip,  
            "user_agent": request.headers.get("user-agent", ""),
        }

    async def _handle_blocked_request(self, request: Request, waf_result: WAFResult, 
                                client_config: dict, client_ip: str) -> Response:
        self.logger.warning(f"Request blocked: {waf_result.reason} for {client_ip}")
    
        # Log the event
        country_code = ""
        try:
            country_data = await self.api_client.get_ip_geolocation(client_ip)
            country_code = country_data.get('country_code', '') if country_data else ""
        except Exception as e:
            self.logger.error(f"Error getting geolocation for logging: {e}")
    
        await self.api_client.log_security_event({
            "client_host": request.headers.get("host", ""),
            "ip_address": client_ip,
            "country_code": country_code,
            "request_path": request.url.path,
            "user_agent": request.headers.get("user-agent", ""),
            "reason": waf_result.reason,
            "method": request.method,
            "blocked": True,
        })

    async def _handle_allowed_request(self, request: Request, client_config: dict, 
                                    client_ip: str, call_next) -> Response:
        """Handle allowed request"""
        self.logger.debug(f"Request allowed from {client_ip} to {client_config.get('client_name')}")
        
        target_url = client_config.get('target_url')
        if not target_url:
            return JSONResponse(
                status_code=500,
                content={'error': 'Target URL not configured'}
            )
        
        return await self._forward_to_backend(request, target_url)
    
    async def _forward_to_backend(self, request: Request, target_url: str) -> Response:
        """Forward request to backend service"""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                url = f"{target_url.rstrip('/')}{request.url.path}"
                if request.url.query:
                    url += f"?{request.url.query}"
                
                headers = dict(request.headers)
                headers.pop("host", None)
                headers.pop("content-length", None)
                
                if request.method in ["POST", "PUT", "PATCH"]:
                    body = await request.body()
                    response = await client.request(
                        request.method, url, headers=headers, content=body
                    )
                else:
                    response = await client.request(
                        request.method, url, headers=headers
                    )
                
                return Response(
                    content=response.content,
                    status_code=response.status_code,
                    headers=dict(response.headers)
                )
                
        except httpx.ConnectError:
            return Response(content=b"Backend service unavailable", status_code=503)
        except Exception as e:
            self.logger.error(f"Error forwarding request: {e}")
            return Response(content=b"Internal server error", status_code=500)

    async def _send_real_time_update(self, request: Request, client_config: dict, 
                                   client_ip: str, waf_result: WAFResult):
        """Send real-time update to WebSocket dashboards"""
        try:
            # Prepare request data with client ID for client dashboard targeting
            request_data = {
                "client_ip": client_ip,  # This now contains the REAL request sender IP
                "client_name": client_config.get('client_name', 'unknown'),
                "client_id": str(client_config.get('id')),  # Convert to string for consistency
                "client_host": client_config.get('host'),
                "path": request.url.path,
                "method": request.method,
                "user_agent": request.headers.get("user-agent", ""),
                "waf_blocked": waf_result.blocked,
                "threat_type": waf_result.reason if waf_result.blocked else "allowed",
                "timestamp": datetime.now().isoformat(),
                "rule_id": waf_result.rule_id
            }
            
            self.logger.info(f"📡 Broadcasting real-time update to both dashboards for {request_data['client_name']} from IP {client_ip}")
            
            # Broadcast to both admin and relevant client dashboard
            await self.websocket_manager.broadcast_request_event(request_data)
            
        except Exception as e:
            self.logger.error(f"Error sending real-time update: {e}")

    async def _handle_recaptcha(self, config_value: str, data: str, client_ip: str, user_agent: str) -> WAFResult:
        """Handle reCAPTCHA challenge for suspicious traffic"""
        if self._is_recaptcha_solved(client_ip):
            return WAFResult(blocked=False)
        return WAFResult(blocked=True, reason="reCAPTCHA required", confidence=0.5)

    def _is_recaptcha_solved(self, client_ip: str) -> bool:
        """Check if reCAPTCHA was solved recently (TTL: 5 minutes)"""
        # This would typically check Redis or another cache
        # For now, return False to always require reCAPTCHA
        return False