from fastapi import FastAPI, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import pandas as pd
import numpy as np
from scipy.linalg import svd
import io
import os

app = FastAPI(title="SpectralShield AI Defense Platform")

# Agar static folder ho toh mount karo, warna root se serve karo
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

def run_spectral_defense(X, y, target_class=0, clean_ratio=0.08):
    class_indices = np.where(y == target_class)[0]
    X_target = X[class_indices]
    
    mean_vec = np.mean(X_target, axis=0)
    centered_data = X_target - mean_vec
    
    _, _, Vt = svd(centered_data, full_matrices=False)
    top_singular_vec = Vt[0]
    
    scores = np.square(np.dot(centered_data, top_singular_vec))
    k = max(1, int(len(class_indices) * clean_ratio))
    quarantined_subset = np.argsort(scores)[::-1][:k]
    
    quarantined_indices = class_indices[quarantined_subset].tolist()
    sanitized_indices = np.setdiff1d(np.arange(len(X)), quarantined_indices).tolist()
    
    return sanitized_indices, quarantined_indices

@app.get("/")
def home():
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    return FileResponse("static/index.html")

@app.get("/manifest.json")
def get_manifest():
    if os.path.exists("manifest.json"):
        return FileResponse("manifest.json")
    return FileResponse("static/manifest.json")

@app.get("/sw.js")
def get_sw():
    if os.path.exists("sw.js"):
        return FileResponse("sw.js")
    return FileResponse("static/sw.js")

@app.post("/audit-csv")
async def audit_dataset(file: UploadFile = File(...)):
    contents = await file.read()
    df = pd.read_csv(io.BytesIO(contents))
    
    X = df.iloc[:, :-1].values
    y = df.iloc[:, -1].values
    
    total_records = len(df)
    clean_idx, quarantined_idx = run_spectral_defense(X, y)
    
    hygiene_score = round(((total_records - len(quarantined_idx)) / total_records) * 100, 2)
    
    return {
        "filename": file.filename,
        "total_records": total_records,
        "quarantined_count": len(quarantined_idx),
        "quarantined_indices": quarantined_idx[:30],
        "hygiene_score": f"{hygiene_score}%",
        "status": "Verified & Sanitized"
    }
