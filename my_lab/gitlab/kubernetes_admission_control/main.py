"""
FastAPI inference service for the supply-chain demo.

A deliberately small "AI" workload: it serves text embeddings and semantic
similarity using a sentence-transformers model. Small enough to build and run on
Minikube, but with a real ML dependency tree so the Trivy scan and Syft SBOM
stages have genuine material to analyse.

The model is baked into the image at build time and loaded once at startup, so
the running container needs no network access and can run on a read-only root
filesystem (see Dockerfile and the deployment securityContext).
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel, Field
from sentence_transformers import SentenceTransformer, util

# Model is configurable but defaults to the small, RAG-standard MiniLM encoder.
MODEL_NAME = os.getenv("MODEL_NAME", "all-MiniLM-L6-v2")

# Loaded model lives here; populated once at startup.
state: dict[str, SentenceTransformer] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load the model a single time when the process starts, never per request.
    state["model"] = SentenceTransformer(MODEL_NAME)
    yield
    state.clear()


app = FastAPI(
    title="Embedding & Similarity Service",
    description="Small sentence-transformers workload for the DevSecOps supply-chain demo.",
    version="1.0.0",
    lifespan=lifespan,
)


class EmbedRequest(BaseModel):
    texts: list[str] = Field(..., min_length=1, description="One or more texts to embed.")


class EmbedResponse(BaseModel):
    model: str
    dimensions: int
    embeddings: list[list[float]]


class SimilarityRequest(BaseModel):
    text_a: str = Field(..., min_length=1)
    text_b: str = Field(..., min_length=1)


class SimilarityResponse(BaseModel):
    model: str
    text_a: str
    text_b: str
    cosine_similarity: float


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness/readiness probe target. Cheap and does not touch the model."""
    return {"status": "ok"}


@app.get("/")
def root() -> dict[str, object]:
    return {
        "service": "embedding-similarity",
        "model": MODEL_NAME,
        "endpoints": ["/health", "/embed", "/similarity", "/docs"],
    }


@app.post("/embed", response_model=EmbedResponse)
def embed(req: EmbedRequest) -> EmbedResponse:
    """Return an embedding vector for each input text."""
    model = state["model"]
    vectors = model.encode(req.texts, convert_to_numpy=True)
    return EmbedResponse(
        model=MODEL_NAME,
        dimensions=int(vectors.shape[1]),
        embeddings=vectors.tolist(),
    )


@app.post("/similarity", response_model=SimilarityResponse)
def similarity(req: SimilarityRequest) -> SimilarityResponse:
    """Return the cosine similarity (0..1) between two texts."""
    model = state["model"]
    emb = model.encode([req.text_a, req.text_b], convert_to_numpy=True)
    score = float(util.cos_sim(emb[0], emb[1]).item())
    return SimilarityResponse(
        model=MODEL_NAME,
        text_a=req.text_a,
        text_b=req.text_b,
        cosine_similarity=round(score, 4),
    )