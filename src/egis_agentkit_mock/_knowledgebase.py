"""知识库混合检索的固定 SSE 演示数据。"""

import asyncio
import json
from collections.abc import AsyncIterator
from time import perf_counter
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

_SAMPLES = {
    "doc": {
        "answer": "演示结果：核对当期缴费清单、缴费基数和生效日期。",
        "item": {
            "rank": 1,
            "score": 0.94,
            "kb": "年金业务演示库",
            "kb_id": "mock-annuity",
            "doc": "企业年金缴费方案（演示）",
            "doc_id": "mock-contribution-plan",
            "node_id": "mock-contribution-plan-review",
            "parent_id": "mock-contribution-plan",
            "ver": "v1",
            "cpath": "企业年金缴费方案/缴费清单",
            "chunk": "mock-doc-1",
            "match": "核对当期清单、基数及生效日期。",
            "full": "提交缴费前，应逐项核对当期缴费清单、缴费基数及生效日期。",
        },
    },
    "wiki": {
        "answer": "演示结果：核对参保人员名单和本期变更记录后，提交复核。",
        "item": {
            "rank": 1,
            "score": 0.89,
            "kb": "年金业务演示库",
            "kb_id": "mock-annuity",
            "doc": "缴费核对操作指引（演示）",
            "doc_id": "mock-contribution-guide",
            "node_id": "mock-contribution-guide-changes",
            "parent_id": "mock-contribution-guide",
            "ver": "v1",
            "cpath": "缴费核对操作指引/人员变更",
            "chunk": "mock-wiki-1",
            "match": "对照人员名单与变更记录。",
            "full": "逐项比对参保人员名单和本期变更记录，确认完成后提交复核。",
        },
    },
}


class KnowledgeQueryRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    query: str = Field(min_length=1)
    topK: int = Field(default=5, ge=1, le=50)
    threshold: float = Field(default=0.5, ge=0, le=1)
    scope: dict[str, list[str]] | None = None


def _frame(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


async def stream_knowledge_query(body: KnowledgeQueryRequest) -> AsyncIterator[str]:
    request_id = uuid4().hex
    started_at = perf_counter()
    yield ": ping\n\n"
    for source, label in (("doc", "文档"), ("wiki", "Wiki")):
        yield _frame(
            "stage",
            {
                "source": source,
                "name": "recall",
                "phase": "start",
                "message": f"正在检索{label}…",
                "request_id": request_id,
            },
        )
    for source, sample in _SAMPLES.items():
        await asyncio.sleep(0.25)
        item = sample["item"]
        yield _frame(
            "result",
            {
                "status": "ok",
                "source": source,
                "answer": sample["answer"],
                "items": [item],
                "total": 1,
                "high_relevance": int(item["score"] >= body.threshold),
                "cost_ms": round((perf_counter() - started_at) * 1000, 1),
                "request_id": request_id,
            },
        )
    yield _frame(
        "done",
        {
            "status": "ok",
            "cost_ms": round((perf_counter() - started_at) * 1000, 1),
            "sources": list(_SAMPLES),
        },
    )
