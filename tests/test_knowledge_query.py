import json

from fastapi.testclient import TestClient

from egis_agentkit_mock.app import create_app


def login(client):
    response = client.post("/auth/login", json={"user_id": "luyang", "password": "123"})
    assert response.status_code == 200
    return response.json()["access_token"]


def test_knowledge_query_streams_document_and_wiki_results_with_references():
    with TestClient(create_app()) as client:
        token = login(client)
        with client.stream(
            "POST",
            "/knowledge/query",
            headers={"Authorization": f"Bearer {token}", "Accept": "text/event-stream"},
            json={"query": "企业年金缴费要核对哪些材料？", "topK": 5, "threshold": 0.5},
        ) as response:
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("text/event-stream")
            frames = []
            event = None
            for line in response.iter_lines():
                if line.startswith("event: "):
                    event = line.removeprefix("event: ")
                elif line.startswith("data: "):
                    frames.append((event, json.loads(line.removeprefix("data: "))))

    stages = [data for name, data in frames if name == "stage"]
    assert {stage["source"] for stage in stages} == {"doc", "wiki"}
    assert frames[0][0] == "stage"
    results = [data for name, data in frames if name == "result"]
    assert [result["source"] for result in results] == ["doc", "wiki"]
    assert all(
        result["status"] == "ok"
        and result["answer"]
        and result["items"][0]["doc_id"]
        and result["items"][0]["node_id"]
        and result["items"][0]["full"]
        for result in results
    )
    assert len({frame["request_id"] for frame in [*stages, *results]}) == 1
    event, final = frames[-1]
    assert event == "done"
    assert final["sources"] == ["doc", "wiki"]
    assert final["status"] == "ok"


def test_knowledge_query_rejects_missing_and_untrusted_bearers():
    with TestClient(create_app()) as other_issuer:
        foreign_token = login(other_issuer)
    with TestClient(create_app()) as client:
        assert (
            client.post("/knowledge/query", json={"query": "缴费"}).status_code == 401
        )
        rejected = client.post(
            "/knowledge/query",
            headers={"Authorization": f"Bearer {foreign_token}"},
            json={"query": "缴费"},
        )
        assert rejected.status_code == 401
