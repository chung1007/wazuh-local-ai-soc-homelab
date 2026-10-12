from __future__ import annotations

import os
import time
import sys
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

def manager_debug(message: str) -> None:
    log_path = BASE_DIR / "manager-debug.log"
    with log_path.open("a", encoding="utf-8") as log:
        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n")
    log_path.chmod(0o600)

def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def clamp(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(value, maximum))


WAZUH_API_URL = os.environ["WAZUH_API_URL"].rstrip("/")
WAZUH_API_USER = os.environ["WAZUH_API_USER"]
WAZUH_API_PASS = os.environ["WAZUH_API_PASS"]

WAZUH_INDEXER_URL = os.environ["WAZUH_INDEXER_URL"].rstrip("/")
WAZUH_INDEXER_USER = os.environ["WAZUH_INDEXER_USER"]
WAZUH_INDEXER_PASS = os.environ["WAZUH_INDEXER_PASS"]

ALERT_INDEX = os.getenv("WAZUH_ALERT_INDEX", "wazuh-alerts-*")
VULN_INDEX = os.getenv(
    "WAZUH_VULN_INDEX",
    "wazuh-states-vulnerabilities-*",
)

VERIFY_SSL = env_bool("VERIFY_SSL", False)
MCP_HOST = os.getenv("MCP_HOST", "127.0.0.1")
MCP_PORT = int(os.getenv("MCP_PORT", "8000"))

mcp = FastMCP(
    "Wazuh Local SOC Tools",
    host=MCP_HOST,
    port=MCP_PORT,
)

_manager_token: str | None = None
_manager_token_created = 0.0
TOKEN_REFRESH_SECONDS = 780


# async def get_manager_token() -> str:
#     """Get and cache a Wazuh Manager API JWT."""
#     global _manager_token, _manager_token_created

#     if (
#         _manager_token
#         and time.monotonic() - _manager_token_created
#         < TOKEN_REFRESH_SECONDS
#     ):
#         return _manager_token

#     async with httpx.AsyncClient(
#         verify=VERIFY_SSL,
#         timeout=20.0,
#     ) as client:
#         response = await client.post(
#             f"{WAZUH_API_URL}/security/user/authenticate?raw=true",
#             auth=httpx.BasicAuth(WAZUH_API_USER, WAZUH_API_PASS),
#         )
#         response.raise_for_status()

#     _manager_token = response.text.strip().strip('"')
#     _manager_token_created = time.monotonic()
#     return _manager_token

async def get_manager_token() -> str:
    """Get and cache a Wazuh Manager API JWT."""
    global _manager_token, _manager_token_created

    manager_debug("get_manager_token called")

    if (
        _manager_token
        and time.monotonic() - _manager_token_created
        < TOKEN_REFRESH_SECONDS
    ):
        manager_debug("Using cached token")
        return _manager_token

    url = f"{WAZUH_API_URL}/security/user/authenticate?raw=true"
    destination = httpx.URL(url)
    manager_debug(
        "Attempting authentication at "
        f"{destination.scheme}://{destination.host}:{destination.port}"
    )

    try:
        async with httpx.AsyncClient(
            verify=VERIFY_SSL,
            timeout=20.0,
            trust_env=False,
        ) as client:
            response = await client.post(
                url,
                auth=httpx.BasicAuth(WAZUH_API_USER, WAZUH_API_PASS),
            )
            response.raise_for_status()

    except httpx.RequestError as exc:
        manager_debug(
            f"Authentication request failed: {type(exc).__name__}: {exc}"
        )
        raise

    except httpx.HTTPStatusError as exc:
        manager_debug(
            f"Authentication returned HTTP {exc.response.status_code}"
        )
        raise

    manager_debug(f"Authentication returned HTTP {response.status_code}")

    _manager_token = response.text.strip().strip('"')
    _manager_token_created = time.monotonic()
    return _manager_token

async def manager_get(
    path: str,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Send an authenticated GET request to the Manager API."""
    global _manager_token

    token = await get_manager_token()

    async with httpx.AsyncClient(
        verify=VERIFY_SSL,
        timeout=30.0,
        trust_env=False,
    ) as client:
        response = await client.get(
            f"{WAZUH_API_URL}{path}",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )

        if response.status_code == 401:
            _manager_token = None
            token = await get_manager_token()
            response = await client.get(
                f"{WAZUH_API_URL}{path}",
                params=params,
                headers={"Authorization": f"Bearer {token}"},
            )

        response.raise_for_status()
        return response.json()


async def indexer_search(
    index: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    """Search a Wazuh Indexer index through the SSH tunnel."""
    async with httpx.AsyncClient(
        verify=VERIFY_SSL,
        timeout=45.0,
        trust_env=False,
    ) as client:
        response = await client.post(
            f"{WAZUH_INDEXER_URL}/{index}/_search",
            auth=httpx.BasicAuth(
                WAZUH_INDEXER_USER,
                WAZUH_INDEXER_PASS,
            ),
            json=body,
        )
        response.raise_for_status()
        return response.json()


def format_hits(response: dict[str, Any]) -> dict[str, Any]:
    hits_section = response.get("hits", {})
    total = hits_section.get("total", 0)

    if isinstance(total, dict):
        total_value = total.get("value", 0)
        total_relation = total.get("relation", "eq")
    else:
        total_value = total
        total_relation = "eq"

    results = [
        {
            "index": hit.get("_index"),
            "id": hit.get("_id"),
            "score": hit.get("_score"),
            "source": hit.get("_source", {}),
        }
        for hit in hits_section.get("hits", [])
    ]

    return {
        "total": total_value,
        "total_relation": total_relation,
        "returned": len(results),
        "results": results,
    }


@mcp.tool()
async def list_agents(
    status: str = "all",
    limit: int = 100,
) -> dict[str, Any]:
    """List Wazuh agents, optionally filtered by connection status."""
    limit = clamp(limit, 1, 500)
    params: dict[str, Any] = {"limit": limit, "sort": "+name"}

    if status.lower() != "all":
        params["status"] = status.lower()

    response = await manager_get("/agents", params=params)
    data = response.get("data", {})

    return {
        "total": data.get("total_affected_items", 0),
        "agents": data.get("affected_items", []),
        "failed_items": data.get("failed_items", []),
    }


@mcp.tool()
async def recent_alerts(
    minutes: int = 15,
    limit: int = 50,
    agent_name: str | None = None,
    min_level: int = 0,
) -> dict[str, Any]:
    """Retrieve recent Wazuh alerts with optional agent and level filters."""
    minutes = clamp(minutes, 1, 1440)
    limit = clamp(limit, 1, 200)
    min_level = clamp(min_level, 0, 15)

    filters: list[dict[str, Any]] = [
        {
            "range": {
                "timestamp": {
                    "gte": f"now-{minutes}m",
                    "lte": "now",
                }
            }
        },
        {"range": {"rule.level": {"gte": min_level}}},
    ]

    if agent_name:
        filters.append(
            {"match_phrase": {"agent.name": agent_name}}
        )

    body = {
        "size": limit,
        "track_total_hits": True,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": filters}},
        "_source": [
            "timestamp",
            "agent.id",
            "agent.name",
            "agent.ip",
            "rule.id",
            "rule.level",
            "rule.description",
            "rule.groups",
            "rule.mitre",
            "decoder.name",
            "location",
            "full_log",
            "data",
        ],
    }

    return format_hits(await indexer_search(ALERT_INDEX, body))


@mcp.tool()
async def search_alerts(
    query: str,
    minutes: int = 60,
    limit: int = 50,
    agent_name: str | None = None,
    min_level: int = 0,
) -> dict[str, Any]:
    """Search alert descriptions, logs, data fields, agents, and locations."""
    if not query.strip():
        raise ValueError("query cannot be empty")

    minutes = clamp(minutes, 1, 10080)
    limit = clamp(limit, 1, 200)
    min_level = clamp(min_level, 0, 15)

    filters: list[dict[str, Any]] = [
        {
            "range": {
                "timestamp": {
                    "gte": f"now-{minutes}m",
                    "lte": "now",
                }
            }
        },
        {"range": {"rule.level": {"gte": min_level}}},
    ]

    if agent_name:
        filters.append(
            {"match_phrase": {"agent.name": agent_name}}
        )

    body = {
        "size": limit,
        "track_total_hits": True,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {
                        "simple_query_string": {
                            "query": query,
                            "fields": [
                                "rule.description",
                                "full_log",
                                "data.srcip",
                                "data.srcport",
                                "agent.name",
                                "location",
                                "decoder.name",
                                "rule.groups",
                            ],
                            "default_operator": "and",
                        }
                    }
                ],
                "filter": filters,
            }
        },
        "_source": [
            "timestamp",
            "agent.id",
            "agent.name",
            "agent.ip",
            "rule.id",
            "rule.level",
            "rule.description",
            "rule.groups",
            "rule.mitre",
            "decoder.name",
            "location",
            "full_log",
            "data",
        ],
    }

    return format_hits(await indexer_search(ALERT_INDEX, body))


@mcp.tool()
async def vulnerabilities(
    agent_id: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Retrieve vulnerability findings by agent, severity, CVE, or package."""
    limit = clamp(limit, 1, 500)
    filters: list[dict[str, Any]] = []
    must: list[dict[str, Any]] = []

    if agent_id:
        filters.append({"term": {"agent.id": agent_id}})

    if severity:
        filters.append(
            {"match_phrase": {"vulnerability.severity": severity}}
        )

    if search:
        must.append(
            {
                "simple_query_string": {
                    "query": search,
                    "fields": [
                        "vulnerability.id",
                        "vulnerability.description",
                        "package.name",
                        "package.version",
                        "agent.name",
                    ],
                    "default_operator": "and",
                }
            }
        )

    query_body: dict[str, Any]
    if must or filters:
        query_body = {"bool": {"must": must, "filter": filters}}
    else:
        query_body = {"match_all": {}}

    body = {
        "size": limit,
        "track_total_hits": True,
        "query": query_body,
        "_source": [
            "agent.id",
            "agent.name",
            "host.os",
            "package.name",
            "package.version",
            "package.architecture",
            "vulnerability.id",
            "vulnerability.severity",
            "vulnerability.description",
            "vulnerability.status",
            "vulnerability.detected_at",
            "vulnerability.published_at",
            "vulnerability.reference",
            "vulnerability.score",
        ],
    }

    return format_hits(await indexer_search(VULN_INDEX, body))


@mcp.tool()
async def agent_health(agent_id: str) -> dict[str, Any]:
    """Check an agent's connection state and its five latest alerts."""
    response = await manager_get(
        "/agents",
        params={"agents_list": agent_id, "limit": 1},
    )
    agents = response.get("data", {}).get("affected_items", [])

    if not agents:
        return {
            "found": False,
            "agent_id": agent_id,
            "health": "unknown",
            "message": "No matching Wazuh agent was found.",
        }

    agent = agents[0]
    status = str(agent.get("status", "unknown")).lower()

    if status == "active":
        health = "healthy"
    elif status in {"disconnected", "never_connected"}:
        health = "unhealthy"
    else:
        health = "attention_required"

    body = {
        "size": 5,
        "track_total_hits": True,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"agent.id": agent_id}},
                    {
                        "range": {
                            "timestamp": {
                                "gte": "now-24h",
                                "lte": "now",
                            }
                        }
                    },
                ]
            }
        },
        "_source": [
            "timestamp",
            "rule.id",
            "rule.level",
            "rule.description",
            "location",
        ],
    }

    alerts = format_hits(await indexer_search(ALERT_INDEX, body))

    return {
        "found": True,
        "health": health,
        "agent": agent,
        "latest_alerts": alerts,
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
