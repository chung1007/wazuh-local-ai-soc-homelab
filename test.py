import asyncio
from server import ALERT_INDEX, indexer_search, format_hits

async def main():
    body = {
            "size": 1,
            "query": {"match_all": {}},
            "sort": [{"timestamp": {"order": "desc"}}],
        }
    index_return = await indexer_search(ALERT_INDEX, body)
    print("Index Search Result: ", index_return)
    formatted_result = format_hits(index_return)
    print("Formatted Result: ", formatted_result)

asyncio.run(main())