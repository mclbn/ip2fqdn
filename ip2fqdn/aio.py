import asyncio

_DONE = object()


async def stream(items, func, workers):
    queue = asyncio.Queue()
    iterator = iter(items)

    async def worker():
        try:
            for item in iterator:
                try:
                    result = await func(item)
                except Exception as error:
                    result = error
                queue.put_nowait(result)
        finally:
            queue.put_nowait(_DONE)

    tasks = [asyncio.create_task(worker()) for _ in range(max(1, workers))]
    finished = 0
    try:
        while finished < len(tasks):
            result = await queue.get()
            if result is _DONE:
                finished += 1
                continue
            yield result
    finally:
        for task in tasks:
            task.cancel()
