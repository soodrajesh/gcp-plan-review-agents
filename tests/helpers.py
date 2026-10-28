import json
from importlib import resources

from planreview.llm import LLM, LLMResult


def sample(name: str) -> dict:
    return json.loads((resources.files("planreview") / "samples" / f"{name}.json").read_text())


def rc(rtype, name, actions=("create",), after=None, before=None):
    return {
        "address": f"{rtype}.{name}",
        "mode": "managed",
        "type": rtype,
        "name": name,
        "change": {"actions": list(actions), "before": before, "after": after},
    }


def plan(*changes):
    return {"resource_changes": list(changes)}


class ScriptedLLM(LLM):
    """Returns whatever the test says, to model hostile or broken providers."""

    name, model = "scripted", "scripted-1"

    def __init__(self, reply=None, *, raises=None, delay=0.0):
        self.reply, self.raises, self.delay, self.calls = reply, raises, delay, 0

    async def complete_json(self, system, user, max_tokens=1200):
        import asyncio

        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.raises:
            raise self.raises
        r = self.reply(json.loads(user)) if callable(self.reply) else self.reply
        return LLMResult(r if isinstance(r, str) else json.dumps(r), 100, 50, 0.001)
