from __future__ import annotations

import asyncio

from crewai import Agent, Crew, LLM, Task

from agent_control_specification import InterventionPoint, guard_crewai_crew

from _common import assert_blocked, control


async def main() -> None:
    llm = LLM(model="gpt-4o", api_key="not-used-pre-agent-block")
    agent = Agent(role="tester", goal="answer locally", backstory="acs real package check", llm=llm)
    task = Task(description="Say {topic}", expected_output="a short answer", agent=agent)
    guarded = guard_crewai_crew(Crew(agents=[agent], tasks=[task], verbose=False, tracing=False), control=control())

    try:
        await guarded.kickoff(inputs={"topic": "BLOCKME"})
    except BaseException as exc:
        assert_blocked(exc, InterventionPoint.INPUT)
    else:
        raise AssertionError("CrewAI BLOCKME input was not blocked")


if __name__ == "__main__":
    asyncio.run(main())
