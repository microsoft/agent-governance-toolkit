# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tool composition for ATR.

Provides mechanisms for chaining and composing tools declaratively.
"""

from __future__ import annotations

import asyncio
import inspect
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    TypeVar,
    Union,
)

T = TypeVar("T")
U = TypeVar("U")


class CompositionError(Exception):
    """Error during tool composition."""

    pass


class ExecutionMode(str, Enum):
    """How to execute composed tools."""

    SEQUENTIAL = "sequential"  # One after another
    PARALLEL = "parallel"  # All at once
    CONDITIONAL = "conditional"  # Based on condition


@dataclass
class ToolResult(Generic[T]):
    """Result from a composed tool execution.

    Attributes:
        value: The result value.
        success: Whether execution succeeded.
        error: Error if execution failed.
        tool_name: Name of the tool that produced this result.
        metadata: Additional execution metadata.
    """

    value: Optional[T] = None
    success: bool = True
    error: Optional[Exception] = None
    tool_name: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def ok(cls, value: T, tool_name: str = "", **metadata) -> "ToolResult[T]":
        """Create a successful result."""
        return cls(value=value, success=True, tool_name=tool_name, metadata=metadata)

    @classmethod
    def fail(cls, error: Exception, tool_name: str = "", **metadata) -> "ToolResult[T]":
        """Create a failed result."""
        return cls(error=error, success=False, tool_name=tool_name, metadata=metadata)

    def map(self, func: Callable[[T], U]) -> "ToolResult[U]":
        """Transform the result value if successful."""
        if not self.success:
            return ToolResult(
                error=self.error, success=False, tool_name=self.tool_name, metadata=self.metadata
            )
        try:
            new_value = func(self.value)
            return ToolResult.ok(new_value, self.tool_name, **self.metadata)
        except Exception as e:
            return ToolResult.fail(e, self.tool_name, **self.metadata)

    def flat_map(self, func: Callable[[T], "ToolResult[U]"]) -> "ToolResult[U]":
        """Chain with another operation that returns a ToolResult."""
        if not self.success:
            return ToolResult(
                error=self.error, success=False, tool_name=self.tool_name, metadata=self.metadata
            )
        try:
            return func(self.value)
        except Exception as e:
            return ToolResult.fail(e, self.tool_name, **self.metadata)

    def unwrap(self) -> T:
        """Get the value or raise if failed."""
        if not self.success:
            raise self.error or CompositionError("Result is not successful")
        return self.value

    def unwrap_or(self, default: T) -> T:
        """Get the value or return default if failed."""
        if not self.success:
            return default
        return self.value


class ToolStep(ABC, Generic[T]):
    """Abstract base for a step in a tool composition."""

    @abstractmethod
    def execute(self, input_data: Any, context: Dict[str, Any]) -> ToolResult[T]:
        """Execute this step synchronously."""
        pass

    @abstractmethod
    async def execute_async(self, input_data: Any, context: Dict[str, Any]) -> ToolResult[T]:
        """Execute this step asynchronously."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of this step."""
        pass


class FunctionStep(ToolStep[T]):
    """A step that executes a function.

    Example:
        >>> step = FunctionStep(my_function, name="process_data")
        >>> result = step.execute(input_data, {})
    """

    def __init__(
        self,
        func: Callable[..., T],
        name: Optional[str] = None,
        input_mapping: Optional[Callable[[Any], Dict[str, Any]]] = None,
    ):
        """Initialize function step.

        Args:
            func: The function to execute.
            name: Name for this step (defaults to function name).
            input_mapping: Optional function to transform input to kwargs.
        """
        self._func = func
        self._name = name or func.__name__
        self._input_mapping = input_mapping
        self._is_async = asyncio.iscoroutinefunction(func)

    @property
    def name(self) -> str:
        return self._name

    def execute(self, input_data: Any, context: Dict[str, Any]) -> ToolResult[T]:
        """Execute the function synchronously."""
        try:
            kwargs = self._prepare_kwargs(input_data, context)

            if self._is_async:
                # Run async function in event loop
                loop = asyncio.new_event_loop()
                try:
                    result = loop.run_until_complete(self._func(**kwargs))
                finally:
                    loop.close()
            else:
                result = self._func(**kwargs)

            return ToolResult.ok(result, self._name)

        except Exception as e:
            return ToolResult.fail(e, self._name)

    async def execute_async(self, input_data: Any, context: Dict[str, Any]) -> ToolResult[T]:
        """Execute the function asynchronously."""
        try:
            kwargs = self._prepare_kwargs(input_data, context)

            if self._is_async:
                result = await self._func(**kwargs)
            else:
                # Run sync function in executor
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, lambda: self._func(**kwargs))

            return ToolResult.ok(result, self._name)

        except Exception as e:
            return ToolResult.fail(e, self._name)

    def _prepare_kwargs(self, input_data: Any, context: Dict[str, Any]) -> Dict[str, Any]:  # noqa: ARG002
        """Prepare kwargs for function call."""
        if self._input_mapping:
            return self._input_mapping(input_data)
        elif isinstance(input_data, dict):
            return input_data
        else:
            # Try to match to first parameter
            sig = inspect.signature(self._func)
            params = list(sig.parameters.keys())
            if params:
                return {params[0]: input_data}
            return {}


class Pipeline(ToolStep[T]):
    """A sequential composition of tool steps.

    Each step's output becomes the next step's input.

    Example:
        >>> pipeline = Pipeline([
        ...     FunctionStep(parse_input),
        ...     FunctionStep(process_data),
        ...     FunctionStep(format_output),
        ... ], name="data_pipeline")
        >>> result = pipeline.execute(raw_input, {})
    """

    def __init__(
        self,
        steps: List[ToolStep],
        name: str = "pipeline",
        stop_on_error: bool = True,
    ):
        """Initialize pipeline.

        Args:
            steps: List of steps to execute in order.
            name: Name for this pipeline.
            stop_on_error: Whether to stop if a step fails.
        """
        self._steps = steps
        self._name = name
        self._stop_on_error = stop_on_error

    @property
    def name(self) -> str:
        return self._name

    def execute(self, input_data: Any, context: Dict[str, Any]) -> ToolResult[T]:
        """Execute all steps sequentially."""
        current_data = input_data
        results: List[ToolResult] = []

        for step in self._steps:
            result = step.execute(current_data, context)
            results.append(result)

            if not result.success:
                if self._stop_on_error:
                    return ToolResult.fail(
                        result.error or CompositionError(f"Step '{step.name}' failed"),
                        self._name,
                        step_results=results,
                    )
                continue

            current_data = result.value

        return ToolResult.ok(current_data, self._name, step_results=results)

    async def execute_async(self, input_data: Any, context: Dict[str, Any]) -> ToolResult[T]:
        """Execute all steps sequentially (async)."""
        current_data = input_data
        results: List[ToolResult] = []

        for step in self._steps:
            result = await step.execute_async(current_data, context)
            results.append(result)

            if not result.success:
                if self._stop_on_error:
                    return ToolResult.fail(
                        result.error or CompositionError(f"Step '{step.name}' failed"),
                        self._name,
                        step_results=results,
                    )
                continue

            current_data = result.value

        return ToolResult.ok(current_data, self._name, step_results=results)

    def then(self, step: ToolStep) -> "Pipeline":
        """Add a step to the pipeline."""
        return Pipeline(
            steps=self._steps + [step], name=self._name, stop_on_error=self._stop_on_error
        )


class ParallelExecution(ToolStep[List[T]]):
    """Execute multiple steps in parallel.

    Example:
        >>> parallel = ParallelExecution([
        ...     FunctionStep(fetch_from_api_a),
        ...     FunctionStep(fetch_from_api_b),
        ... ], name="parallel_fetch")
        >>> result = parallel.execute(query, {})
        >>> results = result.value  # List of results from both
    """

    def __init__(
        self,
        steps: List[ToolStep],
        name: str = "parallel",
        collect_all: bool = True,
    ):
        """Initialize parallel execution.

        Args:
            steps: Steps to execute in parallel.
            name: Name for this composition.
            collect_all: If True, wait for all. If False, return first success.
        """
        self._steps = steps
        self._name = name
        self._collect_all = collect_all

    @property
    def name(self) -> str:
        return self._name

    def execute(self, input_data: Any, context: Dict[str, Any]) -> ToolResult[List[T]]:
        """Execute all steps in parallel using threads."""
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = {
                executor.submit(step.execute, input_data, context): step for step in self._steps
            }

            results: List[ToolResult] = []

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                results.append(result)

                if not self._collect_all and result.success:
                    # Return first success
                    return ToolResult.ok([result.value], self._name, step_results=results)

        values = [r.value for r in results if r.success]
        errors = [r for r in results if not r.success]

        if errors and not values:
            return ToolResult.fail(
                errors[0].error or CompositionError("All parallel steps failed"),
                self._name,
                step_results=results,
            )

        return ToolResult.ok(values, self._name, step_results=results)

    async def execute_async(self, input_data: Any, context: Dict[str, Any]) -> ToolResult[List[T]]:
        """Execute all steps in parallel using asyncio."""
        tasks = [step.execute_async(input_data, context) for step in self._steps]

        if self._collect_all:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            processed_results: List[ToolResult] = []

            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    processed_results.append(ToolResult.fail(result, self._steps[i].name))
                else:
                    processed_results.append(result)

            values = [r.value for r in processed_results if r.success]
            errors = [r for r in processed_results if not r.success]

            if errors and not values:
                return ToolResult.fail(
                    errors[0].error or CompositionError("All parallel steps failed"),
                    self._name,
                    step_results=processed_results,
                )

            return ToolResult.ok(values, self._name, step_results=processed_results)
        else:
            # Return first success
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

            for task in pending:
                task.cancel()

            for task in done:
                result = task.result()
                if result.success:
                    return ToolResult.ok([result.value], self._name)

            # All completed tasks failed
            results = [task.result() for task in done]
            return ToolResult.fail(
                results[0].error if results else CompositionError("No results"),
                self._name,
                step_results=results,
            )


class ConditionalStep(ToolStep[T]):
    """Execute different steps based on a condition.

    Example:
        >>> conditional = ConditionalStep(
        ...     condition=lambda x, ctx: x.get('type') == 'pdf',
        ...     if_true=FunctionStep(parse_pdf),
        ...     if_false=FunctionStep(parse_text),
        ... )
    """

    def __init__(
        self,
        condition: Callable[[Any, Dict[str, Any]], bool],
        if_true: ToolStep[T],
        if_false: Optional[ToolStep[T]] = None,
        name: str = "conditional",
    ):
        """Initialize conditional step.

        Args:
            condition: Function that returns True or False.
            if_true: Step to execute if condition is True.
            if_false: Step to execute if condition is False (optional).
            name: Name for this step.
        """
        self._condition = condition
        self._if_true = if_true
        self._if_false = if_false
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def execute(self, input_data: Any, context: Dict[str, Any]) -> ToolResult[T]:
        """Execute based on condition."""
        try:
            condition_result = self._condition(input_data, context)
        except Exception as e:
            return ToolResult.fail(e, self._name)

        if condition_result:
            return self._if_true.execute(input_data, context)
        elif self._if_false:
            return self._if_false.execute(input_data, context)
        else:
            return ToolResult.ok(input_data, self._name)

    async def execute_async(self, input_data: Any, context: Dict[str, Any]) -> ToolResult[T]:
        """Execute based on condition (async)."""
        try:
            if asyncio.iscoroutinefunction(self._condition):
                condition_result = await self._condition(input_data, context)
            else:
                condition_result = self._condition(input_data, context)
        except Exception as e:
            return ToolResult.fail(e, self._name)

        if condition_result:
            return await self._if_true.execute_async(input_data, context)
        elif self._if_false:
            return await self._if_false.execute_async(input_data, context)
        else:
            return ToolResult.ok(input_data, self._name)


class FallbackStep(ToolStep[T]):
    """Try multiple steps until one succeeds.

    Example:
        >>> fallback = FallbackStep([
        ...     FunctionStep(primary_api),
        ...     FunctionStep(backup_api),
        ...     FunctionStep(cache_lookup),
        ... ])
    """

    def __init__(
        self,
        steps: List[ToolStep[T]],
        name: str = "fallback",
    ):
        """Initialize fallback step.

        Args:
            steps: Steps to try in order until one succeeds.
            name: Name for this step.
        """
        self._steps = steps
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def execute(self, input_data: Any, context: Dict[str, Any]) -> ToolResult[T]:
        """Try steps until one succeeds."""
        errors: List[Exception] = []

        for step in self._steps:
            result = step.execute(input_data, context)
            if result.success:
                return result
            errors.append(result.error)

        return ToolResult.fail(
            CompositionError(f"All fallback steps failed: {errors}"), self._name, errors=errors
        )

    async def execute_async(self, input_data: Any, context: Dict[str, Any]) -> ToolResult[T]:
        """Try steps until one succeeds (async)."""
        errors: List[Exception] = []

        for step in self._steps:
            result = await step.execute_async(input_data, context)
            if result.success:
                return result
            errors.append(result.error)

        return ToolResult.fail(
            CompositionError(f"All fallback steps failed: {errors}"), self._name, errors=errors
        )


# Builder pattern for creating compositions
class ToolChain(Generic[T]):
    """Fluent builder for creating tool compositions.

    Example:
        >>> chain = (ToolChain(name="process_document")
        ...     .then(parse_input)
        ...     .then(validate_data)
        ...     .parallel([extract_text, extract_images])
        ...     .then(merge_results)
        ...     .build())
        >>> result = chain.execute(document, {})
    """

    def __init__(self, name: str = "chain"):
        """Initialize tool chain builder.

        Args:
            name: Name for the resulting composition.
        """
        self._name = name
        self._steps: List[ToolStep] = []

    def then(self, step: Union[ToolStep, Callable]) -> "ToolChain[T]":
        """Add a sequential step.

        Args:
            step: ToolStep or callable to add.

        Returns:
            Self for chaining.
        """
        if callable(step) and not isinstance(step, ToolStep):
            step = FunctionStep(step)
        self._steps.append(step)
        return self

    def parallel(
        self, steps: List[Union[ToolStep, Callable]], collect_all: bool = True
    ) -> "ToolChain[T]":
        """Add parallel execution.

        Args:
            steps: Steps to run in parallel.
            collect_all: Whether to wait for all or return first.

        Returns:
            Self for chaining.
        """
        converted = [
            FunctionStep(s) if callable(s) and not isinstance(s, ToolStep) else s for s in steps
        ]
        self._steps.append(ParallelExecution(converted, collect_all=collect_all))
        return self

    def branch(
        self,
        condition: Callable[[Any, Dict[str, Any]], bool],
        if_true: Union[ToolStep, Callable],
        if_false: Optional[Union[ToolStep, Callable]] = None,
    ) -> "ToolChain[T]":
        """Add conditional branching.

        Args:
            condition: Condition function.
            if_true: Step if condition is True.
            if_false: Step if condition is False.

        Returns:
            Self for chaining.
        """
        if callable(if_true) and not isinstance(if_true, ToolStep):
            if_true = FunctionStep(if_true)
        if if_false and callable(if_false) and not isinstance(if_false, ToolStep):
            if_false = FunctionStep(if_false)

        self._steps.append(ConditionalStep(condition, if_true, if_false))
        return self

    def fallback(self, steps: List[Union[ToolStep, Callable]]) -> "ToolChain[T]":
        """Add fallback execution.

        Args:
            steps: Steps to try until one succeeds.

        Returns:
            Self for chaining.
        """
        converted = [
            FunctionStep(s) if callable(s) and not isinstance(s, ToolStep) else s for s in steps
        ]
        self._steps.append(FallbackStep(converted))
        return self

    def build(self) -> Pipeline:
        """Build the final pipeline.

        Returns:
            Pipeline ready for execution.
        """
        return Pipeline(self._steps, name=self._name)


def compose(*steps: Union[ToolStep, Callable], name: str = "composed") -> Pipeline:
    """Convenience function to compose tools.

    Example:
        >>> pipeline = compose(parse, process, format, name="my_pipeline")
        >>> result = pipeline.execute(data, {})
    """
    converted = [
        FunctionStep(s) if callable(s) and not isinstance(s, ToolStep) else s for s in steps
    ]
    return Pipeline(converted, name=name)
