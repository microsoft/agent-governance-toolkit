# Examples

This directory contains examples demonstrating how to use the ATR (Agent Tool Registry).

## demo.py

A comprehensive demonstration of ATR features including:

- Tool registration with the `@atr.register()` decorator
- Tool discovery and search capabilities
- Tool specification retrieval
- OpenAI function calling format conversion
- Tool execution (by the Agent Runtime)

### Running the Demo

```bash
python examples/demo.py
```

## Key Concepts Demonstrated

1. **No Magic Arguments**: All parameters must have type hints
2. **Registry doesn't execute**: Tools are stored and returned, execution is separate
3. **Strict typing**: Full type safety with Pydantic validation
4. **OpenAI compatibility**: Easy conversion to OpenAI function calling format
5. **Metadata-rich**: Tools have cost, tags, side effects, and more
