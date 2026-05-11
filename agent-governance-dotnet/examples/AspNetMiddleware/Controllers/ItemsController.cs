// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.AspNetCore.Mvc;

namespace AgentGovernance.Examples.AspNetMiddleware.Controllers;

/// <summary>
/// Tiny in-memory items API used to demonstrate governance enforcement
/// at the HTTP layer:
///
///   GET    /api/items        -> always allowed
///   GET    /api/items/{id}   -> always allowed
///   POST   /api/items        -> rate-limited to 5/minute by policy
///   PUT    /api/items/{id}   -> always allowed
///   DELETE /api/items/{id}   -> blocked by policy (deny-item-delete)
/// </summary>
[ApiController]
[Route("api/items")]
public sealed class ItemsController : ControllerBase
{
    // An in-memory store for demo purposes.
    private readonly Dictionary<int, Item> Store = new()
    {
        [1] = new Item(1, "alpha"),
        [2] = new Item(2, "bravo"),
    };

    private int _nextId = 3;
    private readonly object Sync = new();

    [HttpGet]
    public ActionResult<IEnumerable<Item>> List()
    {
        lock (Sync)
        {
            return Ok(Store.Values.ToArray());
        }
    }

    [HttpGet("{id:int}")]
    public ActionResult<Item> GetById(int id)
    {
        lock (Sync)
        {
            return Store.TryGetValue(id, out var item) ? Ok(item) : NotFound();
        }
    }

    [HttpPost]
    public ActionResult<Item> Create([FromBody] CreateItemRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return BadRequest(new { error = "name is required" });
        }

        Item created;
        lock (Sync)
        {
            created = new Item(_nextId++, request.Name);
            Store[created.Id] = created;
        }

        return CreatedAtAction(nameof(GetById), new { id = created.Id }, created);
    }

    [HttpPut("{id:int}")]
    public ActionResult<Item> Update(int id, [FromBody] UpdateItemRequest request)
    {
        lock (Sync)
        {
            if (!Store.TryGetValue(id, out var existing))
            {
                return NotFound();
            }

            var updated = new Item(id, request.Name ?? existing.Name);
            Store[id] = updated;
            return Ok(updated);
        }
    }

    [HttpDelete("{id:int}")]
    public IActionResult Delete(int id)
    {
        // Note: policy `deny-item-delete` blocks this route at the middleware
        // layer, so callers will see a 403 long before this method runs.
        lock (Sync)
        {
            return Store.Remove(id) ? NoContent() : NotFound();
        }
    }
}

public sealed record Item(int Id, string Name);
public sealed record CreateItemRequest(string Name);
public sealed record UpdateItemRequest(string? Name);
