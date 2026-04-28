// Cedar policy for distributed inference pipeline governance.
//
// Governs multi-node LLM inference: which ranks can load which models,
// resource limits, and audit requirements for cross-shard trust propagation.
//
// Inspired by real-world distributed inference on Apple Silicon (Hippo Pipeline).

// === Permits ===

// Allow Rank 0 to load shards (governed by memory budget in forbid rules)
permit(
    principal == Rank::"r0",
    action == Action::"LoadShard",
    resource
);

// Allow Rank 1 to load shards (governed by memory budget in forbid rules)
permit(
    principal == Rank::"r1",
    action == Action::"LoadShard",
    resource
);

// Allow cross-shard communication for pipeline inference
permit(
    principal,
    action == Action::"CrossShardTransfer",
    resource
) when {
    context.has_valid_receipt == true
};

// Allow inference on approved models
permit(
    principal,
    action == Action::"RunInference",
    resource
) when {
    context.model in ["gemma-3-12b-qat4", "qwen3-4b-bf16"]
};

// Allow audit log writes
permit(
    principal,
    action == Action::"WriteAudit",
    resource
);

// === Forbids ===

// Deny loading shards beyond memory budget
forbid(
    principal,
    action == Action::"LoadShard",
    resource
) when {
    context.shard_size_mb > context.memory_budget_mb
};

// Deny cross-shard transfer without receipt
forbid(
    principal,
    action == Action::"CrossShardTransfer",
    resource
) when {
    context.has_valid_receipt == false
};
