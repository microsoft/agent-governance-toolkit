// Cedar policy for MCP tool access governance.
//
// This policy permits read-oriented tools and denies destructive operations.
// Used by the mcp-receipt-governed adapter to produce signed receipts.

// Allow agents to read data
permit(
    principal,
    action == Action::"ReadData",
    resource
);

// Allow agents to list files and directories
permit(
    principal,
    action == Action::"ListFiles",
    resource
);

// Allow agents to search across datasets
permit(
    principal,
    action == Action::"SearchData",
    resource
);

// Deny file deletion
forbid(
    principal,
    action == Action::"DeleteFile",
    resource
);

// Deny database drops
forbid(
    principal,
    action == Action::"DropTable",
    resource
);

// Deny sending external communications
forbid(
    principal,
    action == Action::"SendEmail",
    resource
);
