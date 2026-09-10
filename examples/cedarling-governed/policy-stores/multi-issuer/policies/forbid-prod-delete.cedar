@id("forbid-prod-delete")
forbid(
    principal,
    action == AGT::Action::"pre_tool_call",
    resource == AGT::Tool::"delete_prod"
);
