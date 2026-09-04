@id("allow-admin-read")
permit(
    principal,
    action == AGT::Action::"pre_tool_call",
    resource == AGT::Tool::"read_config"
) when {
    context has tokens.janssen_access_token &&
    context.tokens.janssen_access_token.hasTag("role") &&
    context.tokens.janssen_access_token.getTag("role").contains("admin")
};
