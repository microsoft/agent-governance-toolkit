@id("allow-admin-write")
permit(
    principal,
    action == AGT::Action::"pre_tool_call",
    resource == AGT::Tool::"write_config"
) when {
    context has tokens.janssen_access_token &&
    context.tokens.janssen_access_token.hasTag("role") &&
    context.tokens.janssen_access_token.getTag("role").contains("admin") &&
    context has device &&
    context.device != "mobile"
};
