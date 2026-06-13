@id("allow-admin-read")
permit(
    principal,
    action in [AGT::Action::"ReadData", AGT::Action::"Read"],
    resource is AGT::Resource
) when {
    context has tokens.janssen_access_token &&
    context.tokens.janssen_access_token.hasTag("role") &&
    context.tokens.janssen_access_token.getTag("role").contains("admin")
};
