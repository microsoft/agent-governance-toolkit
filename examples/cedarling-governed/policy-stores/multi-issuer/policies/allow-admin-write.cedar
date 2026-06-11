@id("allow-admin-write")
permit(
    principal,
    action == AGT::Action::"Write",
    resource is AGT::Resource
) when {
    context has tokens.janssen_access_token &&
    context.tokens.janssen_access_token.hasTag("role") &&
    context.tokens.janssen_access_token.getTag("role").contains("admin") &&
    context has device &&
    context.device != "mobile"
};
