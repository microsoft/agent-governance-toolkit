@id("allow-org-match")
permit(
    principal,
    action in [AGT::Action::"ReadData", AGT::Action::"Read"],
    resource is AGT::Resource
) when {
    context has tokens.testissuer_access_token &&
    context.tokens.testissuer_access_token.hasTag("org_id") &&
    context.tokens.testissuer_access_token.getTag("org_id").contains("some_long_id")
};
