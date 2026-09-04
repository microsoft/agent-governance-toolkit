@id("allow-admin-tools")
permit(
  principal is AGT::Agent,
  action == AGT::Action::"pre_tool_call",
  resource is AGT::Tool
)
when {
  principal.role == "admin"
};
