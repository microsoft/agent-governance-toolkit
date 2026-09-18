@id("forbid-auditor-delete")
forbid(
  principal is AGT::Agent,
  action == AGT::Action::"pre_tool_call",
  resource == AGT::Tool::"delete_file"
)
when {
  principal.role == "auditor"
};
