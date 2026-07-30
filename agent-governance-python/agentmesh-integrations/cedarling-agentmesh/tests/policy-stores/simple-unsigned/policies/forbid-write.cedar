@id("forbid-write")
forbid(
  principal is AGT::Agent,
  action == AGT::Action::"Write",
  resource is AGT::Resource
)
when {
  principal.role == "auditor"
};
