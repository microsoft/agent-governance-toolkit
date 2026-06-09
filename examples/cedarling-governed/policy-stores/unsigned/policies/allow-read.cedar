@id("allow-read")
permit(
  principal is AGT::Agent,
  action in [AGT::Action::"Read", AGT::Action::"ReadData"],
  resource is AGT::Resource
)
when {
  principal.role == "admin"
};
