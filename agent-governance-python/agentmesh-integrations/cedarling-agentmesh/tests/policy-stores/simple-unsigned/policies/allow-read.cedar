@id("allow-read")
permit(
  principal is Agent,
  action in [Action::"Read", Action::"ReadData"],
  resource is Resource
);
