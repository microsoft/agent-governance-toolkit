// Cedar policy for cold chain IoT sensor governance.
//
// Enforces temperature, humidity, and shock thresholds for pharmaceutical
// and food supply chain scenarios. Each sensor reading is governed and
// receipted for regulatory accountability.

// Allow normal temperature readings within safe range
permit(
    principal,
    action == Action::"RecordTemperature",
    resource
) when {
    context.value_celsius >= -25 && context.value_celsius <= 8
};

// Allow normal humidity readings within safe range
permit(
    principal,
    action == Action::"RecordHumidity",
    resource
) when {
    context.value_percent >= 20 && context.value_percent <= 80
};

// Allow GPS location updates
permit(
    principal,
    action == Action::"RecordGPS",
    resource
);

// Forbid shock readings above damage threshold (> 5g)
forbid(
    principal,
    action == Action::"RecordShock",
    resource
) when {
    context.value_g > 5.0
};

// Allow minor shock readings
permit(
    principal,
    action == Action::"RecordShock",
    resource
) when {
    context.value_g <= 5.0
};

// Forbid temperature readings outside safe range (excursion)
forbid(
    principal,
    action == Action::"RecordTemperature",
    resource
) when {
    context.value_celsius < -25 || context.value_celsius > 8
};

// Forbid humidity readings outside safe range
forbid(
    principal,
    action == Action::"RecordHumidity",
    resource
) when {
    context.value_percent < 20 || context.value_percent > 80
};
