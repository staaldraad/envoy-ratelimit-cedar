forbid (
	principal,
	action == Action::"SELECT",
	resource in Table::"user_logs"
) when {
	resource.requests.user > 1
};

forbid (
	principal,
	action == Action::"SELECT",
	resource in Table::"user_logs"
) when {
	principal.role == "service_role"
    &&
    context.remote_address != "127.0.0.1"
};