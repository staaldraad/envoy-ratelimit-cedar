forbid (
	principal,
	action == Action::"SELECT",
	resource in Table::"tbl"
) when {
	resource.requests.user > 1
};