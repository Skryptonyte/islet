#!/bin/bash

set -e

cargo clippy --lib -p islet_rmm --no-deps -- \
	-A clippy::comparison_chain \
	-A clippy::crate_in_macro_def \
	-A clippy::empty_loop \
	-A clippy::explicit_auto_deref \
	-A clippy::from_over_into \
	-A clippy::identity_op \
	-A clippy::len_without_is_empty \
	-A clippy::let_underscore_lock \
	-A clippy::manual_range_contains \
	-A clippy::match_like_matches_macro \
	-A clippy::new_without_default \
	-A clippy::redundant_pattern_matching \
	-A clippy::type_complexity \
	-A clippy::upper-case-acronyms \
	-A static-mut-refs \
	--deny "warnings"
