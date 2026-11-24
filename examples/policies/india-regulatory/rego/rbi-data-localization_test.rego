# agt-policies-india - RBI payment data localization (OPA tests)
# This rule was already guarded on the subject-matter field. The tests pin that
# behaviour, since it is the pattern the other packs' region rules now follow.
package agt_policies_india.rbi_test

import data.agt_policies_india.rbi
import rego.v1

test_region_silent_when_data_class_absent if {
	denials := rbi.deny with input as {"action": "read_file", "params": {}}
	count(denials) == 0
}

test_region_denies_payment_data_with_no_declared_region if {
	denials := rbi.deny with input as {"action": "store_data", "params": {"data_class": "card_data"}}
	count(denials) == 1
}

test_region_silent_for_payment_data_stored_in_india if {
	denials := rbi.deny with input as {"action": "store_data", "params": {"data_class": "card_data", "storage_region": "IN"}}
	count(denials) == 0
}
