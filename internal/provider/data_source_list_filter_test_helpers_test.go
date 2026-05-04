package provider_test

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// The helpers in this file tighten acceptance-test assertions for the ad_groups
// and ad_users data sources. Each helper returns a resource.TestCheckFunc that
// walks the indexed state attributes of a list-nested attribute
// (e.g. "groups.0.name", "groups.1.name", ...) and asserts a predicate on every
// element. These checks are order-independent and cardinality-independent,
// making them suitable for live-AD acceptance tests whose result set size is
// unpredictable.
//
// All helpers short-circuit when the list is empty: a filter that legitimately
// returns zero items is not necessarily a bug, but a broken filter that
// returns items with non-matching attributes is. Callers that need to assert
// non-empty results should combine these with a separate check such as
// resource.TestCheckResourceAttrWith on "<list>.#" / "<count>".

// testCheckListAttrEachWith iterates the collection "<listAttr>.*" attached to
// the named resource and invokes predicate on every element's "<field>" value.
// The predicate is expected to return a descriptive error if the value does
// not satisfy the expectation.
func testCheckListAttrEachWith(resourceName, listAttr, field string, predicate func(value string) error) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}

		countAttr := listAttr + ".#"
		countValue, ok := rs.Primary.Attributes[countAttr]
		if !ok {
			return fmt.Errorf("%s: attribute %q not found", resourceName, countAttr)
		}

		var count int
		if _, err := fmt.Sscanf(countValue, "%d", &count); err != nil {
			return fmt.Errorf("%s: failed to parse %q=%q: %w", resourceName, countAttr, countValue, err)
		}

		for i := 0; i < count; i++ {
			key := fmt.Sprintf("%s.%d.%s", listAttr, i, field)
			value, ok := rs.Primary.Attributes[key]
			if !ok {
				return fmt.Errorf("%s: attribute %q not found", resourceName, key)
			}
			if err := predicate(value); err != nil {
				return fmt.Errorf("%s[%d].%s = %q: %w", listAttr, i, field, value, err)
			}
		}

		return nil
	}
}

// testCheckListAttrAllHavePrefix asserts that every element's "<field>" value
// starts (case-insensitively) with prefix.
func testCheckListAttrAllHavePrefix(resourceName, listAttr, field, prefix string) resource.TestCheckFunc {
	return testCheckListAttrEachWith(resourceName, listAttr, field, func(value string) error {
		if !strings.HasPrefix(strings.ToLower(value), strings.ToLower(prefix)) {
			return fmt.Errorf("expected prefix %q", prefix)
		}
		return nil
	})
}

// testCheckListAttrAllHaveSuffix asserts that every element's "<field>" value
// ends (case-insensitively) with suffix.
func testCheckListAttrAllHaveSuffix(resourceName, listAttr, field, suffix string) resource.TestCheckFunc {
	return testCheckListAttrEachWith(resourceName, listAttr, field, func(value string) error {
		if !strings.HasSuffix(strings.ToLower(value), strings.ToLower(suffix)) {
			return fmt.Errorf("expected suffix %q", suffix)
		}
		return nil
	})
}

// testCheckListAttrAllContain asserts that every element's "<field>" value
// contains (case-insensitively) the given substring.
func testCheckListAttrAllContain(resourceName, listAttr, field, substring string) resource.TestCheckFunc {
	return testCheckListAttrEachWith(resourceName, listAttr, field, func(value string) error {
		if !strings.Contains(strings.ToLower(value), strings.ToLower(substring)) {
			return fmt.Errorf("expected to contain %q", substring)
		}
		return nil
	})
}

// testCheckListAttrAllEqual asserts that every element's "<field>" value
// equals expected (case-insensitive).
func testCheckListAttrAllEqual(resourceName, listAttr, field, expected string) resource.TestCheckFunc {
	return testCheckListAttrEachWith(resourceName, listAttr, field, func(value string) error {
		if !strings.EqualFold(value, expected) {
			return fmt.Errorf("expected %q", expected)
		}
		return nil
	})
}

// testCheckListAttrAllEqualBool asserts that every element's "<field>" value
// (a stringified bool from Terraform state: "true"/"false") equals expected.
func testCheckListAttrAllEqualBool(resourceName, listAttr, field string, expected bool) resource.TestCheckFunc {
	want := "false"
	if expected {
		want = "true"
	}
	return testCheckListAttrEachWith(resourceName, listAttr, field, func(value string) error {
		if value != want {
			return fmt.Errorf("expected %q", want)
		}
		return nil
	})
}

// testCheckListAttrAllInSubtree asserts that every element's "dn" attribute
// is either (case-insensitively) equal to container or a descendant of it.
// For subtree searches rooted at container, this is the expected property.
// The check normalises by trimming surrounding whitespace and lowercasing
// both sides before comparison.
func testCheckListAttrAllInSubtree(resourceName, listAttr, container string) resource.TestCheckFunc {
	containerLower := strings.ToLower(strings.TrimSpace(container))
	// The suffix an entry DN must end with to be a descendant:
	// "<itemRDN>,<container>" -> lower-cased full DN ends with ",<container>".
	descendantSuffix := "," + containerLower
	return testCheckListAttrEachWith(resourceName, listAttr, "dn", func(value string) error {
		got := strings.ToLower(strings.TrimSpace(value))
		if got == containerLower {
			return nil
		}
		if strings.HasSuffix(got, descendantSuffix) {
			return nil
		}
		return fmt.Errorf("expected DN equal to or descendant of %q", container)
	})
}

// testCheckListAttrAllEmailDomain asserts that every element's "<field>"
// value (an email address) ends with "@<domain>" (case-insensitive). Empty
// values are rejected because has_email/email_domain filters imply the field
// is populated.
func testCheckListAttrAllEmailDomain(resourceName, listAttr, field, domain string) resource.TestCheckFunc {
	wantSuffix := "@" + strings.ToLower(domain)
	return testCheckListAttrEachWith(resourceName, listAttr, field, func(value string) error {
		if value == "" {
			return fmt.Errorf("expected email address with domain %q, got empty string", domain)
		}
		if !strings.HasSuffix(strings.ToLower(value), wantSuffix) {
			return fmt.Errorf("expected email domain %q", domain)
		}
		return nil
	})
}

// testCheckListAttrAllNonEmpty asserts that every element's "<field>" value
// is non-empty. Useful for has_email=true (email_address must be populated)
// or similar "field must be set" assertions.
func testCheckListAttrAllNonEmpty(resourceName, listAttr, field string) resource.TestCheckFunc {
	return testCheckListAttrEachWith(resourceName, listAttr, field, func(value string) error {
		if value == "" {
			return fmt.Errorf("expected non-empty value")
		}
		return nil
	})
}

// testCheckListAttrAllEmpty asserts that every element's "<field>" value
// is empty. Useful for has_email=false (email_address must be absent).
func testCheckListAttrAllEmpty(resourceName, listAttr, field string) resource.TestCheckFunc {
	return testCheckListAttrEachWith(resourceName, listAttr, field, func(value string) error {
		if value != "" {
			return fmt.Errorf("expected empty value")
		}
		return nil
	})
}
