package ldap

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Client wraps LDAP connection and operations
type Client struct {
	host    string
	port    int
	useTLS  bool
	timeout time.Duration
}

// NewClient creates a new LDAP client
func NewClient(host string, port int, useTLS bool, timeout time.Duration) *Client {
	return &Client{
		host:    host,
		port:    port,
		useTLS:  useTLS,
		timeout: timeout,
	}
}

// AuthenticateUser performs search-then-bind authentication
// Returns user attributes (map of attribute name to value) on success
func (c *Client) AuthenticateUser(
	baseDN, attrLogin, username, password string,
	serviceAccountDN, serviceAccountPassword string,
	filter string,
	attributesToRetrieve []string,
) (map[string]string, error) {

	// 1. Connect to LDAP server
	ldapURL := fmt.Sprintf("ldap://%s:%d", c.host, c.port)
	if c.useTLS {
		ldapURL = fmt.Sprintf("ldaps://%s:%d", c.host, c.port)
	}

	dialer := &net.Dialer{Timeout: c.timeout}
	conn, err := ldap.DialURL(ldapURL, ldap.DialWithDialer(dialer))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}
	defer conn.Close()

	// 2. Bind with service account (if provided) or anonymous bind
	if serviceAccountDN != "" {
		err = conn.Bind(serviceAccountDN, serviceAccountPassword)
		if err != nil {
			return nil, fmt.Errorf("service account bind failed: %w", err)
		}
	}

	// 3. Build search filter combining attr_login and optional group filter
	searchFilter := fmt.Sprintf("(%s=%s)", attrLogin, ldap.EscapeFilter(username))
	if filter != "" {
		// Combine user filter with group filter using AND
		searchFilter = fmt.Sprintf("(&%s%s)", searchFilter, filter)
	}

	// 4. Search for user
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, // Size limit: 1 user
		int(c.timeout.Seconds()),
		false,
		searchFilter,
		attributesToRetrieve,
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(searchResult.Entries) == 0 {
		return nil, fmt.Errorf("user not found in LDAP")
	}

	entry := searchResult.Entries[0]
	userDN := entry.DN

	// 5. Rebind with user credentials to validate password (LDAP bind)
	err = conn.Bind(userDN, password)
	if err != nil {
		return nil, fmt.Errorf("LDAP bind failed (invalid credentials or disabled account): %w", err)
	}

	// 6. Extract user attributes (case-insensitive matching for LDAP attribute names)
	attributes := make(map[string]string)

	// Build a case-insensitive map of actual LDAP attributes
	ldapAttrs := make(map[string]string)
	for _, attr := range entry.Attributes {
		// Store with lowercase key for case-insensitive lookup
		ldapAttrs[strings.ToLower(attr.Name)] = attr.Name
	}

	// Retrieve requested attributes with case-insensitive matching
	for _, requestedAttr := range attributesToRetrieve {
		// Try exact match first
		values := entry.GetAttributeValues(requestedAttr)
		if len(values) > 0 {
			attributes[requestedAttr] = values[0]
			continue
		}

		// Try case-insensitive match
		if actualAttr, exists := ldapAttrs[strings.ToLower(requestedAttr)]; exists {
			values = entry.GetAttributeValues(actualAttr)
			if len(values) > 0 {
				attributes[requestedAttr] = values[0]
				continue
			}
		}

		// Attribute not found or empty
		attributes[requestedAttr] = ""
	}

	return attributes, nil
}
