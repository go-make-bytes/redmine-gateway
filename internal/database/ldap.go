package database

import (
	"database/sql"
	"fmt"
)

// LDAPAuthSource represents an LDAP authentication source from Redmine database
type LDAPAuthSource struct {
	ID               int
	Name             string
	Host             string
	Port             int
	Account          string // Service account DN (optional)
	AccountPassword  string // Service account password (encrypted)
	BaseDN           string
	AttrLogin        string
	AttrFirstname    string
	AttrLastname     string
	AttrMail         string
	OnTheFlyRegister bool
	TLS              bool
	Filter           string
	Timeout          int
}

// GetActiveLDAPSources retrieves all active LDAP authentication sources ordered by ID
func (db *PostgreSQL) GetActiveLDAPSources() ([]LDAPAuthSource, error) {
	query := `
		SELECT id, name, host, port, 
		       COALESCE(account, '') as account, 
		       COALESCE(account_password, '') as account_password, 
		       base_dn,
		       attr_login, 
		       COALESCE(attr_firstname, '') as attr_firstname, 
		       COALESCE(attr_lastname, '') as attr_lastname, 
		       attr_mail,
		       onthefly_register, tls, 
		       COALESCE(filter, '') as filter, 
		       COALESCE(timeout, 10) as timeout
		FROM auth_sources
		WHERE type = 'AuthSourceLdap'
		ORDER BY id ASC
	`

	rows, err := db.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query LDAP sources: %w", err)
	}
	defer rows.Close()

	var sources []LDAPAuthSource
	for rows.Next() {
		var src LDAPAuthSource
		err := rows.Scan(
			&src.ID, &src.Name, &src.Host, &src.Port,
			&src.Account, &src.AccountPassword, &src.BaseDN,
			&src.AttrLogin, &src.AttrFirstname, &src.AttrLastname, &src.AttrMail,
			&src.OnTheFlyRegister, &src.TLS, &src.Filter, &src.Timeout,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan LDAP source: %w", err)
		}
		sources = append(sources, src)
	}

	return sources, nil
}

// FindUserByLoginAndAuthSource finds a user by login and auth_source_id (case-insensitive)
func (db *PostgreSQL) FindUserByLoginAndAuthSource(login string, authSourceID int) (*User, error) {
	query := `
		SELECT id, login, firstname, lastname, auth_source_id, status
		FROM users
		WHERE LOWER(login) = LOWER($1) AND auth_source_id = $2
		LIMIT 1
	`

	var user User
	err := db.db.QueryRow(query, login, authSourceID).Scan(
		&user.ID, &user.Login, &user.Firstname, &user.Lastname,
		&user.AuthSourceID, &user.Status,
	)
	if err == sql.ErrNoRows {
		return nil, nil // User not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	return &user, nil
}

// CreateLDAPUser creates a new user from LDAP authentication with email in email_addresses table
func (db *PostgreSQL) CreateLDAPUser(login, firstname, lastname, mail string, authSourceID int) (*User, error) {
	// Use transaction to create user and email atomically
	tx, err := db.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Create user record
	userQuery := `
		INSERT INTO users (login, firstname, lastname, auth_source_id, status, type, created_on, updated_on)
		VALUES ($1, $2, $3, $4, 1, 'User', NOW(), NOW())
		RETURNING id, login, firstname, lastname, auth_source_id, status
	`

	var user User
	err = tx.QueryRow(userQuery, login, firstname, lastname, authSourceID).Scan(
		&user.ID, &user.Login, &user.Firstname, &user.Lastname,
		&user.AuthSourceID, &user.Status,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create LDAP user: %w", err)
	}

	// Create email address record
	emailQuery := `
		INSERT INTO email_addresses (user_id, address, is_default, notify, created_on, updated_on)
		VALUES ($1, $2, true, true, NOW(), NOW())
	`
	_, err = tx.Exec(emailQuery, user.ID, mail)
	if err != nil {
		return nil, fmt.Errorf("failed to create email address: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return &user, nil
}

// UpdateLDAPUserAttributes synchronizes user attributes from LDAP (name in users, email in email_addresses)
func (db *PostgreSQL) UpdateLDAPUserAttributes(userID int, firstname, lastname, mail string) error {
	// Use transaction to update user and email atomically
	tx, err := db.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Update user names
	userQuery := `
		UPDATE users
		SET firstname = $1, lastname = $2, updated_on = NOW()
		WHERE id = $3
	`
	_, err = tx.Exec(userQuery, firstname, lastname, userID)
	if err != nil {
		return fmt.Errorf("failed to update user attributes: %w", err)
	}

	// Update default email address
	emailQuery := `
		UPDATE email_addresses
		SET address = $1, updated_on = NOW()
		WHERE user_id = $2 AND is_default = true
	`
	_, err = tx.Exec(emailQuery, mail, userID)
	if err != nil {
		return fmt.Errorf("failed to update email address: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// MarkUserInactive marks a user as inactive (status=3) when LDAP account is disabled
func (db *PostgreSQL) MarkUserInactive(userID int) error {
	query := `
		UPDATE users
		SET status = 3, updated_on = NOW()
		WHERE id = $1
	`

	_, err := db.db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to mark user inactive: %w", err)
	}

	return nil
}
