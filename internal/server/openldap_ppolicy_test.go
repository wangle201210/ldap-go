package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const openLDAPPasswordPolicyUserDN = "uid=policy,ou=people,dc=example,dc=com"

type openLDAPPasswordPolicyObservation struct {
	badBindCodes       []int64
	badBindControls    [][]byte
	lockedBindCode     int64
	lockedBindControl  []byte
	failureCount       int
	lockedAttribute    bool
	accountUsability   []byte
	qualityResultCode  int64
	qualityResultValue []byte
	checkerResultCode  int64
	checkerResultValue []byte
}

func TestOpenLDAPReferencePasswordPolicy(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		`access to attrs=userPassword
    by self write
    by anonymous auth
    by * none
access to *
    by self write
    by * read
overlay ppolicy
ppolicy_default "cn=default,ou=policies,dc=example,dc=com"
ppolicy_use_lockout`,
		`
dn: ou=policies,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: policies

dn: cn=default,ou=policies,dc=example,dc=com
objectClass: top
objectClass: device
objectClass: pwdPolicy
objectClass: pwdPolicyChecker
cn: default
pwdAttribute: 2.5.4.35
pwdLockout: TRUE
pwdLockoutDuration: 0
pwdMaxFailure: 2
pwdMaxRecordedFailure: 3
pwdCheckQuality: 2
pwdMinLength: 8
pwdAllowUserChange: TRUE
pwdUseCheckModule: TRUE

dn: uid=policy,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: policy
cn: Policy User
sn: User
userPassword: secret
`,
	)
	defer stopReference()

	goAddress, stopGo := startLDAPGoPasswordPolicyReferenceServer(t)
	defer stopGo()

	reference := observeOpenLDAPPasswordPolicy(
		t,
		trimLDAPURI(referenceURI),
	)
	implementation := observeOpenLDAPPasswordPolicy(t, goAddress)
	if !equalOpenLDAPPasswordPolicyObservation(reference, implementation) {
		t.Fatalf(
			"ppolicy observation mismatch\nOpenLDAP: %#v\nldap-go:  %#v",
			reference,
			implementation,
		)
	}
}

type openLDAPPasswordExpirationObservation struct {
	accountBefore     []byte
	bindCodes         []int64
	bindControls      [][]byte
	accountAfterTwo   []byte
	graceUseTimeCount int
}

func TestOpenLDAPReferencePasswordPolicyExpiration(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	changedTime := formatPasswordPolicyTime(time.Now().Add(-20 * time.Second))
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		`access to attrs=userPassword
    by self write
    by anonymous auth
    by * none
access to *
    by self write
    by * read
overlay ppolicy
ppolicy_default "cn=default,ou=policies,dc=example,dc=com"`,
		fmt.Sprintf(`
dn: ou=policies,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: policies

dn: cn=default,ou=policies,dc=example,dc=com
objectClass: top
objectClass: device
objectClass: pwdPolicy
cn: default
pwdAttribute: 2.5.4.35
pwdMaxAge: 10
pwdGraceAuthNLimit: 3

dn: uid=policy,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: policy
cn: Policy User
sn: User
userPassword: secret
pwdChangedTime: %s
`, changedTime),
	)
	defer stopReference()

	goAddress, stopGo := startLDAPGoPasswordExpirationReferenceServer(
		t,
		changedTime,
	)
	defer stopGo()
	reference := observeOpenLDAPPasswordExpiration(
		t,
		trimLDAPURI(referenceURI),
	)
	implementation := observeOpenLDAPPasswordExpiration(t, goAddress)
	if !reflect.DeepEqual(reference, implementation) {
		t.Fatalf(
			"ppolicy expiration mismatch\nOpenLDAP: %#v\nldap-go:  %#v",
			reference,
			implementation,
		)
	}
}

type openLDAPPasswordPolicyTimingObservation struct {
	warningCode              int64
	warningSeconds           int64
	netscapeCode             int64
	netscapeWarningSeconds   int
	badBindCode              int64
	badBindControl           []byte
	delayedBindCode          int64
	delayedBindControl       []byte
	temporaryInactive        bool
	temporarySecondsToUnlock int64
	resetBindCode            int64
	resetBindControl         []byte
	futureBindCode           int64
	futureBindControl        []byte
}

func TestOpenLDAPReferencePasswordPolicyControlsAndTiming(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	now := time.Now().UTC().Truncate(time.Second)
	changedTime := formatPasswordPolicyTime(now)
	futureTime := formatPasswordPolicyTime(now.Add(10 * time.Minute))
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		`access to attrs=userPassword
    by self write
    by anonymous auth
    by * none
access to *
    by self write
    by * read
overlay ppolicy
ppolicy_default "cn=default,ou=policies,dc=example,dc=com"
ppolicy_use_lockout
ppolicy_send_netscape_controls`,
		fmt.Sprintf(`
dn: ou=policies,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: policies

dn: cn=default,ou=policies,dc=example,dc=com
objectClass: top
objectClass: device
objectClass: pwdPolicy
cn: default
pwdAttribute: 2.5.4.35
pwdMaxAge: 300
pwdExpireWarning: 600
pwdLockout: TRUE
pwdMinDelay: 120
pwdMaxDelay: 120
pwdMaxRecordedFailure: 3
pwdMustChange: TRUE

dn: uid=warning,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: warning
cn: Warning User
sn: User
userPassword: secret
pwdChangedTime: %s

dn: uid=delay,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: delay
cn: Delay User
sn: User
userPassword: secret

dn: uid=reset,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: reset
cn: Reset User
sn: User
userPassword: secret
pwdReset: TRUE
pwdChangedTime: %s

dn: uid=future,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: future
cn: Future User
sn: User
userPassword: secret
pwdStartTime: %s
`, changedTime, changedTime, futureTime),
	)
	defer stopReference()

	goAddress, stopGo := startLDAPGoPasswordPolicyTimingReferenceServer(
		t,
		changedTime,
		futureTime,
	)
	defer stopGo()

	reference := observeOpenLDAPPasswordPolicyControlsAndTiming(
		t,
		trimLDAPURI(referenceURI),
	)
	implementation := observeOpenLDAPPasswordPolicyControlsAndTiming(
		t,
		goAddress,
	)
	if !equalOpenLDAPPasswordPolicyTimingObservation(
		reference,
		implementation,
	) {
		t.Fatalf(
			"ppolicy timing mismatch\nOpenLDAP: %#v\nldap-go:  %#v",
			reference,
			implementation,
		)
	}
}

func startLDAPGoPasswordPolicyTimingReferenceServer(
	t *testing.T,
	changedTime, futureTime string,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(
		t,
		store,
		[]directory.Attribute{
			{Description: "pwdMaxAge", Values: stringValues("300")},
			{Description: "pwdExpireWarning", Values: stringValues("600")},
			{Description: "pwdLockout", Values: stringValues("TRUE")},
			{Description: "pwdMinDelay", Values: stringValues("120")},
			{Description: "pwdMaxDelay", Values: stringValues("120")},
			{Description: "pwdMaxRecordedFailure", Values: stringValues("3")},
			{Description: "pwdMustChange", Values: stringValues("TRUE")},
		},
		[]directory.Attribute{
			{Description: "olcPPolicyUseLockout", Values: stringValues("TRUE")},
			{
				Description: "olcPPolicySendNetscapeControls",
				Values:      stringValues("TRUE"),
			},
		},
	)
	entries := []directory.Entry{
		passwordPolicyReferenceUser(
			"warning",
			directory.Attribute{
				Description: "pwdChangedTime",
				Values:      stringValues(changedTime),
			},
		),
		passwordPolicyReferenceUser("delay"),
		passwordPolicyReferenceUser(
			"reset",
			directory.Attribute{
				Description: "pwdReset",
				Values:      stringValues("TRUE"),
			},
			directory.Attribute{
				Description: "pwdChangedTime",
				Values:      stringValues(changedTime),
			},
		),
		passwordPolicyReferenceUser(
			"future",
			directory.Attribute{
				Description: "pwdStartTime",
				Values:      stringValues(futureTime),
			},
		),
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed ldap-go ppolicy timing users: %v", err)
	}
	return startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
}

func passwordPolicyReferenceUser(
	uid string,
	attributes ...directory.Attribute,
) directory.Entry {
	entry := directory.Entry{
		DN: "uid=" + uid + ",ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues(uid)},
			{Description: "cn", Values: stringValues(uid + " User")},
			{Description: "sn", Values: stringValues("User")},
			{Description: "userPassword", Values: stringValues("secret")},
		},
	}
	entry.Attributes = append(entry.Attributes, attributes...)
	return entry
}

func observeOpenLDAPPasswordPolicyControlsAndTiming(
	t *testing.T,
	address string,
) openLDAPPasswordPolicyTimingObservation {
	t.Helper()
	const (
		warningDN = "uid=warning,ou=people,dc=example,dc=com"
		delayDN   = "uid=delay,ou=people,dc=example,dc=com"
		resetDN   = "uid=reset,ou=people,dc=example,dc=com"
		futureDN  = "uid=future,ou=people,dc=example,dc=com"
	)
	var observation openLDAPPasswordPolicyTimingObservation
	warningCode, warningControl := observeOpenLDAPPasswordPolicyBind(
		t,
		address,
		warningDN,
		"secret",
	)
	observation.warningCode = warningCode
	observation.warningSeconds = passwordPolicyWarningSeconds(
		t,
		warningControl,
	)

	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial Netscape ppolicy reference: %v", err)
	}
	response := sendRawLDAPOperation(
		t,
		connection,
		1,
		rawSimpleBindRequestVersion(3, warningDN, "secret"),
	)
	_ = connection.Close()
	observation.netscapeCode = rawLDAPResultCode(t, response.Children[1])
	controls := rawLDAPResponseControls(response)
	netscapeValue, exists := controls[netscapePasswordExpiringOID]
	if !exists {
		t.Fatalf("Netscape warning control missing from %#v", controls)
	}
	observation.netscapeWarningSeconds, err = strconv.Atoi(
		string(netscapeValue),
	)
	if err != nil {
		t.Fatalf("parse Netscape warning %q: %v", netscapeValue, err)
	}

	observation.badBindCode, observation.badBindControl =
		observeOpenLDAPPasswordPolicyBind(t, address, delayDN, "wrong")
	observation.delayedBindCode, observation.delayedBindControl =
		observeOpenLDAPPasswordPolicyBind(t, address, delayDN, "secret")
	temporary := observeOpenLDAPAccountUsabilityFor(t, address, delayDN)
	packet, err := ber.DecodePacketErr(temporary)
	if err != nil || len(packet.Children) != 5 || packet.Tag != 1 {
		t.Fatalf("temporary account usability = %x, %v", temporary, err)
	}
	observation.temporaryInactive = bytes.Equal(
		packet.Children[0].Data.Bytes(),
		[]byte{0xff},
	)
	observation.temporarySecondsToUnlock, err = ber.ParseInt64(
		packet.Children[4].Data.Bytes(),
	)
	if err != nil {
		t.Fatalf("parse temporary unlock time: %v", err)
	}

	observation.resetBindCode, observation.resetBindControl =
		observeOpenLDAPPasswordPolicyBind(t, address, resetDN, "secret")
	observation.futureBindCode, observation.futureBindControl =
		observeOpenLDAPPasswordPolicyBind(t, address, futureDN, "secret")
	return observation
}

func equalOpenLDAPPasswordPolicyTimingObservation(
	left, right openLDAPPasswordPolicyTimingObservation,
) bool {
	within := func(left, right int64, tolerance int64) bool {
		difference := left - right
		if difference < 0 {
			difference = -difference
		}
		return difference <= tolerance
	}
	return left.warningCode == right.warningCode &&
		within(left.warningSeconds, right.warningSeconds, 5) &&
		left.netscapeCode == right.netscapeCode &&
		within(
			int64(left.netscapeWarningSeconds),
			int64(right.netscapeWarningSeconds),
			5,
		) &&
		left.badBindCode == right.badBindCode &&
		bytes.Equal(left.badBindControl, right.badBindControl) &&
		left.delayedBindCode == right.delayedBindCode &&
		bytes.Equal(left.delayedBindControl, right.delayedBindControl) &&
		left.temporaryInactive == right.temporaryInactive &&
		within(
			left.temporarySecondsToUnlock,
			right.temporarySecondsToUnlock,
			5,
		) &&
		left.resetBindCode == right.resetBindCode &&
		bytes.Equal(left.resetBindControl, right.resetBindControl) &&
		left.futureBindCode == right.futureBindCode &&
		bytes.Equal(left.futureBindControl, right.futureBindControl)
}

func startLDAPGoPasswordExpirationReferenceServer(
	t *testing.T,
	changedTime string,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(
		t,
		store,
		[]directory.Attribute{
			{Description: "pwdMaxAge", Values: stringValues("10")},
			{Description: "pwdGraceAuthNLimit", Values: stringValues("3")},
		},
		nil,
	)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry := directory.Entry{
			DN: openLDAPPasswordPolicyUserDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("policy")},
				{Description: "cn", Values: stringValues("Policy User")},
				{Description: "sn", Values: stringValues("User")},
				{Description: "userPassword", Values: stringValues("secret")},
				{Description: "pwdChangedTime", Values: stringValues(changedTime)},
			},
		}
		return writer.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed ldap-go expired ppolicy user: %v", err)
	}
	return startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
}

func observeOpenLDAPPasswordExpiration(
	t *testing.T,
	address string,
) openLDAPPasswordExpirationObservation {
	t.Helper()
	observation := openLDAPPasswordExpirationObservation{
		accountBefore: observeOpenLDAPAccountUsability(t, address),
	}
	for attempt := 0; attempt < 4; attempt++ {
		code, control := observeOpenLDAPPasswordPolicyBind(
			t,
			address,
			openLDAPPasswordPolicyUserDN,
			"secret",
		)
		observation.bindCodes = append(observation.bindCodes, code)
		observation.bindControls = append(
			observation.bindControls,
			control,
		)
		if attempt == 1 {
			observation.accountAfterTwo = observeOpenLDAPAccountUsability(
				t,
				address,
			)
		}
	}
	root, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(expiration root): %v", err)
	}
	defer root.Close()
	if err := root.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("expiration root Bind(): %v", err)
	}
	result, err := root.Search(ldap.NewSearchRequest(
		openLDAPPasswordPolicyUserDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"pwdGraceUseTime"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("expiration state Search() = %#v, %v", result, err)
	}
	observation.graceUseTimeCount = len(
		result.Entries[0].GetRawAttributeValues("pwdGraceUseTime"),
	)
	return observation
}

func startLDAPGoPasswordPolicyReferenceServer(
	t *testing.T,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(
		t,
		store,
		[]directory.Attribute{
			{Description: "pwdLockout", Values: stringValues("TRUE")},
			{Description: "pwdLockoutDuration", Values: stringValues("0")},
			{Description: "pwdMaxFailure", Values: stringValues("2")},
			{Description: "pwdMaxRecordedFailure", Values: stringValues("3")},
			{Description: "pwdCheckQuality", Values: stringValues("2")},
			{Description: "pwdMinLength", Values: stringValues("8")},
			{Description: "pwdAllowUserChange", Values: stringValues("TRUE")},
			{Description: "pwdUseCheckModule", Values: stringValues("TRUE")},
		},
		[]directory.Attribute{{
			Description: "olcPPolicyUseLockout",
			Values:      stringValues("TRUE"),
		}},
	)
	setPasswordPolicyEntryValues(t, store, passwordPolicyDN, map[string][][]byte{
		"objectClass": stringValues(
			"top",
			"device",
			"pwdPolicy",
			"pwdPolicyChecker",
		),
	})
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: openLDAPPasswordPolicyUserDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("policy")},
				{Description: "cn", Values: stringValues("Policy User")},
				{Description: "sn", Values: stringValues("User")},
				{Description: "userPassword", Values: stringValues("secret")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed ldap-go ppolicy user: %v", err)
	}
	return startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
}

func observeOpenLDAPPasswordPolicy(
	t *testing.T,
	address string,
) openLDAPPasswordPolicyObservation {
	t.Helper()
	var observation openLDAPPasswordPolicyObservation
	for range 2 {
		code, control := observeOpenLDAPPasswordPolicyBind(
			t,
			address,
			openLDAPPasswordPolicyUserDN,
			"wrong",
		)
		observation.badBindCodes = append(observation.badBindCodes, code)
		observation.badBindControls = append(
			observation.badBindControls,
			control,
		)
	}
	observation.lockedBindCode, observation.lockedBindControl =
		observeOpenLDAPPasswordPolicyBind(
			t,
			address,
			openLDAPPasswordPolicyUserDN,
			"secret",
		)

	root, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(root): %v", err)
	}
	defer root.Close()
	if err := root.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("root Bind(): %v", err)
	}
	result, err := root.Search(ldap.NewSearchRequest(
		openLDAPPasswordPolicyUserDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"pwdFailureTime", "pwdAccountLockedTime"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("root ppolicy Search() = %#v, %v", result, err)
	}
	observation.failureCount = len(
		result.Entries[0].GetRawAttributeValues("pwdFailureTime"),
	)
	observation.lockedAttribute = len(
		result.Entries[0].GetRawAttributeValues("pwdAccountLockedTime"),
	) == 1
	observation.accountUsability = observeOpenLDAPAccountUsability(
		t,
		address,
	)

	unlock := ldap.NewModifyRequest(openLDAPPasswordPolicyUserDN, nil)
	unlock.Delete("pwdAccountLockedTime", nil)
	if err := root.Modify(unlock); err != nil {
		t.Fatalf("unlock ppolicy account: %v", err)
	}
	connection := dialAndBindRawLDAP(
		t,
		address,
		openLDAPPasswordPolicyUserDN,
		"secret",
	)
	defer connection.Close()
	response := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawModifyReplaceRequest(
			openLDAPPasswordPolicyUserDN,
			"userPassword",
			"short",
		),
		rawControlWithoutValue(passwordPolicyControlOID),
	)
	if len(response.Children) < 2 {
		t.Fatalf("malformed ppolicy Modify response: %#v", response)
	}
	observation.qualityResultCode = rawLDAPResultCode(
		t,
		response.Children[1],
	)
	observation.qualityResultValue = bytes.Clone(
		rawLDAPResponseControl(t, response, passwordPolicyControlOID),
	)
	response = sendRawLDAPOperation(
		t,
		connection,
		3,
		rawModifyReplaceRequest(
			openLDAPPasswordPolicyUserDN,
			"userPassword",
			"long-password",
		),
		rawControlWithoutValue(passwordPolicyControlOID),
	)
	observation.checkerResultCode = rawLDAPResultCode(
		t,
		response.Children[1],
	)
	observation.checkerResultValue = bytes.Clone(
		rawLDAPResponseControls(response)[passwordPolicyControlOID],
	)
	return observation
}

func observeOpenLDAPPasswordPolicyBind(
	t *testing.T,
	address, dn, password string,
) (int64, []byte) {
	t.Helper()
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial ppolicy Bind server: %v", err)
	}
	defer connection.Close()
	response := sendRawLDAPOperation(
		t,
		connection,
		1,
		rawSimpleBindRequestVersion(3, dn, password),
		rawControlWithoutValue(passwordPolicyControlOID),
	)
	if len(response.Children) < 2 {
		t.Fatalf("malformed ppolicy Bind response: %#v", response)
	}
	return rawLDAPResultCode(t, response.Children[1]), bytes.Clone(
		rawLDAPResponseControl(t, response, passwordPolicyControlOID),
	)
}

func observeOpenLDAPAccountUsability(
	t *testing.T,
	address string,
) []byte {
	return observeOpenLDAPAccountUsabilityFor(
		t,
		address,
		openLDAPPasswordPolicyUserDN,
	)
}

func observeOpenLDAPAccountUsabilityFor(
	t *testing.T,
	address, userDN string,
) []byte {
	t.Helper()
	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"secret",
	)
	defer connection.Close()
	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawSyncSearchRequestFor(
			t,
			userDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			"(objectClass=*)",
		),
		rawControlWithoutValue(accountUsabilityControlOID),
	)
	entry := readRawLDAPPacket(t, connection)
	if len(entry.Children) < 2 ||
		entry.Children[1].Tag != ldapwire.ApplicationSearchResultEntry {
		t.Fatalf("account usability entry = %#v", entry)
	}
	value := bytes.Clone(
		rawLDAPResponseControl(t, entry, accountUsabilityControlOID),
	)
	done := readRawLDAPPacket(t, connection)
	if len(done.Children) < 2 ||
		done.Children[1].Tag != ldapwire.ApplicationSearchResultDone ||
		rawLDAPResultCode(t, done.Children[1]) != int64(ldap.LDAPResultSuccess) {
		t.Fatalf("account usability done = %#v", done)
	}
	return value
}

func equalOpenLDAPPasswordPolicyObservation(
	left, right openLDAPPasswordPolicyObservation,
) bool {
	if len(left.badBindCodes) != len(right.badBindCodes) ||
		len(left.badBindControls) != len(right.badBindControls) {
		return false
	}
	for index := range left.badBindCodes {
		if left.badBindCodes[index] != right.badBindCodes[index] ||
			!bytes.Equal(
				left.badBindControls[index],
				right.badBindControls[index],
			) {
			return false
		}
	}
	return left.lockedBindCode == right.lockedBindCode &&
		bytes.Equal(left.lockedBindControl, right.lockedBindControl) &&
		left.failureCount == right.failureCount &&
		left.lockedAttribute == right.lockedAttribute &&
		bytes.Equal(left.accountUsability, right.accountUsability) &&
		left.qualityResultCode == right.qualityResultCode &&
		bytes.Equal(left.qualityResultValue, right.qualityResultValue) &&
		left.checkerResultCode == right.checkerResultCode &&
		bytes.Equal(left.checkerResultValue, right.checkerResultValue)
}

func trimLDAPURI(uri string) string {
	const prefix = "ldap://"
	if len(uri) >= len(prefix) && uri[:len(prefix)] == prefix {
		return uri[len(prefix):]
	}
	return uri
}
