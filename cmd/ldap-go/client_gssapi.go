package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/saslkrb5"
)

func (options *ldapClientOptions) bindSASLGSSAPI(
	connection net.Conn,
	host string,
	password []byte,
	hasPassword bool,
	messageID *int64,
) error {
	initiator, err := options.newGSSAPIInitiator(password, hasPassword)
	if err != nil {
		return fmt.Errorf("initialize SASL GSSAPI credentials: %w", err)
	}
	defer initiator.Close()

	var channelBinding []byte
	if options.gssapiChannelBinding == saslkrb5.ChannelBindingTLSServerEndpoint {
		switching, ok := connection.(*ldapClientSASLSwitchConnection)
		if !ok {
			return errors.New("tls-server-end-point channel binding requires a switchable TLS connection")
		}
		channelBinding, err = switching.gssapiChannelBinding()
		if err != nil {
			return fmt.Errorf("initialize SASL GSSAPI channel binding: %w", err)
		}
		if len(channelBinding) == 0 {
			return errors.New("tls-server-end-point channel binding requires TLS")
		}
	}
	defer clear(channelBinding)
	initial, err := initiator.InitialToken("ldap/"+host, channelBinding)
	if err != nil {
		return fmt.Errorf("initialize SASL GSSAPI context: %w", err)
	}
	defer clear(initial)
	first, err := options.exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		"GSSAPI",
		initial,
		true,
	)
	if err != nil {
		return fmt.Errorf("SASL GSSAPI AP-REQ: %w", err)
	}
	if first.code != ldap.LDAPResultSaslBindInProgress {
		return fmt.Errorf("SASL GSSAPI AP-REQ: %w", first.err())
	}
	if !first.hasServerCredentials || len(first.serverCredentials) == 0 {
		return errors.New("SASL GSSAPI acceptor omitted AP-REP")
	}
	if err := initiator.AcceptAPRep(first.serverCredentials); err != nil {
		return fmt.Errorf("verify SASL GSSAPI acceptor: %w", err)
	}

	second, err := options.exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		"GSSAPI",
		nil,
		false,
	)
	if err != nil {
		return fmt.Errorf("request SASL GSSAPI security layers: %w", err)
	}
	if second.code != ldap.LDAPResultSaslBindInProgress {
		return fmt.Errorf("request SASL GSSAPI security layers: %w", second.err())
	}
	if !second.hasServerCredentials || len(second.serverCredentials) == 0 {
		return errors.New("SASL GSSAPI acceptor omitted its security-layer offer")
	}
	key, err := initiator.ContextKey()
	if err != nil {
		return err
	}
	defer clear(key.KeyValue)
	securityState, err := initiator.SecurityState()
	if err != nil {
		return err
	}
	offer, err := saslkrb5.Unwrap(
		second.serverCredentials,
		key,
		true,
		securityState.AcceptorSubkey,
		securityState.ReceiveSequence,
	)
	if err != nil {
		return fmt.Errorf("verify SASL GSSAPI security-layer offer: %w", err)
	}
	securityState.ReceiveSequence++
	layers, peerMaximum, err := saslkrb5.DecodeOffer(offer)
	clear(offer)
	if err != nil {
		return err
	}
	properties, err := parseLDAPClientDigestMD5SecurityProperties(options.saslSecurity)
	if err != nil {
		return err
	}
	selection := byte(0)
	localMaximum := uint32(0)
	keySSF, err := saslkrb5.SecurityStrength(key)
	if err != nil {
		return fmt.Errorf("determine SASL GSSAPI context strength: %w", err)
	}
	if layers&saslkrb5.SecurityConfidentiality != 0 &&
		properties.minimumSSF <= keySSF && properties.maximumSSF >= keySSF &&
		properties.maxBufferSize != 0 {
		selection = saslkrb5.SecurityConfidentiality
		localMaximum = properties.maxBufferSize
	} else if layers&saslkrb5.SecurityIntegrity != 0 &&
		properties.minimumSSF <= 1 && properties.maximumSSF >= 1 &&
		properties.maxBufferSize != 0 {
		selection = saslkrb5.SecurityIntegrity
		localMaximum = properties.maxBufferSize
	} else if layers&saslkrb5.SecurityNone != 0 && properties.minimumSSF == 0 {
		selection = saslkrb5.SecurityNone
	}
	if selection == 0 {
		return errors.New("SASL GSSAPI acceptor offers no security layer allowed by -O")
	}
	payload, err := saslkrb5.EncodeNegotiation(
		selection,
		localMaximum,
		options.saslAuthorization,
	)
	if err != nil {
		return err
	}
	wrapped, err := saslkrb5.Wrap(
		payload,
		key,
		false,
		securityState.AcceptorSubkey,
		securityState.SendSequence,
	)
	clear(payload)
	if err != nil {
		return fmt.Errorf("encode SASL GSSAPI security-layer selection: %w", err)
	}
	securityState.SendSequence++
	defer clear(wrapped)
	final, err := options.exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		"GSSAPI",
		wrapped,
		true,
	)
	if err != nil {
		return fmt.Errorf("complete SASL GSSAPI bind: %w", err)
	}
	if final.code != ldap.LDAPResultSuccess {
		return fmt.Errorf("complete SASL GSSAPI bind: %w", final.err())
	}
	if final.hasServerCredentials {
		return errors.New("SASL GSSAPI acceptor returned unexpected completion data")
	}
	if selection == saslkrb5.SecurityNone {
		return nil
	}
	switching, ok := connection.(*ldapClientSASLSwitchConnection)
	if !ok {
		return errors.New("SASL GSSAPI integrity requires a switchable connection")
	}
	if err := switching.installGSSAPISecurity(
		key,
		selection == saslkrb5.SecurityConfidentiality,
		securityState,
		peerMaximum,
		localMaximum,
	); err != nil {
		return fmt.Errorf("install SASL GSSAPI security layer: %w", err)
	}
	return nil
}

func (options *ldapClientOptions) newGSSAPIInitiator(
	password []byte,
	hasPassword bool,
) (*saslkrb5.Initiator, error) {
	configuration := ldapClientKerberosConfigurationPath(os.LookupEnv)
	if hasPassword {
		username, realm, err := ldapClientKerberosPrincipal(
			options.saslAuthentication,
			options.saslRealm,
		)
		if err != nil {
			return nil, err
		}
		return saslkrb5.NewInitiatorWithPassword(
			username,
			realm,
			string(password),
			configuration,
		)
	}
	keytabValue, keytabVariable := ldapClientFirstEnvironment(
		os.LookupEnv,
		"KRB5_CLIENT_KTNAME",
		"KRB5_KTNAME",
	)
	if keytabValue != "" {
		if options.saslAuthentication == "" {
			return nil, errors.New("SASL GSSAPI keytab credentials require -U")
		}
		path, err := ldapClientKerberosFileCredential(
			keytabValue,
			keytabVariable,
			true,
		)
		if err != nil {
			return nil, err
		}
		username, realm, err := ldapClientKerberosPrincipal(
			options.saslAuthentication,
			options.saslRealm,
		)
		if err != nil {
			return nil, err
		}
		return saslkrb5.NewInitiatorWithKeytab(
			username,
			realm,
			path,
			configuration,
		)
	}
	cache, configured := os.LookupEnv("KRB5CCNAME")
	if configured && strings.TrimSpace(cache) != "" {
		var err error
		cache, err = ldapClientKerberosFileCredential(cache, "KRB5CCNAME", false)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		cache, err = ldapClientDefaultKerberosCCache()
		if err != nil {
			return nil, err
		}
	}
	return saslkrb5.NewInitiatorFromCCache(cache, configuration)
}

func ldapClientKerberosPrincipal(authenticationID, configuredRealm string) (string, string, error) {
	authenticationID = strings.TrimSpace(authenticationID)
	configuredRealm = strings.TrimSpace(configuredRealm)
	at := strings.LastIndexByte(authenticationID, '@')
	if at <= 0 || at == len(authenticationID)-1 {
		return authenticationID, configuredRealm, nil
	}
	realm := authenticationID[at+1:]
	if configuredRealm != "" && !strings.EqualFold(configuredRealm, realm) {
		return "", "", fmt.Errorf("SASL GSSAPI authcid realm %q conflicts with realm %q", realm, configuredRealm)
	}
	return authenticationID[:at], realm, nil
}

func ldapClientKerberosConfigurationPath(lookup func(string) (string, bool)) string {
	if configured, ok := lookup("KRB5_CONFIG"); ok {
		for _, candidate := range filepath.SplitList(configured) {
			if candidate = strings.TrimSpace(candidate); candidate != "" {
				return candidate
			}
		}
	}
	if runtime.GOOS == "windows" {
		return `C:\Windows\krb5.ini`
	}
	if runtime.GOOS == "darwin" {
		const path = "/Library/Preferences/edu.mit.Kerberos"
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return "/etc/krb5.conf"
}

func ldapClientFirstEnvironment(lookup func(string) (string, bool), names ...string) (string, string) {
	for _, name := range names {
		if value, ok := lookup(name); ok && strings.TrimSpace(value) != "" {
			return value, name
		}
	}
	return "", ""
}

func ldapClientKerberosFileCredential(value, variable string, allowWritable bool) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s is empty", variable)
	}
	kind, path, hasKind := strings.Cut(value, ":")
	if !hasKind || (len(kind) == 1 && len(path) > 0 && (path[0] == '\\' || path[0] == '/')) {
		return value, nil
	}
	if strings.EqualFold(kind, "FILE") || (allowWritable && strings.EqualFold(kind, "WRFILE")) {
		if path == "" {
			return "", fmt.Errorf("%s FILE credential path is empty", variable)
		}
		return path, nil
	}
	return "", fmt.Errorf("%s credential type %q is unsupported; use FILE", variable, kind)
}

func ldapClientDefaultKerberosCCache() (string, error) {
	current, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("resolve default Kerberos credential cache: %w", err)
	}
	uid := strings.TrimSpace(current.Uid)
	if _, err := strconv.ParseUint(uid, 10, 64); err != nil {
		return "", errors.New("KRB5CCNAME is required when the operating system has no numeric UID")
	}
	return filepath.Join(os.TempDir(), "krb5cc_"+uid), nil
}
