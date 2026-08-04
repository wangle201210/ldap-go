package acl

import (
	"regexp"

	"github.com/wangle201210/ldap-go/internal/directory"
)

type Privilege uint16

const (
	Disclose Privilege = 1 << iota
	Auth
	Compare
	Search
	Read
	WriteAdd
	WriteDelete
	Manage
)

const Write = WriteAdd | WriteDelete

const (
	NoneLevel     Privilege = 0
	DiscloseLevel           = Disclose
	AuthLevel               = DiscloseLevel | Auth
	CompareLevel            = AuthLevel | Compare
	SearchLevel             = CompareLevel | Search
	ReadLevel               = SearchLevel | Read
	WriteLevel              = ReadLevel | WriteAdd | WriteDelete
	ManageLevel             = WriteLevel | Manage
)

type Control uint8

const (
	ControlStop Control = iota
	ControlContinue
	ControlBreak
)

type grantMode uint8

const (
	grantSet grantMode = iota
	grantAdd
	grantRemove
	grantIdentity
)

type Grant struct {
	Mode          grantMode
	Privileges    Privilege
	SelfValue     bool
	RealSelfValue bool
}

type DNStyle uint8

const (
	DNAny DNStyle = iota
	DNExact
	DNOne
	DNSubtree
	DNChildren
	DNLevel
	DNRegex
)

type DNMatcher struct {
	Style   DNStyle
	DN      directory.DN
	Pattern *regexp.Regexp
	Raw     string
	Expand  bool
	Level   int
}

type TargetSelector struct {
	DN         DNMatcher
	Attributes []string
	Filter     *directory.Filter
	Value      *ValueSelector
}

type ValueSelector struct {
	Style        DNStyle
	MatchingRule string
	Assertion    []byte
	Pattern      *regexp.Regexp
}

type WhoKind uint8

const (
	WhoAny WhoKind = iota
	WhoAnonymous
	WhoUsers
	WhoSelf
	WhoDN
	WhoDNAttribute
	WhoGroup
	WhoPeerName
	WhoSockName
	WhoDomain
	WhoSockURL
	WhoSet
	WhoACI
	WhoSSF
)

type StringStyle uint8

const (
	StringExact StringStyle = iota
	StringRegex
	StringSubtree
	StringIP
	StringIPv6
	StringPath
)

type StringMatcher struct {
	Style   StringStyle
	Value   string
	Pattern *regexp.Regexp
	Expand  bool
}

type SSFKind uint8

const (
	SSFOverall SSFKind = iota
	SSFTransport
	SSFTLS
	SSFSASL
)

type WhoMatcher struct {
	Kind             WhoKind
	Real             bool
	DN               DNMatcher
	Attribute        string
	GroupObjectClass string
	GroupAttribute   string
	GroupPattern     string
	GroupExpand      bool
	Connection       StringMatcher
	SetPattern       string
	SetExpand        bool
	ACIAttribute     string
	SelfLevel        int
	SSFKind          SSFKind
	MinimumSSF       int
}

type ByClause struct {
	Who     []WhoMatcher
	Grant   Grant
	Control Control
}

type Rule struct {
	Order  int
	Target TargetSelector
	By     []ByClause
	Raw    string
}

type Subject struct {
	DN           string
	RealDN       string
	PeerName     string
	SockName     string
	Domain       string
	SockURL      string
	SSF          int
	TransportSSF int
	TLSSSF       int
	SASLSSF      int
}

type Target struct {
	Entry     directory.Entry
	Attribute string
	Value     []byte
	DNValued  bool
	Schema    TargetSchema
}

type TargetSchema interface {
	directory.ValueMatcher
	directory.AttributeResolver
	AttributeDescriptionSubtype(candidate, requested string) bool
	EntryHasObjectClass(entry directory.Entry, objectClass string) bool
	ObjectClassAllowsAttribute(objectClass, attribute string) (bool, bool)
	HasAttributeType(attribute string) bool
	IsOperational(attribute string) bool
	IsDNValued(attribute string) bool
	IsDNReferenceValued(attribute string) bool
	IsACIValued(attribute string) bool
	NormalizeEqualityValue(attribute string, value []byte) ([]byte, error)
}

type matchContext struct {
	dn    []string
	value []string
}

type EntryReader interface {
	Get(dn directory.DN) (directory.Entry, error)
}

type databaseRules struct {
	Suffix        directory.DN
	Rules         []Rule
	AddContentACL bool
}

type Policy struct {
	global    []Rule
	databases []databaseRules
}

type LoadResult struct {
	RuleSets int
	Rules    int
}
