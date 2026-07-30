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
	Mode       grantMode
	Privileges Privilege
	SelfValue  bool
}

type DNStyle uint8

const (
	DNAny DNStyle = iota
	DNExact
	DNOne
	DNSubtree
	DNChildren
	DNRegex
)

type DNMatcher struct {
	Style   DNStyle
	DN      directory.DN
	Pattern *regexp.Regexp
}

type TargetSelector struct {
	DN         DNMatcher
	Attributes []string
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
	WhoSSF
)

type WhoMatcher struct {
	Kind             WhoKind
	DN               DNMatcher
	Attribute        string
	GroupObjectClass string
	GroupAttribute   string
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
	DN  string
	SSF int
}

type Target struct {
	Entry     directory.Entry
	Attribute string
	Value     []byte
	DNValued  bool
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
