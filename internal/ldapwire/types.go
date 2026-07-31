package ldapwire

import "github.com/wangle201210/ldap-go/internal/directory"

const (
	ApplicationBindRequest           = 0
	ApplicationBindResponse          = 1
	ApplicationUnbindRequest         = 2
	ApplicationSearchRequest         = 3
	ApplicationSearchResultEntry     = 4
	ApplicationSearchResultDone      = 5
	ApplicationModifyRequest         = 6
	ApplicationModifyResponse        = 7
	ApplicationAddRequest            = 8
	ApplicationAddResponse           = 9
	ApplicationDeleteRequest         = 10
	ApplicationDeleteResponse        = 11
	ApplicationModifyDNRequest       = 12
	ApplicationModifyDNResponse      = 13
	ApplicationCompareRequest        = 14
	ApplicationCompareResponse       = 15
	ApplicationAbandonRequest        = 16
	ApplicationSearchResultReference = 19
	ApplicationExtendedRequest       = 23
	ApplicationExtendedResponse      = 24
	ApplicationIntermediateResponse  = 25
)

const DefaultMaxMessageSize int64 = 16 << 20

type Message struct {
	ID       int64
	Request  Request
	Controls []Control
}

type Request interface {
	ApplicationTag() uint64
}

type BindRequest struct {
	Version        int
	Name           string
	Authentication Authentication
}

func (BindRequest) ApplicationTag() uint64 { return ApplicationBindRequest }

type Authentication struct {
	Simple             []byte
	SASLMechanism      string
	SASLCredentials    []byte
	IsSASL             bool
	HasSASLCredentials bool
}

type SearchRequest struct {
	BaseDN       string
	Scope        directory.Scope
	DerefAliases int
	SizeLimit    int
	TimeLimit    int
	TypesOnly    bool
	Filter       directory.Filter
	Attributes   []string
}

const (
	NeverDerefAliases = iota
	DerefInSearching
	DerefFindingBaseObject
	DerefAlways
)

func (SearchRequest) ApplicationTag() uint64 { return ApplicationSearchRequest }

type UnbindRequest struct{}

func (UnbindRequest) ApplicationTag() uint64 { return ApplicationUnbindRequest }

type AddRequest struct {
	Entry directory.Entry
}

func (AddRequest) ApplicationTag() uint64 { return ApplicationAddRequest }

type ModificationOperation int

const (
	ModificationAdd ModificationOperation = iota
	ModificationDelete
	ModificationReplace
	ModificationIncrement
)

type Modification struct {
	Operation ModificationOperation
	Attribute directory.Attribute
}

type ModifyRequest struct {
	DN      string
	Changes []Modification
}

func (ModifyRequest) ApplicationTag() uint64 { return ApplicationModifyRequest }

type DeleteRequest struct {
	DN string
}

func (DeleteRequest) ApplicationTag() uint64 { return ApplicationDeleteRequest }

type ModifyDNRequest struct {
	DN             string
	NewRDN         string
	DeleteOldRDN   bool
	NewSuperior    string
	HasNewSuperior bool
}

func (ModifyDNRequest) ApplicationTag() uint64 { return ApplicationModifyDNRequest }

type CompareRequest struct {
	DN        string
	Attribute string
	Assertion []byte
}

func (CompareRequest) ApplicationTag() uint64 { return ApplicationCompareRequest }

type AbandonRequest struct {
	MessageID int64
}

func (AbandonRequest) ApplicationTag() uint64 { return ApplicationAbandonRequest }

type ExtendedRequest struct {
	Name     string
	Value    []byte
	HasValue bool
}

func (ExtendedRequest) ApplicationTag() uint64 { return ApplicationExtendedRequest }

type UnsupportedRequest struct {
	Tag uint64
}

func (request UnsupportedRequest) ApplicationTag() uint64 { return request.Tag }

type Control struct {
	OID      string
	Critical bool
	Value    []byte
	HasValue bool
}

type ResultCode int

const (
	ResultSuccess                      ResultCode = 0
	ResultOperationsError              ResultCode = 1
	ResultProtocolError                ResultCode = 2
	ResultTimeLimitExceeded            ResultCode = 3
	ResultSizeLimitExceeded            ResultCode = 4
	ResultCompareFalse                 ResultCode = 5
	ResultCompareTrue                  ResultCode = 6
	ResultAuthMethodNotSupported       ResultCode = 7
	ResultStrongerAuthRequired         ResultCode = 8
	ResultReferral                     ResultCode = 10
	ResultAdminLimitExceeded           ResultCode = 11
	ResultUnavailableCriticalExtension ResultCode = 12
	ResultConfidentialityRequired      ResultCode = 13
	ResultSASLBindInProgress           ResultCode = 14
	ResultNoSuchAttribute              ResultCode = 16
	ResultUndefinedAttributeType       ResultCode = 17
	ResultInappropriateMatching        ResultCode = 18
	ResultConstraintViolation          ResultCode = 19
	ResultAttributeOrValueExists       ResultCode = 20
	ResultInvalidAttributeSyntax       ResultCode = 21
	ResultNoSuchObject                 ResultCode = 32
	ResultAliasProblem                 ResultCode = 33
	ResultInvalidDNSyntax              ResultCode = 34
	ResultAliasDereferencingProblem    ResultCode = 36
	ResultInappropriateAuthentication  ResultCode = 48
	ResultInvalidCredentials           ResultCode = 49
	ResultInsufficientAccessRights     ResultCode = 50
	ResultBusy                         ResultCode = 51
	ResultUnavailable                  ResultCode = 52
	ResultUnwillingToPerform           ResultCode = 53
	ResultLoopDetect                   ResultCode = 54
	ResultNamingViolation              ResultCode = 64
	ResultObjectClassViolation         ResultCode = 65
	ResultNotAllowedOnNonLeaf          ResultCode = 66
	ResultNotAllowedOnRDN              ResultCode = 67
	ResultEntryAlreadyExists           ResultCode = 68
	ResultObjectClassModsProhibited    ResultCode = 69
	ResultAffectsMultipleDSAs          ResultCode = 71
	ResultVirtualListViewError         ResultCode = 76
	ResultOther                        ResultCode = 80
	ResultCanceled                     ResultCode = 118
	ResultNoSuchOperation              ResultCode = 119
	ResultTooLate                      ResultCode = 120
	ResultCannotCancel                 ResultCode = 121
	ResultAssertionFailed              ResultCode = 122
	ResultSyncRefreshRequired          ResultCode = 4096
	ResultTransactionIDInvalid         ResultCode = 0x4121
)

type Result struct {
	Code              ResultCode
	MatchedDN         string
	DiagnosticMessage string
	Referrals         []string
}
