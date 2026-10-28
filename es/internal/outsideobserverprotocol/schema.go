package outsideobserverprotocol

// All structures in this package are untrusted parsed values. In particular,
// a true process claim or a matching digest is not proof of an observation,
// authenticated peer, durable commit, consumed receipt, or execution authority.

type EvidenceFrameV1 struct {
	Schema             string
	Version            int64
	RunID              string
	EntryDigest        string
	PermitDigest       string
	SourceInstanceID   string
	Epoch              int64
	Sequence           int64
	ProducerRole       string
	QualifiedClockRef  string
	ObservedTime       int64
	PreviousRecordHash string
	PayloadType        string
	PayloadLength      int64
	PayloadSHA256      string
	Payload            []byte
	PayloadValue       any
	RecordHash         string
}

type AckV1 struct {
	Schema           string
	Version          int64
	RunID            string
	SourceInstanceID string
	Epoch            int64
	Sequence         int64
	RecordHash       string
	JournalSegmentID string
	DurableOffset    int64
	SourceState      string
	CommitID         string
}

type JournalHeaderV2 struct {
	Schema                         string
	Version                        int64
	RunID                          string
	SourceInstanceID               string
	EntryDigest                    string
	PermitDigest                   string
	Epoch                          int64
	EndpointNonce                  string
	ObserverSessionNonce           string
	ReceiverSessionNonce           string
	JournalNonce                   string
	ObserverSPIFFEID               string
	ReceiverSPIFFEID               string
	PermitConsumptionReceiptSHA256 string
	SessionBindingSHA256           string
	JournalIdentitySHA256          string
}

type JournalFrameV2 struct {
	Schema                string
	Version               int64
	EvidenceRecordHash    string
	ExactFrameBytes       []byte
	FrameLength           int64
	FrameSHA256           string
	JournalIdentitySHA256 string
	PayloadType           string
	SessionBindingSHA256  string
	SourceSequence        int64
	TransactionKind       string
	TransactionSequence   int64
	EmbeddedFrame         EvidenceFrameV1
}

type JournalCommitV2 struct {
	Schema                   string
	Version                  int64
	CommitHash               string
	CommitID                 string
	DurableOffsetAfterCommit int64
	EvidenceRecordHash       string
	FrameRecordSHA256        string
	JournalIdentitySHA256    string
	NextSourceState          string
	PreviousCommitHash       string
	SessionBindingSHA256     string
	SourceSequence           int64
	TransactionKind          string
	TransactionPayloadSHA256 string
	TransactionSequence      int64
}

type ProtocolLimits struct {
	EvidenceFrameMaxBytes      int64
	EvidencePayloadMaxBytes    int64
	MaxFramesPerSession        int64
	MaxFramesPerSource         int64
	MaxSources                 int64
	PerSourceAggregateMaxBytes int64
	SessionAggregateMaxBytes   int64
}

type ObserverHelloV1 struct {
	Schema                   string
	Version                  int64
	RunID                    string
	EntryDigest              string
	PermitDigest             string
	PermitNonce              string
	SourceInstanceID         string
	Epoch                    int64
	ObserverSessionNonce     string
	EndpointNonce            string
	ObserverSPIFFEID         string
	ExpectedReceiverSPIFFEID string
	RequestedLimits          ProtocolLimits
}

type ReceiverHelloV1 struct {
	Schema                   string
	Version                  int64
	RunID                    string
	EntryDigest              string
	ReceiverSessionNonce     string
	EndpointNonce            string
	ReceiverSPIFFEID         string
	ExpectedObserverSPIFFEID string
	AcceptedLimits           ProtocolLimits
}

type SupervisorStartedV1 struct {
	ParentPID                int64
	PID                      int64
	ProcessGroupID           int64
	ProcStartToken           string
	PIDNamespaceDevice       int64
	PIDNamespaceInode        int64
	MountNamespaceDevice     int64
	MountNamespaceInode      int64
	ExecutableSHA256         string
	PIDFDBound               bool
	ExecutionAuthorityDigest string
}

type SupervisorExitObservedV1 struct {
	PID            int64
	ProcStartToken string
	WaitCodeKind   string
	ExitCode       *int64
	Signal         *int64
	CoreDumped     bool
	ObservedByPID  int64
	IdentityMatch  bool
}

type SupervisorReapedV1 struct {
	PID                  int64
	ProcStartToken       string
	PIDFDBound           bool
	ReapCount            int64
	WaitOwnerPID         int64
	TerminalStatusSHA256 string
}

type NamespaceDrainedV1 struct {
	SupervisorPID         int64
	TermSignalCount       int64
	KillSignalCount       int64
	ReapedDescendantCount int64
	RemainingPIDs         []int64
	WaitIDAllResult       string
}

type SourceCompleteV1 struct {
	ResultKind                     string
	SupervisorTerminalStatusSHA256 string
	SupervisorReapedOnce           bool
	NamespaceDrained               bool
	LastNonfinalRecordHash         string
	EvidenceFailure                bool
	TerminalReason                 string
}

// DerivedSourceState is only an internal representation of a future recovery
// result. Stage A provides no parser, serializer, loader, store, or accepting
// function for caller-supplied SOURCE_STATE.json bytes.
type DerivedSourceState struct {
	Schema                string
	Version               int64
	RunID                 string
	SourceInstanceID      string
	Epoch                 int64
	EntryDigest           string
	PermitDigest          string
	EndpointNonce         string
	ReceiverSessionNonce  string
	JournalNonce          string
	SessionBindingSHA256  string
	JournalIdentitySHA256 string
	SourceSequence        int64
	TransactionSequence   int64
	LastRecordHash        string
	CommitHash            string
	CommitID              string
	DurableOffset         int64
	SourceState           string
}
