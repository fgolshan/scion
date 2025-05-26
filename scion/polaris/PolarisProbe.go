// contains the code to send a Polaris Probe

package polaris

import (
	"context"
	"math/rand"
	"net"
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

// Types and structures ----------------------------------------------------

type returnType int

const (
	PProbe returnType = iota
	PCA
	Empty
)

type PProbeResult struct {
	StructType returnType
	Pprobe     slayers.SCMPPProbeRequest
	PCA        slayers.SCMPPCongestionAlert
}

type HandlerReturn struct {
	structType returnType
	echoReply  snet.SCMPEchoReply
	pCA        snet.SCMPPCongestionAlert
}

type scmpHandler struct {
	replies chan<- reply
}

// Update contains the information for a single hop.
type Update struct {
	// Index indicates the hop index in the path.
	Index int
	// Remote is the remote router.
	Remote snet.SCIONAddress
	// Interface is the interface ID of the remote router.
	Interface uint64
	// RTTs are the RTTs for this hop. To detect whether there was a timeout the
	// value of the RTT can be compared against the timeout value from the
	// configuration.
	RTTs []time.Duration
}

func (u Update) empty() bool {
	return u.Index == 0 && u.Remote == (snet.SCIONAddress{}) && u.Interface == 0 && len(u.RTTs) == 0
}

// Config configures the polaris run.
type Config struct {
	Local   addr.Addr
	Remote  addr.Addr
	NextHop *net.UDPAddr

	Topology    snet.Topology
	MTU         uint16
	PathEntry   snet.Path
	PayloadSize uint
	EPIC        bool

	// ProbesPerHop indicates how many probes should be done per hop.
	ProbesPerHop int
	// ErrHandler is invoked for every error that does not cause tracerouting to
	// abort. Execution time must be small, as it is run synchronously.
	ErrHandler func(error)
	// Update handler is invoked for every hop. Execution time must be
	// small, as it is run synchronously.
	UpdateHandler func(Update)
}

type reply struct {
	Received time.Time
	Reply    HandlerReturn
	Remote   snet.SCIONAddress
	Error    error
}

type Pprobe struct {
	probesPerHop  int
	timeout       time.Duration
	conn          snet.PacketConn
	local         addr.Addr
	remote        addr.Addr
	errHandler    func(error)
	updateHandler func(Update)
	sequence      uint16

	replies <-chan reply

	path    snet.Path
	nextHop *net.UDPAddr
	epic    bool
	id      uint16
	index   int
}

func Run(ctx context.Context, cfg Config) (PProbeResult, error) {
	if _, isEmpty := cfg.PathEntry.Dataplane().(path.Empty); isEmpty {
		return PProbeResult{StructType: Empty}, serrors.New("empty path is not allowed for traceroute")
	}
	replies := make(chan reply, 10)
	sn := &snet.SCIONNetwork{
		SCMPHandler: scmpHandler{replies: replies},
		Topology:    cfg.Topology,
	}

	// We need to manufacture a netip.UDPAddr as we're constrained by the sn API.
	netUdpAddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(cfg.Local.Host.IP(), 0))
	conn, err := sn.OpenRaw(ctx, netUdpAddr)
	if err != nil {
		return PProbeResult{StructType: Empty}, err
	}
	// Get our real local address.
	asNetipAddr, ok := netip.AddrFromSlice(conn.LocalAddr().(*net.UDPAddr).IP)
	if !ok {
		panic("Invalid Local IP address")
	}

	// Seed the random number generator
	rand.New(rand.NewSource(42))

	// Generate a random uint16
	sequence := uint16(rand.Intn(1 << 16)) // 1 << 16 is 65536

	local := cfg.Local
	local.Host = addr.HostIP(asNetipAddr)
	t := Pprobe{
		probesPerHop:  cfg.ProbesPerHop,
		conn:          conn,
		local:         local,
		remote:        cfg.Remote,
		replies:       replies,
		errHandler:    cfg.ErrHandler,
		updateHandler: cfg.UpdateHandler,
		id:            uint16(conn.LocalAddr().(*net.UDPAddr).Port),
		path:          cfg.PathEntry,
		sequence:      sequence,
		timeout:       time.Second * 5,
		nextHop:       cfg.NextHop,
		epic:          cfg.EPIC,
	}
	return t.Pprobe(ctx)
}

func (t *Pprobe) Pprobe(ctx context.Context) (PProbeResult, error) {
	scionPath, ok := t.path.Dataplane().(path.SCION)
	// log.Debug("SCION path", "Path", scionPath)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		defer log.HandlePanic()
		t.drain(ctx)
	}()

	if !ok {
		return PProbeResult{StructType: Empty}, serrors.New("only SCION path allowed for pprobe", "type", common.TypeOf(t.path.Dataplane()))
	}

	var idxPath scion.Decoded
	if err := idxPath.DecodeFromBytes(scionPath.Raw); err != nil {
		return PProbeResult{StructType: Empty}, serrors.Wrap("decoding path", err)
	}
	// log.Debug("Decoded path", "Path", idxPath)

	// Set up the SCION path for the remote destination
	scionAlertPath, err := path.NewSCIONFromDecoded(idxPath)
	if err != nil {
		return PProbeResult{StructType: Empty}, serrors.Wrap("setting alert flag", err)
	}
	// log.Debug("SCION alert path", "Path", scionAlertPath)

	var alertPath snet.DataplanePath
	if t.epic {
		epicAlertPath, err := path.NewEPICDataplanePath(
			scionAlertPath,
			t.path.Metadata().EpicAuths,
		)
		if err != nil {
			return PProbeResult{StructType: Empty}, err
		}
		alertPath = epicAlertPath
	} else {
		alertPath = scionAlertPath
	}

	// log.Debug("Alert path", "Path", alertPath)

	// Construct the packet
	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: t.remote,
			Source:      t.local,
			Path:        alertPath,
			Payload: snet.SCMPPProbeRequest{
				NextHdr:           202, //slayers.L4SCMP,
				ExtLen:            0,
				RequestIdentifier: t.id,
				SequenceNumber:    uint16(t.sequence),
				CumQueuingDelay:   0,
				ASIdentifier:      0,
				InterfaceID:       0,
				BottleneckShare:   65535, // max uint 16 value
			},
		},
	}

	log.Debug("Next Hop", "NextHop", t.nextHop, "Packet", pkt)
	if err := t.conn.WriteTo(pkt, t.nextHop); err != nil {
		return PProbeResult{StructType: Empty}, serrors.Wrap("writing", err)
	}

	// Wait for a reply

	var scmpPp slayers.SCMPPProbeRequest
	var scmpPCA slayers.SCMPPCongestionAlert
	var ReturnVal PProbeResult

	select {
	case <-time.After(t.timeout):
		log.Debug("Timeout waiting for reply")
		return PProbeResult{StructType: Empty}, serrors.New("timeout waiting for reply")
	case reply := <-t.replies:
		log.Debug("Received reply", "Reply", reply.Reply, "Error", reply.Error)
		if reply.Error != nil {
			if t.errHandler != nil {
				return PProbeResult{StructType: Empty}, serrors.Wrap("error in reply", reply.Error)
			}
		}
		if reply.Reply.structType == Empty {
			return PProbeResult{StructType: Empty}, serrors.Wrap("no packet received. Empty HandleReturn", err)
		} else if reply.Reply.structType == PProbe {

			log.Debug("Received reply", "t.id", t.id, "reply.Reply.Identifier", reply.Reply.echoReply.Identifier, "reply.Reply.SeqNumber", reply.Reply.echoReply.SeqNumber)
			if t.id != reply.Reply.echoReply.Identifier {
				if t.errHandler != nil {
					return PProbeResult{StructType: Empty}, serrors.New("wrong SCMP ID", "expected", t.id, "actual", reply.Reply.echoReply.Identifier)
				}
			}
			errPp := scmpPp.DecodeFromBytes(reply.Reply.echoReply.Payload, gopacket.NilDecodeFeedback)
			if errPp != nil {
				log.Debug("Parsing SCMPProbeRequest failed:", "err", errPp)
				return PProbeResult{StructType: Empty}, serrors.Wrap("parsing SCMPProbeRequest", errPp)
			}
			log.Debug("SCMPProbeRequest reply:", "scmpPp", scmpPp)
			ReturnVal = PProbeResult{
				StructType: PProbe,
				Pprobe:     scmpPp,
			}
		} else {
			// In this case it has to be a congestion alert
			log.Debug("Received reply", "t.id", t.id, "reply.Reply.Identifier", reply.Reply.pCA.RequestIdentifier, "reply.Reply.SeqNumber", reply.Reply.pCA.SequenceNumber)
			if t.id != reply.Reply.pCA.RequestIdentifier {
				if t.errHandler != nil {
					return PProbeResult{StructType: Empty}, serrors.New("wrong SCMP ID", "expected", t.id, "actual", reply.Reply.pCA.RequestIdentifier)
				}
			}

			scmpPCA.ASIdentifier = reply.Reply.pCA.ASIdentifier
			scmpPCA.InterfaceID = reply.Reply.pCA.InterfaceID
			scmpPCA.RequestIdentifier = reply.Reply.pCA.RequestIdentifier
			scmpPCA.SequenceNumber = reply.Reply.pCA.SequenceNumber
			ReturnVal = PProbeResult{
				StructType: PCA,
				PCA:        scmpPCA,
			}
		}

	case <-ctx.Done():
		log.Debug("SCMPProbeRequest reply:", "scmpPp", scmpPp)
		return ReturnVal, nil
	}

	log.Debug("After select statement")

	return ReturnVal, nil
}

// functions of handlers and other structures

func (t Pprobe) drain(ctx context.Context) {
	var last time.Time
	for {
		select {
		case <-ctx.Done():
			return
		default:
			var pkt snet.Packet
			var ov net.UDPAddr
			if err := t.conn.ReadFrom(&pkt, &ov); err != nil && t.errHandler != nil {
				// Rate limit the error reports.
				if now := time.Now(); now.Sub(last) > 500*time.Millisecond {
					t.errHandler(serrors.Wrap("reading packet", err))
					last = now
				}
			}
		}
	}
}

func (h scmpHandler) Handle(pkt *snet.Packet) error {
	log.Debug("SCMP handler", "Packet", pkt)
	r, err := h.handle(pkt)

	h.replies <- reply{
		Received: time.Now(),
		Reply:    r,
		Remote:   pkt.Source,
		Error:    err,
	}
	return nil
}

func (h scmpHandler) handle(pkt *snet.Packet) (HandlerReturn, error) {
	if pkt.Payload == nil {

		return HandlerReturn{structType: Empty}, serrors.New("no payload found")
	}
	r, okEcho := pkt.Payload.(snet.SCMPEchoReply)
	if !okEcho {
		r, okPCA := pkt.Payload.(snet.SCMPPCongestionAlert)
		if !okPCA {
			return HandlerReturn{structType: Empty}, serrors.New("not SCMP echo reply or congestion alert",
				"type", common.TypeOf(pkt.Payload))
		}
		return HandlerReturn{structType: PCA, pCA: r}, nil
	}
	return HandlerReturn{structType: PProbe, echoReply: r}, nil
}
