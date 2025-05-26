// Enables the command to send Polaris specific SCMP messages
// Needs to be similar to tracerout. Needs to be on the slowpahts as it need additional processing and can not be instantly forwarded

package main

// Modeled after the ping function
import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/addrutil"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/flag"
	"github.com/scionproto/scion/private/app/path"
	"github.com/scionproto/scion/private/path/pathpol"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/tracing"
	"github.com/scionproto/scion/scion/polaris"
)

// structure looks like the one from traceroute command
func newPProbe(pather CommandPather) *cobra.Command {
	var envFlags flag.SCIONEnvironment
	var flags struct {
		logLevel string
		tracer   string
		epic     bool
		format   string
	}

	var cmd = &cobra.Command{
		Use:     "pprobe [flags] <path>",
		Short:   "Send a P-Probe SCMP message to a SCION address. Over a specified path.",
		Example: "scion pprobe 1-ff00:0:111,10.150.0.71",
		Long:    `Send a P-Probe SCMP message to a SCION address. Over a specified path.`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			remote, err := addr.ParseAddr(args[0])
			if err != nil {
				return serrors.Wrap("parsing remote", err)
			}
			if err := app.SetupLog(flags.logLevel); err != nil {
				return serrors.Wrap("setting up logging", err)
			}
			closer, err := setupTracer("traceroute", flags.tracer)
			if err != nil {
				return serrors.Wrap("setting up tracing", err)
			}
			defer closer()
			printf, err := getPrintf(flags.format, cmd.OutOrStdout())
			log.Debug("Arguments to the function: %v\n", args)
			log.Debug("Command: %v\n", cmd)
			log.Debug("Flags: %v\n", flags)
			if err != nil {
				return serrors.Wrap("get formatting", err)
			}
			cmd.SilenceUsage = true

			if err := envFlags.LoadExternalVars(); err != nil {
				return err
			}
			daemonAddr := envFlags.Daemon()
			localIP := net.IP(envFlags.Local().AsSlice())
			log.Debug("Resolved SCION environment flags",
				"daemon", daemonAddr,
				"local", localIP,
			)

			span, traceCtx := tracing.CtxWith(context.Background(), "run")
			log.Debug("span", "span", span)
			log.Debug("traceCtx", "traceCtx", traceCtx)
			span.SetTag("dst.isd_as", remote.IA)
			span.SetTag("dst.host", remote.Host.IP)
			defer span.Finish()

			ctx, cancelF := context.WithTimeout(traceCtx, time.Second)
			log.Debug("ctx", "ctx", ctx)
			log.Debug("cancelF", "cancelF", cancelF)
			defer cancelF()
			sd, err := daemon.NewService(daemonAddr).Connect(ctx)
			if err != nil {
				return serrors.Wrap("connecting to SCION Daemon", err)
			}
			defer sd.Close()
			log.Debug("Before loading topology")
			topo, err := daemon.LoadTopology(ctx, sd)
			log.Debug("After loading topology")
			if err != nil {
				return serrors.Wrap("loading topology", err)
			}
			span.SetTag("src.isd_as", topo.LocalIA)

			log.Debug("Topology of sciond", "topo", topo)
			// log.Debug("Remote address", "remote", remote)
			// log.Debug("Local address", "local", localIP)
			// log.Debug("topo error", "err", err)
			path, err := path.Choose(traceCtx, sd, remote.IA,
				path.WithEPIC(flags.epic),
			)
			if err != nil {
				return err
			}
			nextHop := path.UnderlayNextHop()
			if nextHop == nil {
				nextHop = &net.UDPAddr{
					IP:   remote.Host.IP().AsSlice(),
					Port: topology.EndhostPort,
					Zone: remote.Host.IP().Zone(),
				}
			}

			if localIP == nil {
				target := remote.Host.IP().AsSlice()
				if nextHop != nil {
					target = nextHop.IP
				}
				if localIP, err = addrutil.ResolveLocal(target); err != nil {
					return serrors.Wrap("resolving local address", err)
				}
				printf("Resolved local address:\n  %s\n", localIP)
			}
			printf("Using path:\n  %s\n\n", path)

			seq, err := pathpol.GetSequence(path)
			if err != nil {
				return serrors.New("get sequence from used path")
			}
			var res ResultTraceroute
			res.Path = Path{
				Fingerprint: snet.Fingerprint(path).String(),
				Hops:        getHops(path),
				Sequence:    seq,
				LocalIP:     localIP,
				NextHop:     path.UnderlayNextHop().String(),
			}

			span.SetTag("src.host", localIP)
			asNetipAddr, ok := netip.AddrFromSlice(localIP)
			if !ok {
				panic("Invalid Local IP address")
			}
			local := addr.Addr{
				IA:   topo.LocalIA,
				Host: addr.HostIP(asNetipAddr),
			}
			ctx = app.WithSignal(traceCtx, os.Interrupt, syscall.SIGTERM)

			var updates []polaris.Update
			log.Debug("We are before the config of Pprobe Polaris")
			cfg := polaris.Config{
				Topology:     topo,
				Remote:       remote,
				NextHop:      nextHop,
				MTU:          path.Metadata().MTU,
				Local:        local,
				PathEntry:    path,
				ProbesPerHop: 3,
				ErrHandler:   func(err error) { fmt.Fprintf(os.Stderr, "ERROR: %s\n", err) },
				EPIC:         flags.epic,
			}
			log.Debug("Running Pprobe", "config", cfg)

			response, err := polaris.Run(ctx, cfg)
			if err != nil {
				return err
			}
			res.Hops = make([]HopInfo, 0, len(updates))

			if response.StructType == polaris.Empty {
				return serrors.New("empty path is not allowed for traceroute")
			} else if response.StructType == polaris.PProbe {
				switch flags.format {

				case "human":
					printf("Received SCMP P-Probe response:\n")
					printf("NextHeader: %d\n", response.Pprobe.NextHeader)
					printf("ExtLen: %d\n", response.Pprobe.ExtLen)
					printf("RequestIdentifier: %d\n", response.Pprobe.RequestIdentifier)
					printf("SequenceNumber: %d\n", response.Pprobe.SequenceNumber)
					printf("CumQueuingDelay: %f\n", response.Pprobe.CumQueuingDelay.Float32())
					printf("ASIdentifier: %s\n", response.Pprobe.ASIdentifier)
					printf("InterfaceID: %d\n", response.Pprobe.InterfaceID)
					printf("BottleneckShare: %f\n", response.Pprobe.BottleneckShare.Float32())
				case "json":
					enc := json.NewEncoder(os.Stdout)
					enc.SetIndent("", "  ")
					enc.SetEscapeHTML(false)
					return enc.Encode(res)
				case "yaml":
					enc := yaml.NewEncoder(os.Stdout)
					return enc.Encode(res)
				}
			} else {
				// This should be a congestion alert
				switch flags.format {

				case "human":
					printf("Received SCMP Polaris Congestion Alert response:\n")
					printf("RequestIdentifier: %d\n", response.PCA.RequestIdentifier)
					printf("SequenceNumber: %d\n", response.PCA.SequenceNumber)
					printf("ASIdentifier: %s\n", response.PCA.ASIdentifier)
					printf("InterfaceID: %d\n", response.PCA.InterfaceID)
				case "json":
					enc := json.NewEncoder(os.Stdout)
					enc.SetIndent("", "  ")
					enc.SetEscapeHTML(false)
					return enc.Encode(res)
				case "yaml":
					enc := yaml.NewEncoder(os.Stdout)
					return enc.Encode(res)
				}
			}
			return nil
		},
	}

	// text from ping command
	envFlags.Register(cmd.Flags())
	cmd.Flags().StringVar(&flags.logLevel, "log.level", "", app.LogLevelUsage)
	cmd.Flags().StringVar(&flags.tracer, "tracing.agent", "", "Tracing agent address")
	cmd.Flags().BoolVar(&flags.epic, "epic", false, "Enable EPIC for path probing.")
	cmd.Flags().StringVar(&flags.format, "format", "human",
		"Specify the output format (human|json|yaml)")
	return cmd
}

// ------------------------------------------ Congestion Alert ------------------------------------------

func newPCA(pather CommandPather) *cobra.Command {
	var envFlags flag.SCIONEnvironment
	var flags struct {
		logLevel string
		tracer   string
		epic     bool
		format   string
	}

	var cmd = &cobra.Command{
		Use:     "pprobe [flags] <path>",
		Short:   "Send a Polaris Congestion Alert SCMP message to a SCION address. Over a specified path.",
		Example: "scion pca 1-ff00:0:111,10.150.0.71",
		Long:    `Send a Polaris Congestion Alert SCMP message to a SCION address. Over a specified path.`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// remote, err := addr.ParseAddr(args[0])
			// if err != nil {
			// 	return serrors.Wrap("parsing remote", err)
			// }
			// if err := app.SetupLog(flags.logLevel); err != nil {
			// 	return serrors.Wrap("setting up logging", err)
			// }
			// closer, err := setupTracer("traceroute", flags.tracer)
			// if err != nil {
			// 	return serrors.Wrap("setting up tracing", err)
			// }
			// defer closer()
			printf, err := getPrintf(flags.format, cmd.OutOrStdout())
			if err != nil {
				return serrors.Wrap("get formatting", err)
			}
			printf("Note yet implemented!")
			return nil
			// log.Debug("Arguments to the function: %v\n", args)
			// log.Debug("Command: %v\n", cmd)
			// log.Debug("Flags: %v\n", flags)
			// cmd.SilenceUsage = true

			// if err := envFlags.LoadExternalVars(); err != nil {
			// 	return err
			// }
			// daemonAddr := envFlags.Daemon()
			// localIP := net.IP(envFlags.Local().AsSlice())
			// log.Debug("Resolved SCION environment flags",
			// 	"daemon", daemonAddr,
			// 	"local", localIP,
			// )

			// span, traceCtx := tracing.CtxWith(context.Background(), "run")
			// log.Debug("span", "span", span)
			// log.Debug("traceCtx", "traceCtx", traceCtx)
			// span.SetTag("dst.isd_as", remote.IA)
			// span.SetTag("dst.host", remote.Host.IP)
			// defer span.Finish()

			// ctx, cancelF := context.WithTimeout(traceCtx, time.Second)
			// log.Debug("ctx", "ctx", ctx)
			// log.Debug("cancelF", "cancelF", cancelF)
			// defer cancelF()
			// sd, err := daemon.NewService(daemonAddr).Connect(ctx)
			// if err != nil {
			// 	return serrors.Wrap("connecting to SCION Daemon", err)
			// }
			// defer sd.Close()
			// log.Debug("Before loading topology")
			// topo, err := daemon.LoadTopology(ctx, sd)
			// log.Debug("After loading topology")
			// if err != nil {
			// 	return serrors.Wrap("loading topology", err)
			// }
			// span.SetTag("src.isd_as", topo.LocalIA)

			// log.Debug("Topology of sciond", "topo", topo)
			// // log.Debug("Remote address", "remote", remote)
			// // log.Debug("Local address", "local", localIP)
			// // log.Debug("topo error", "err", err)
			// path, err := path.Choose(traceCtx, sd, remote.IA,
			// 	path.WithEPIC(flags.epic),
			// )
			// if err != nil {
			// 	return err
			// }
			// nextHop := path.UnderlayNextHop()
			// if nextHop == nil {
			// 	nextHop = &net.UDPAddr{
			// 		IP:   remote.Host.IP().AsSlice(),
			// 		Port: topology.EndhostPort,
			// 		Zone: remote.Host.IP().Zone(),
			// 	}
			// }

			// if localIP == nil {
			// 	target := remote.Host.IP().AsSlice()
			// 	if nextHop != nil {
			// 		target = nextHop.IP
			// 	}
			// 	if localIP, err = addrutil.ResolveLocal(target); err != nil {
			// 		return serrors.Wrap("resolving local address", err)
			// 	}
			// 	printf("Resolved local address:\n  %s\n", localIP)
			// }
			// printf("Using path:\n  %s\n\n", path)

			// seq, err := pathpol.GetSequence(path)
			// if err != nil {
			// 	return serrors.New("get sequence from used path")
			// }
			// var res ResultTraceroute
			// res.Path = Path{
			// 	Fingerprint: snet.Fingerprint(path).String(),
			// 	Hops:        getHops(path),
			// 	Sequence:    seq,
			// 	LocalIP:     localIP,
			// 	NextHop:     path.UnderlayNextHop().String(),
			// }

			// span.SetTag("src.host", localIP)
			// asNetipAddr, ok := netip.AddrFromSlice(localIP)
			// if !ok {
			// 	panic("Invalid Local IP address")
			// }
			// local := addr.Addr{
			// 	IA:   topo.LocalIA,
			// 	Host: addr.HostIP(asNetipAddr),
			// }
			// ctx = app.WithSignal(traceCtx, os.Interrupt, syscall.SIGTERM)

			// var updates []polaris.Update
			// log.Debug("We are before the config of Pprobe Polaris")
			// cfg := polaris.Config{
			// 	Topology:     topo,
			// 	Remote:       remote,
			// 	NextHop:      nextHop,
			// 	MTU:          path.Metadata().MTU,
			// 	Local:        local,
			// 	PathEntry:    path,
			// 	ProbesPerHop: 3,
			// 	ErrHandler:   func(err error) { fmt.Fprintf(os.Stderr, "ERROR: %s\n", err) },
			// 	EPIC:         flags.epic,
			// }
			// log.Debug("Running Pprobe", "config", cfg)

			// response, err := polaris.Run(ctx, cfg)
			// if err != nil {
			// 	return err
			// }
			// res.Hops = make([]HopInfo, 0, len(updates))

			// switch flags.format {

			// case "human":
			// 	printf("Received SCMP P-Probe response:\n")
			// 	printf("NextHeader: %d\n", response.NextHeader)
			// 	printf("ExtLen: %d\n", response.ExtLen)
			// 	printf("RequestIdentifier: %d\n", response.RequestIdentifier)
			// 	printf("SequenceNumber: %d\n", response.SequenceNumber)
			// 	printf("CumQueuingDelay: %f\n", response.CumQueuingDelay.Float32())
			// 	printf("ASIdentifier: %s\n", response.ASIdentifier)
			// 	printf("InterfaceID: %d\n", response.InterfaceID)
			// 	printf("BottleneckShare: %f\n", response.BottleneckShare.Float32())
			// case "json":
			// 	enc := json.NewEncoder(os.Stdout)
			// 	enc.SetIndent("", "  ")
			// 	enc.SetEscapeHTML(false)
			// 	return enc.Encode(res)
			// case "yaml":
			// 	enc := yaml.NewEncoder(os.Stdout)
			// 	return enc.Encode(res)
			// }
			// return nil
		},
	}
	// text from ping command
	envFlags.Register(cmd.Flags())
	cmd.Flags().StringVar(&flags.logLevel, "log.level", "", app.LogLevelUsage)
	cmd.Flags().StringVar(&flags.tracer, "tracing.agent", "", "Tracing agent address")
	cmd.Flags().BoolVar(&flags.epic, "epic", false, "Enable EPIC for path probing.")
	cmd.Flags().StringVar(&flags.format, "format", "human",
		"Specify the output format (human|json|yaml)")
	return cmd
}
