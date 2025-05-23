// Code generated by protoc-gen-connect-go. DO NOT EDIT.
//
// Source: proto/discovery/v1/discovery.proto

package discoveryconnect

import (
	connect "connectrpc.com/connect"
	context "context"
	errors "errors"
	discovery "github.com/scionproto/scion/pkg/proto/discovery"
	http "net/http"
	strings "strings"
)

// This is a compile-time assertion to ensure that this generated file and the connect package are
// compatible. If you get a compiler error that this constant is not defined, this code was
// generated with a version of connect newer than the one compiled into your binary. You can fix the
// problem by either regenerating this code with an older version of connect or updating the connect
// version compiled into your binary.
const _ = connect.IsAtLeastVersion1_13_0

const (
	// DiscoveryServiceName is the fully-qualified name of the DiscoveryService service.
	DiscoveryServiceName = "proto.discovery.v1.DiscoveryService"
)

// These constants are the fully-qualified names of the RPCs defined in this package. They're
// exposed at runtime as Spec.Procedure and as the final two segments of the HTTP route.
//
// Note that these are different from the fully-qualified method names used by
// google.golang.org/protobuf/reflect/protoreflect. To convert from these constants to
// reflection-formatted method names, remove the leading slash and convert the remaining slash to a
// period.
const (
	// DiscoveryServiceGatewaysProcedure is the fully-qualified name of the DiscoveryService's Gateways
	// RPC.
	DiscoveryServiceGatewaysProcedure = "/proto.discovery.v1.DiscoveryService/Gateways"
	// DiscoveryServiceHiddenSegmentServicesProcedure is the fully-qualified name of the
	// DiscoveryService's HiddenSegmentServices RPC.
	DiscoveryServiceHiddenSegmentServicesProcedure = "/proto.discovery.v1.DiscoveryService/HiddenSegmentServices"
)

// DiscoveryServiceClient is a client for the proto.discovery.v1.DiscoveryService service.
type DiscoveryServiceClient interface {
	Gateways(context.Context, *connect.Request[discovery.GatewaysRequest]) (*connect.Response[discovery.GatewaysResponse], error)
	HiddenSegmentServices(context.Context, *connect.Request[discovery.HiddenSegmentServicesRequest]) (*connect.Response[discovery.HiddenSegmentServicesResponse], error)
}

// NewDiscoveryServiceClient constructs a client for the proto.discovery.v1.DiscoveryService
// service. By default, it uses the Connect protocol with the binary Protobuf Codec, asks for
// gzipped responses, and sends uncompressed requests. To use the gRPC or gRPC-Web protocols, supply
// the connect.WithGRPC() or connect.WithGRPCWeb() options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewDiscoveryServiceClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) DiscoveryServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	discoveryServiceMethods := discovery.File_proto_discovery_v1_discovery_proto.Services().ByName("DiscoveryService").Methods()
	return &discoveryServiceClient{
		gateways: connect.NewClient[discovery.GatewaysRequest, discovery.GatewaysResponse](
			httpClient,
			baseURL+DiscoveryServiceGatewaysProcedure,
			connect.WithSchema(discoveryServiceMethods.ByName("Gateways")),
			connect.WithClientOptions(opts...),
		),
		hiddenSegmentServices: connect.NewClient[discovery.HiddenSegmentServicesRequest, discovery.HiddenSegmentServicesResponse](
			httpClient,
			baseURL+DiscoveryServiceHiddenSegmentServicesProcedure,
			connect.WithSchema(discoveryServiceMethods.ByName("HiddenSegmentServices")),
			connect.WithClientOptions(opts...),
		),
	}
}

// discoveryServiceClient implements DiscoveryServiceClient.
type discoveryServiceClient struct {
	gateways              *connect.Client[discovery.GatewaysRequest, discovery.GatewaysResponse]
	hiddenSegmentServices *connect.Client[discovery.HiddenSegmentServicesRequest, discovery.HiddenSegmentServicesResponse]
}

// Gateways calls proto.discovery.v1.DiscoveryService.Gateways.
func (c *discoveryServiceClient) Gateways(ctx context.Context, req *connect.Request[discovery.GatewaysRequest]) (*connect.Response[discovery.GatewaysResponse], error) {
	return c.gateways.CallUnary(ctx, req)
}

// HiddenSegmentServices calls proto.discovery.v1.DiscoveryService.HiddenSegmentServices.
func (c *discoveryServiceClient) HiddenSegmentServices(ctx context.Context, req *connect.Request[discovery.HiddenSegmentServicesRequest]) (*connect.Response[discovery.HiddenSegmentServicesResponse], error) {
	return c.hiddenSegmentServices.CallUnary(ctx, req)
}

// DiscoveryServiceHandler is an implementation of the proto.discovery.v1.DiscoveryService service.
type DiscoveryServiceHandler interface {
	Gateways(context.Context, *connect.Request[discovery.GatewaysRequest]) (*connect.Response[discovery.GatewaysResponse], error)
	HiddenSegmentServices(context.Context, *connect.Request[discovery.HiddenSegmentServicesRequest]) (*connect.Response[discovery.HiddenSegmentServicesResponse], error)
}

// NewDiscoveryServiceHandler builds an HTTP handler from the service implementation. It returns the
// path on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewDiscoveryServiceHandler(svc DiscoveryServiceHandler, opts ...connect.HandlerOption) (string, http.Handler) {
	discoveryServiceMethods := discovery.File_proto_discovery_v1_discovery_proto.Services().ByName("DiscoveryService").Methods()
	discoveryServiceGatewaysHandler := connect.NewUnaryHandler(
		DiscoveryServiceGatewaysProcedure,
		svc.Gateways,
		connect.WithSchema(discoveryServiceMethods.ByName("Gateways")),
		connect.WithHandlerOptions(opts...),
	)
	discoveryServiceHiddenSegmentServicesHandler := connect.NewUnaryHandler(
		DiscoveryServiceHiddenSegmentServicesProcedure,
		svc.HiddenSegmentServices,
		connect.WithSchema(discoveryServiceMethods.ByName("HiddenSegmentServices")),
		connect.WithHandlerOptions(opts...),
	)
	return "/proto.discovery.v1.DiscoveryService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case DiscoveryServiceGatewaysProcedure:
			discoveryServiceGatewaysHandler.ServeHTTP(w, r)
		case DiscoveryServiceHiddenSegmentServicesProcedure:
			discoveryServiceHiddenSegmentServicesHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// UnimplementedDiscoveryServiceHandler returns CodeUnimplemented from all methods.
type UnimplementedDiscoveryServiceHandler struct{}

func (UnimplementedDiscoveryServiceHandler) Gateways(context.Context, *connect.Request[discovery.GatewaysRequest]) (*connect.Response[discovery.GatewaysResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("proto.discovery.v1.DiscoveryService.Gateways is not implemented"))
}

func (UnimplementedDiscoveryServiceHandler) HiddenSegmentServices(context.Context, *connect.Request[discovery.HiddenSegmentServicesRequest]) (*connect.Response[discovery.HiddenSegmentServicesResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("proto.discovery.v1.DiscoveryService.HiddenSegmentServices is not implemented"))
}
