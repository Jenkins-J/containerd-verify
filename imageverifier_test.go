package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"

	iv "github.com/containerd/containerd/pkg/cri/server/imageverifier/v1"
	"github.com/containerd/ttrpc"
	_ "github.com/notaryproject/notation-core-go/signature/cose"
	_ "github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	c, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading configuration file: %s\n", err.Error())
	}
	verifierConfiguration = c

	server, err := ttrpc.NewServer()
	if err != nil {
		fmt.Printf("Error creating ttrpc server: %s\n", err.Error())
	}

	iv.RegisterImageVerifierService(server, &notaryVerifier{})

	l, err := net.Listen("unix", socket)
	if err != nil {
		fmt.Printf("Error listening on socket: %s\n", err.Error())
	}
	defer func() {
		server.Close()
		os.Remove(socket)
	}()

	go func() {
		err = server.Serve(context.Background(), l)
		if err != nil {
			fmt.Printf("Server returned an error: %s\n", err.Error())
		}
	}()

	m.Run()

}

func TestVerifyImage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestVerifyImage: testing in short mode")
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Errorf("Error: %s\n", err.Error())
	}
	defer conn.Close()

	tc := ttrpc.NewClient(conn)
	client := iv.NewImageVerifierClient(tc)

	r := &iv.VerifyImageRequest{
		ImageName:   "image name here",
		ImageDigest: "image digest here",
	}

	ctx := context.Background()

	resp, err := client.VerifyImage(ctx, r)
	if err != nil {
		t.Errorf("Error: %s\n", err.Error())
	}

	fmt.Printf("Response Ok: %v\n", resp.Ok)
	fmt.Printf("Response Reason: %v\n", resp.Reason)

}

func TestGetCertificate(t *testing.T) {
	ts := &trustStore{}
	ctx := context.Background()

	c, err := ts.GetCertificates(ctx, truststore.TypeCA, "")
	if err != nil {
		t.Errorf("Error retrieving certificates: %s\n", err.Error())
	}
	assert.NotEmpty(t, c)
}

func TestLoadConfig(t *testing.T) {
	config, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading config: %s\n", err.Error())
	}

	assert.Nil(t, err)
	assert.NotNil(t, config)
	assert.NotEmpty(t, config)
}
