package integration_test

import (
	"context"
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/veloceapps/lastpass-go"
)

var client *lastpass.Client

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration Suite")
}

var _ = BeforeSuite(func() {
	username := os.Getenv("LASTPASS_USERNAME_1")
	Expect(username).NotTo(BeEmpty())
	passwd := os.Getenv("LASTPASS_MASTER_PASSWORD_1")
	Expect(passwd).NotTo(BeEmpty())

	var err error
	client, err = lastpass.NewClient(context.Background(), username, passwd)
	Expect(err).NotTo(HaveOccurred())
})

var _ = AfterSuite(func() {
	Expect(client.Logout(context.Background())).To(Succeed())
	Expect(client.Delete(context.Background(), nil)).To(MatchError("client not logged in"))
})
