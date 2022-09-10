package integration_test

import (
	"context"
	"os"
	"testing"

	"github.com/ansd/lastpass-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	client    *lastpass.Client
	username2 string
	password2 string
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration Suite")
}

var _ = BeforeSuite(func() {
	username1 := os.Getenv("LASTPASS_USERNAME_1")
	Expect(username1).NotTo(BeEmpty())
	password1 := os.Getenv("LASTPASS_MASTER_PASSWORD_1")
	Expect(password1).NotTo(BeEmpty())

	username2 = os.Getenv("LASTPASS_USERNAME_2")
	Expect(username2).NotTo(BeEmpty())
	password2 = os.Getenv("LASTPASS_MASTER_PASSWORD_2")
	Expect(password2).NotTo(BeEmpty())

	var err error
	client, err = lastpass.NewClient(context.Background(), username1, password1)
	Expect(err).NotTo(HaveOccurred())
})

var _ = AfterSuite(func() {
	Expect(client.Logout(context.Background())).To(Succeed())
	Expect(client.Delete(context.Background(), nil)).To(MatchError("client not logged in"))
})
