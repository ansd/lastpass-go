package integration_test

import (
	"io/ioutil"
	"log"
	"strings"
	"testing"

	"github.com/ansd/lastpass-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var client *lastpass.Client

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration Suite")
}

var _ = BeforeSuite(func() {
	b, err := ioutil.ReadFile("credentials.txt")
	if err != nil {
		log.Fatalln(err)
	}
	lines := strings.Split(string(b), "\n")
	username := lines[0]
	password := lines[1]

	client, err = lastpass.Login(username, password)
	Expect(err).NotTo(HaveOccurred())
})

var _ = AfterSuite(func() {
	Expect(client.Logout()).To(Succeed())
	_, err := client.Accounts()
	Expect(err).To(MatchError("GET https://lastpass.com/getaccts.php: 403 Forbidden"))
})
