package lastpass_test

import (
	"context"
	"log"
	"net/http"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"

	. "github.com/ansd/lastpass-go"
)

var _ = Describe("Log", func() {
	var server *ghttp.Server
	var logger Logger
	var logs strings.Builder
	var err error

	BeforeEach(func() {
		server = ghttp.NewServer()
		server.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest(http.MethodPost, EndpointIterations),
				ghttp.RespondWith(http.StatusOK, "1"),
			),
		)
		server.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest(http.MethodPost, EndpointLogin),
				ghttp.RespondWith(http.StatusOK, "<ok token=\"fakeToken\"/>"),
			),
		)
		logger = log.New(&logs, "", 0)
	})

	AfterEach(func() {
		Expect(err).NotTo(HaveOccurred())
		lines := strings.Split(logs.String(), "\n")
		Expect(lines[0]).To(MatchRegexp("^POST http://127.0.0.1:[0-9]{1,5}/iterations.php$"))
		Expect(lines[1]).To(MatchRegexp("^POST http://127.0.0.1:[0-9]{1,5}/login.php$"))
		server.Close()
	})

	Describe("NewContextWithLogger()", func() {
		It("writes logs", func() {
			_, err = NewClient(
				NewContextWithLogger(context.Background(), logger),
				"user", "pwd",
				WithBaseURL(server.URL()))
		})
	})
	Describe("WithLogger()", func() {
		It("writes logs", func() {
			_, err = NewClient(context.Background(), "user", "pwd",
				WithBaseURL(server.URL()),
				WithLogger(logger))
		})
	})
})
