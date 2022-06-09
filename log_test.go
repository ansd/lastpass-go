package lastpass_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"

	. "github.com/veloceapps/lastpass-go"
)

var _ = Describe("Log", func() {
	var server *ghttp.Server
	var logger Logger
	var logs strings.Builder
	var err error
	var user string
	var passwd string

	BeforeEach(func() {
		user = readFile("user.txt")
		passwd = readFile("passwd.txt")

		server = ghttp.NewServer()
		server.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest(http.MethodPost, EndpointLogin),
				ghttp.RespondWith(http.StatusOK, fmt.Sprintf("<ok token=\"%s\" privatekeyenc=\"%s\" />",
					"fakeToken", readFile("privatekeyencrypted.txt"))),
			),
		)
		logger = log.New(&logs, "", 0)
	})

	AfterEach(func() {
		Expect(err).NotTo(HaveOccurred())
		Expect(logs.String()).To(MatchRegexp(`^POST http://127\.0\.0\.1:[0-9]{1,5}/login\.php`))
		server.Close()
	})

	Describe("NewContextWithLogger()", func() {
		It("writes logs", func() {
			_, err = NewClient(
				NewContextWithLogger(context.Background(), logger),
				user, passwd,
				WithBaseURL(server.URL()))
		})
	})
	Describe("WithLogger()", func() {
		It("writes logs", func() {
			_, err = NewClient(context.Background(), user, passwd,
				WithBaseURL(server.URL()),
				WithLogger(logger))
		})
	})
})
