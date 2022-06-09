package lastpass_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"

	. "github.com/veloceapps/lastpass-go"
)

var _ = Describe("Account", func() {
	var (
		client *Client
		server *ghttp.Server
		user   string
		passwd string
	)

	BeforeEach(func() {
		user = readFile("user.txt")
		passwd = readFile("passwd.txt")
		server = ghttp.NewServer()
		server.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest(http.MethodPost, EndpointLogin),
				ghttp.RespondWith(http.StatusOK,
					fmt.Sprintf("<ok token=\"fakeToken\" privatekeyenc=\"%s\"/>", readFile("privatekeyencrypted.txt"))),
			),
			ghttp.CombineHandlers(
				ghttp.VerifyRequest(http.MethodPost, EndpointLoginCheck),
				ghttp.RespondWith(http.StatusOK, `<response> <ok accts_version="111"/> </response>`),
			),
		)
		var err error
		client, err = NewClient(context.Background(), user, passwd, WithBaseURL(server.URL()))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		server.Close()
	})

	Describe("Accounts()", func() {
		When("server returns blob", func() {
			var rsp string
			JustBeforeEach(func() {
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodGet, EndpointGetAccts,
							"requestsrc=cli&mobile=1&b64=1&hasplugin=1.3.3"),
						ghttp.RespondWith(http.StatusOK, rsp),
					),
				)
			})
			When("accounts including secure notes are returned", func() {
				BeforeEach(func() {
					rsp = readFile("blob-3accts.txt")
				})
				It("parses the accounts", func() {
					accts, err := client.Accounts(context.Background())
					Expect(err).NotTo(HaveOccurred())
					Expect(accts).To(ConsistOf(
						&Account{
							ID:              readFile("id-name0.txt"),
							Name:            "name0",
							Username:        "user0",
							Password:        "password0",
							URL:             "http://url0",
							Group:           "folder0",
							Notes:           "notes0",
							LastModifiedGMT: "1566373887",
							LastTouch:       "1566373925",
						},
						&Account{
							ID:              readFile("id-name1.txt"),
							Name:            "name1",
							URL:             "http://sn",
							Group:           "folder0",
							Notes:           "some secure note",
							LastModifiedGMT: "1566373920",
							LastTouch:       "1566373932",
						},
						&Account{
							ID:              readFile("id-name2.txt"),
							Name:            "name2",
							URL:             "http://url2",
							LastModifiedGMT: "1566373921",
							LastTouch:       "1566373938",
						},
					))
					// /login.php, /login_check.php, /getaccts.php
					Expect(server.ReceivedRequests()).To(HaveLen(3))
				})
			})
			When("group accounts are returned", func() {
				BeforeEach(func() {
					rsp = readFile("blob-groupaccount.txt")
				})
				It("filters out group accounts", func() {
					accts, err := client.Accounts(context.Background())
					Expect(err).NotTo(HaveOccurred())
					Expect(accts).To(BeEmpty())
					// /login.php, /login_check.php, /getaccts.php
					Expect(server.ReceivedRequests()).To(HaveLen(3))
				})
			})
			When("shared folders exist whose sharing key is AES encrypted with user's encryption key", func() {
				BeforeEach(func() {
					rsp = readFile("blob-sharedaccounts.txt")
				})
				It("parses accounts in shared folders", func() {
					accts, err := client.Accounts(context.Background())
					Expect(err).NotTo(HaveOccurred())
					Expect(accts).To(ConsistOf(
						&Account{
							ID:              readFile("id-name0.txt"),
							Name:            "name0",
							Username:        "user0",
							Password:        "password0",
							URL:             "http://url0",
							Group:           "folder0",
							Notes:           "notes0",
							LastModifiedGMT: "1566373887",
							LastTouch:       "0",
						},
						&Account{
							ID:              readFile("id-nameshared0.txt"),
							Name:            "nameShared0",
							Username:        "userShared0",
							Password:        "passwordShared0",
							URL:             "http://urlShared0",
							Group:           "",
							Share:           "Shared-share1",
							Notes:           "notesShared0",
							LastModifiedGMT: "1566373807",
							LastTouch:       "0",
						},
						&Account{
							ID:              readFile("id-nameshared1.txt"),
							Name:            "nameShared1",
							Username:        "userShared1",
							Password:        "passwordShared1",
							URL:             "http://urlShared1",
							Group:           "",
							Share:           "Shared-share2",
							Notes:           "notesShared1",
							LastModifiedGMT: "1566373836",
							LastTouch:       "0",
						},
						&Account{
							ID:              readFile("id-nameshared2.txt"),
							Name:            "nameShared2",
							Username:        "userShared2",
							Password:        "passwordShared2",
							URL:             "http://urlShared2",
							Group:           "",
							Share:           "Shared-share2",
							Notes:           "notesShared2",
							LastModifiedGMT: "1566373837",
							LastTouch:       "0",
						},
					))
					// /login.php, /login_check.php, /getaccts.php
					Expect(server.ReceivedRequests()).To(HaveLen(3))
				})
			})
			When("shared folder exists whose sharing key needs to be decrypted with user's RSA private key", func() {
				BeforeEach(func() {
					rsp = readFile("blob-sharingkeyrsaencrypted.txt")
				})
				It("parses account in shared folder", func() {
					accts, err := client.Accounts(context.Background())
					Expect(err).NotTo(HaveOccurred())
					Expect(accts).To(ConsistOf(
						&Account{
							ID:              readFile("id-nameshared0.txt"),
							Name:            "nameShared0",
							Username:        "userShared0",
							Password:        "passwordShared0",
							URL:             "http://urlShared0",
							Group:           "",
							Share:           "Shared-share1",
							Notes:           "notesShared0",
							LastModifiedGMT: "1566373807",
							LastTouch:       "0",
						},
					))
					// /login.php, /login_check.php, /getaccts.php
					Expect(server.ReceivedRequests()).To(HaveLen(3))
				})
			})
			When("an account is AES 256 ECB encrypted", func() {
				BeforeEach(func() {
					rsp = readFile("blob-ecb.txt")
				})
				It("decrypts", func() {
					accts, err := client.Accounts(context.Background())
					Expect(err).NotTo(HaveOccurred())
					Expect(accts).To(ConsistOf(
						&Account{
							ID:              readFile("id-nameecb.txt"),
							Name:            "nameECB",
							Username:        "user ECB",
							Password:        "password ECB",
							URL:             "http://urlECB",
							Group:           "groupECB",
							Notes:           "notes ECB",
							LastModifiedGMT: "1566373979",
							LastTouch:       "0",
						},
					))
					// /login.php, /login_check.php, /getaccts.php
					Expect(server.ReceivedRequests()).To(HaveLen(3))
				})
			})
			When("blob is not base 64 encoded", func() {
				BeforeEach(func() {
					rsp = "!! blob not base64 encoded !!"
				})
				It("returns base64.CorruptInputError", func() {
					_, err := client.Accounts(context.Background())
					_, ok := err.(base64.CorruptInputError)
					Expect(ok).To(BeTrue())
				})
			})
			When("blob is empty", func() {
				BeforeEach(func() {
					rsp = ""
				})
				It("returns a descriptive error", func() {
					_, err := client.Accounts(context.Background())
					Expect(err).To(MatchError("blob is truncated"))
				})
			})
			When("blob is truncated and therefore chunk cannot be extracted", func() {
				BeforeEach(func() {
					// 8 base64 digits (each 6 bit) = 48 bits = 6 bytes
					// chunk contains 4-byte ID, 4-byte size and payload of that size
					// therefore, the complete chunk cannot be read
					rsp = "TFBBVgAA"
				})
				It("returns an EOF error", func() {
					_, err := client.Accounts(context.Background())
					Expect(err).To(MatchError("EOF"))
				})
			})
		})
		When("request gets canceled", func() {
			var ctx context.Context
			BeforeEach(func() {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
			})
			It("returns correct error", func() {
				_, err := client.Accounts(ctx)
				Expect(err).To(MatchError(MatchRegexp("context canceled")))
			})
		})
		When("HTTP error response", func() {
			BeforeEach(func() {
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodGet, EndpointGetAccts,
							"requestsrc=cli&mobile=1&b64=1&hasplugin=1.3.3"),
						ghttp.RespondWith(http.StatusInternalServerError, ""),
					),
				)
			})
			It("returns error including HTTP status code", func() {
				_, err := client.Accounts(context.Background())
				Expect(err).To(MatchError(MatchRegexp(
					`GET http://127\.0\.0\.1:[0-9]{1,5}/getaccts.php` +
						`\?b64=1&hasplugin=1\.3\.3&mobile=1&requestsrc=cli: 500 Internal Server Error$`)))
			})
		})
	})
})
