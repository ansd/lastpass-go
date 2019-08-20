package lastpass_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"

	. "github.com/ansd/lastpass-go"
)

var _ = Describe("Client", func() {
	var client *Client
	var server *ghttp.Server
	var acct *Account

	BeforeEach(func() {
		server = ghttp.NewServer()
		acct = &Account{
			ID:       "test ID",
			Name:     "test site",
			Username: "test user",
			Password: "test pwd",
			URL:      "https://testURL",
			Group:    "test group",
			Notes:    "test notes",
		}
	})

	AfterEach(func() {
		server.Close()
	})

	AssertUnauthenticatedBehavior := func() {
		Describe("Accounts()", func() {
			It("returns AuthenticationError", func() {
				accts, err := client.Accounts(context.Background())
				Expect(accts).To(BeNil())
				_, ok := err.(*AuthenticationError)
				Expect(ok).To(BeTrue())
			})
		})
		Describe("Add()", func() {
			It("returns AuthenticationError", func() {
				err := client.Add(context.Background(), acct)
				_, ok := err.(*AuthenticationError)
				Expect(ok).To(BeTrue())
			})
		})
		Describe("Update()", func() {
			It("returns AuthenticationError", func() {
				err := client.Update(context.Background(), acct)
				_, ok := err.(*AuthenticationError)
				Expect(ok).To(BeTrue())
			})
		})
		Describe("Delete()", func() {
			It("returns AuthenticationError", func() {
				err := client.Delete(context.Background(), acct.ID)
				_, ok := err.(*AuthenticationError)
				Expect(ok).To(BeTrue())
			})
		})
		Describe("Logout()", func() {
			It("succeeds", func() {
				Expect(client.Logout(context.Background())).To(Succeed())
			})
		})
	}

	Context("when Client never logged in", func() {
		BeforeEach(func() {
			client = &Client{}
		})
		AssertUnauthenticatedBehavior()
	})

	Context("when NewClient()", func() {
		var loginForm url.Values
		var user string
		var passwd string
		const passwdIterations = "100100"
		contentTypeVerifier := ghttp.VerifyContentType("application/x-www-form-urlencoded")

		BeforeEach(func() {
			user = readFile("user.txt")
			passwd = readFile("passwd.txt")

			loginForm = url.Values{}
			loginForm.Set("method", "cli")
			loginForm.Set("xml", "1")
			loginForm.Set("username", user)
			loginForm.Set("iterations", passwdIterations)

			server.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest(http.MethodPost, EndpointIterations),
					contentTypeVerifier,
					ghttp.VerifyFormKV("email", user),
					ghttp.RespondWith(http.StatusOK, passwdIterations),
				),
			)
		})

		Context("when authentication fails", func() {
			var cause string
			var msg string
			var rsp string
			JustBeforeEach(func() {
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodPost, EndpointLogin),
						contentTypeVerifier,
						ghttp.VerifyForm(loginForm),
						ghttp.RespondWith(http.StatusOK, rsp),
					),
				)
			})
			Context("due to invalid email or password", func() {
				BeforeEach(func() {
					cause = "unknown"
					msg = "Invalid email or password!"
					rsp = fmt.Sprintf("<response><error message=\"%s\" cause=\"%s\" email=\"%s\"/></response>",
						msg, cause, user)
				})
				Describe("NewClient()", func() {
					It("returns AuthenticationError", func() {
						var err error
						client, err = NewClient(context.Background(), user, passwd, WithBaseURL(server.URL()))
						Expect(client).To(BeNil())
						Expect(err).To(MatchError(fmt.Sprintf("%s: %s", cause, msg)))
						_, ok := err.(*AuthenticationError)
						Expect(ok).To(BeTrue())
						// /iterations.php, /login.php
						Expect(server.ReceivedRequests()).To(HaveLen(2))
					})
				})
			})
			Context("due to missing out-of-band approval", func() {
				var retryID string
				var loginRetryForm url.Values
				BeforeEach(func() {
					cause = "outofbandrequired"
					msg = "Multifactor authentication required!"
					retryID = "123"
					rsp = fmt.Sprintf("<response><error message=\"%s\" cause=\"%s\" retryid=\"%s\"/></response>",
						msg, cause, retryID)
				})
				JustBeforeEach(func() {
					loginRetryForm = url.Values{}
					for k, v := range loginForm {
						loginRetryForm[k] = v
					}
					loginRetryForm.Set("outofbandrequest", "1")
					loginRetryForm.Set("outofbandretry", "1")
					loginRetryForm.Set("outofbandretryid", retryID)
					for i := 0; i < MaxLoginRetries; i++ {
						server.AppendHandlers(
							ghttp.CombineHandlers(
								ghttp.VerifyRequest(http.MethodPost, EndpointLogin),
								contentTypeVerifier,
								ghttp.VerifyForm(loginRetryForm),
								ghttp.RespondWith(http.StatusOK, rsp),
							),
						)
					}
				})
				Describe("NewClient()", func() {
					It("returns AuthenticationError", func() {
						var err error
						client, err = NewClient(context.Background(), user, passwd, WithBaseURL(server.URL()))
						Expect(client).To(BeNil())
						Expect(err).To(MatchError(MatchRegexp(`^didn't receive out-of-band approval within the last \d seconds$`)))
						// /iterations.php, /login.php, MaxLoginRetries * /login/php
						Expect(server.ReceivedRequests()).To(HaveLen(2 + MaxLoginRetries))
					})
				})
			})
		})

		Context("when NewClient() succeeds", func() {
			var form url.Values
			const token = "fakeToken"

			BeforeEach(func() {
				privateKeyEncrypted := readFile("privatekeyencrypted.txt")

				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodPost, EndpointLogin),
						contentTypeVerifier,
						ghttp.VerifyForm(loginForm),
						ghttp.RespondWith(http.StatusOK, fmt.Sprintf("<ok token=\"%s\" privatekeyenc=\"%s\"/>",
							token, privateKeyEncrypted)),
					),
				)
				var err error
				client, err = NewClient(context.Background(), user, passwd, WithBaseURL(server.URL()))
				Expect(err).NotTo(HaveOccurred())
			})

			Describe("NewClient()", func() {
				It("requests /iterations.php and /login.php", func() {
					Expect(server.ReceivedRequests()).To(HaveLen(2))
				})
			})

			Context("when session is live", func() {
				rsp := `<?xml version="1.0" encoding="UTF-8"?>
	<response>
	<ok accts_version="111"/>
	</response>`
				BeforeEach(func() {
					server.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest(http.MethodPost, EndpointLoginCheck),
							ghttp.RespondWith(http.StatusOK, rsp),
						),
					)
				})

				Describe("Accounts()", func() {
					var rsp string
					JustBeforeEach(func() {
						server.AppendHandlers(
							ghttp.CombineHandlers(
								ghttp.VerifyRequest(http.MethodGet, EndointGetAccts,
									"requestsrc=cli&mobile=1&b64=1&hasplugin=1.3.3"),
								ghttp.RespondWith(http.StatusOK, rsp),
							),
						)
					})

					Context("when accounts including secure notes are returned", func() {
						BeforeEach(func() {
							rsp = readFile("blob-3accts.txt")
						})
						It("parses the accounts", func() {
							accts, err := client.Accounts(context.Background())
							Expect(err).NotTo(HaveOccurred())
							Expect(accts).To(ConsistOf(
								&Account{
									ID:       readFile("id-name0.txt"),
									Name:     "name0",
									Username: "user0",
									Password: "password0",
									URL:      "http://url0",
									Group:    "folder0",
									Notes:    "notes0",
								},
								&Account{
									ID:    readFile("id-name1.txt"),
									Name:  "name1",
									URL:   "http://sn",
									Group: "folder0",
									Notes: "some secure note",
								},
								&Account{
									ID:   readFile("id-name2.txt"),
									Name: "name2",
									URL:  "http://url2",
								},
							))
							// /iterations.php, /login.php, /login_check.php, /getaccts.php
							Expect(server.ReceivedRequests()).To(HaveLen(4))
						})
					})
					Context("when group accounts are returned", func() {
						BeforeEach(func() {
							rsp = readFile("blob-groupaccount.txt")
						})
						It("filters out group accounts", func() {
							accts, err := client.Accounts(context.Background())
							Expect(err).NotTo(HaveOccurred())
							Expect(accts).To(BeEmpty())
							// /iterations.php, /login.php, /login_check.php, /getaccts.php
							Expect(server.ReceivedRequests()).To(HaveLen(4))
						})
					})
					Context("when shared folders exist whose sharing key is AES encrypted with user's encryption key", func() {
						BeforeEach(func() {
							rsp = readFile("blob-sharedaccounts.txt")
						})
						It("parses accounts in shared folders", func() {
							accts, err := client.Accounts(context.Background())
							Expect(err).NotTo(HaveOccurred())
							Expect(accts).To(ConsistOf(
								&Account{
									ID:       readFile("id-name0.txt"),
									Name:     "name0",
									Username: "user0",
									Password: "password0",
									URL:      "http://url0",
									Group:    "folder0",
									Notes:    "notes0",
								},
								&Account{
									ID:       readFile("id-nameshared0.txt"),
									Name:     "nameShared0",
									Username: "userShared0",
									Password: "passwordShared0",
									URL:      "http://urlShared0",
									Group:    "Shared-share1",
									Notes:    "notesShared0",
								},
								&Account{
									ID:       readFile("id-nameshared1.txt"),
									Name:     "nameShared1",
									Username: "userShared1",
									Password: "passwordShared1",
									URL:      "http://urlShared1",
									Group:    "Shared-share2",
									Notes:    "notesShared1",
								},
								&Account{
									ID:       readFile("id-nameshared2.txt"),
									Name:     "nameShared2",
									Username: "userShared2",
									Password: "passwordShared2",
									URL:      "http://urlShared2",
									Group:    "Shared-share2",
									Notes:    "notesShared2",
								},
							))
							// /iterations.php, /login.php, /login_check.php, /getaccts.php
							Expect(server.ReceivedRequests()).To(HaveLen(4))
						})
					})

					Context("when shared folder exists whose sharing key needs to be decrypted with user's RSA private key", func() {
						BeforeEach(func() {
							rsp = readFile("blob-sharingkeyrsaencrypted.txt")
						})
						It("parses account in shared folder", func() {
							accts, err := client.Accounts(context.Background())
							Expect(err).NotTo(HaveOccurred())
							Expect(accts).To(ConsistOf(
								&Account{
									ID:       readFile("id-nameshared0.txt"),
									Name:     "nameShared0",
									Username: "userShared0",
									Password: "passwordShared0",
									URL:      "http://urlShared0",
									Group:    "Shared-share1",
									Notes:    "notesShared0",
								},
							))
							// /iterations.php, /login.php, /login_check.php, /getaccts.php
							Expect(server.ReceivedRequests()).To(HaveLen(4))
						})
					})
					Context("when an account is AES 256 ECB encrypted", func() {
						BeforeEach(func() {
							rsp = readFile("blob-ecb.txt")
						})
						It("decrypts", func() {
							accts, err := client.Accounts(context.Background())
							Expect(err).NotTo(HaveOccurred())
							Expect(accts).To(ConsistOf(
								&Account{
									ID:       readFile("id-nameecb.txt"),
									Name:     "nameECB",
									Username: "user ECB",
									Password: "password ECB",
									URL:      "http://urlECB",
									Group:    "groupECB",
									Notes:    "notes ECB",
								},
							))
							// /iterations.php, /login.php, /login_check.php, /getaccts.php
							Expect(server.ReceivedRequests()).To(HaveLen(4))
						})
					})
				})

				Context("when successfully operating on a single account", func() {
					var rspMsg string
					JustBeforeEach(func() {
						server.AppendHandlers(
							ghttp.CombineHandlers(
								ghttp.VerifyRequest(http.MethodPost, EndpointShowWebsite),
								contentTypeVerifier,
								ghttp.VerifyForm(form),
								ghttp.RespondWith(http.StatusOK, fmt.Sprintf(
									"<xmlresponse><result aid=\"%s\" msg=\"%s\"></result></xmlresponse>",
									acct.ID, rspMsg),
								),
							),
						)
					})

					AfterEach(func() {
						// /iterations.php, /login.php, /login_check.php, /show_website.php
						Expect(server.ReceivedRequests()).To(HaveLen(4))
					})

					Context("when upserting", func() {
						BeforeEach(func() {
							form = url.Values{}
							form.Set("method", "cli")
							form.Set("extjs", "1")
							form.Set("token", token)
							form.Set("url", hex.EncodeToString([]byte(acct.URL)))
							form.Set("pwprotect", "off")
						})

						Describe("Add()", func() {
							BeforeEach(func() {
								rspMsg = "accountadded"
								form.Set("aid", "0")
							})
							It("requests /show_website.php with aid=0 and sets account ID correctly", func() {
								acct.ID = "ignored"
								Expect(client.Add(context.Background(), acct)).To(Succeed())
								Expect(acct.ID).To(Equal("test ID"))
							})
						})
						Describe("Update()", func() {
							BeforeEach(func() {
								rspMsg = "accountupdated"
								form.Set("aid", acct.ID)
							})
							It("requests /show_website.php with correct aid", func() {
								Expect(client.Update(context.Background(), acct)).To(Succeed())
							})
						})
					})
					Describe("Delete()", func() {
						BeforeEach(func() {
							rspMsg = "accountdeleted"
							form = url.Values{}
							form.Set("delete", "1")
							form.Set("extjs", "1")
							form.Set("token", token)
							form.Set("aid", acct.ID)
						})
						It("requests /show_website.php with correct aid and delete=1", func() {
							Expect(client.Delete(context.Background(), acct.ID)).To(Succeed())
						})
					})
				})

				Context("when account does not exist", func() {
					BeforeEach(func() {
						header := http.Header{}
						header.Set("Content-Length", "0")
						server.AppendHandlers(
							ghttp.CombineHandlers(
								ghttp.VerifyRequest(http.MethodPost, EndpointShowWebsite),
								ghttp.RespondWith(http.StatusOK, nil, header),
							),
						)
					})
					AfterEach(func() {
						// /iterations.php, /login.php, /login_check.php, /show_website.php
						Expect(server.ReceivedRequests()).To(HaveLen(4))
					})
					Describe("Update()", func() {
						It("returns AccountNotFoundError", func() {
							Expect(client.Update(context.Background(), acct)).To(MatchError(&AccountNotFoundError{acct.ID}))
						})
					})
					Describe("Delete()", func() {
						It("returns AccountNotFoundError", func() {
							id := "notExisting"
							Expect(client.Delete(context.Background(), id)).To(MatchError(&AccountNotFoundError{id}))
						})
					})
				})

				Context("when HTTP error response", func() {
					var err error
					var path, method string
					BeforeEach(func() {
						server.AppendHandlers(
							ghttp.RespondWith(http.StatusInternalServerError, ""),
						)
					})
					AfterEach(func() {
						Expect(err).To(MatchError(MatchRegexp(
							method + ` http://127\.0\.0\.1:[0-9]{1,5}` + path + `: 500 Internal Server Error$`)))
					})
					Describe("Add()", func() {
						It("returns error including HTTP status code", func() {
							_, err = client.Accounts(context.Background())
							method = http.MethodGet
							path = EndointGetAccts + `\?b64=1&hasplugin=1\.3\.3&mobile=1&requestsrc=cli`
						})
					})
					Describe("Update()", func() {
						It("returns error including HTTP status code", func() {
							err = client.Update(context.Background(), acct)
							method = http.MethodPost
							path = EndpointShowWebsite
						})
					})
					Describe("Delete()", func() {
						It("returns error including HTTP status code", func() {
							err = client.Delete(context.Background(), "fakeID")
							method = http.MethodPost
							path = EndpointShowWebsite
						})
					})
					Describe("Logout()", func() {
						It("returns error including HTTP status code", func() {
							err = client.Delete(context.Background(), "fakeID")
							method = http.MethodPost
							path = EndpointShowWebsite
						})
					})
				})

				Context("when Client Logout()", func() {
					BeforeEach(func() {
						form = url.Values{}
						form.Set("method", "cli")
						form.Set("noredirect", "1")

						server.AppendHandlers(
							ghttp.CombineHandlers(
								ghttp.VerifyRequest(http.MethodPost, EndointLogout),
								contentTypeVerifier,
								ghttp.VerifyForm(form),
								ghttp.RespondWith(http.StatusOK, ""),
							),
						)
						Expect(client.Logout(context.Background())).To(Succeed())
					})
					AfterEach(func() {
						// /iterations.php, /login.php, /login_check.php, /logout.php
						Expect(server.ReceivedRequests()).To(HaveLen(4))
					})
					AssertUnauthenticatedBehavior()
				})

				Context("when request gets canceled", func() {
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
			})

			Context("when session becomes dead (e.g. when session cookie expires)", func() {
				rsp := `<?xml version="1.0" encoding="UTF-8"?>
	<response>
	<error silent="1" from="session is not live"/>
	</response>`
				BeforeEach(func() {
					server.AppendHandlers(
						ghttp.CombineHandlers(
							ghttp.VerifyRequest(http.MethodPost, EndpointLoginCheck),
							ghttp.RespondWith(http.StatusOK, rsp),
						),
					)
				})
				AfterEach(func() {
					// /iterations.php, /login.php, /login_check.php
					Expect(server.ReceivedRequests()).To(HaveLen(3))
				})
				AssertUnauthenticatedBehavior()
			})
		})
	})
})

func readFile(file string) string {
	content, err := ioutil.ReadFile("test/unit/data/" + file)
	Expect(err).NotTo(HaveOccurred())
	return strings.TrimSuffix(string(content), "\n")
}
