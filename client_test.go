package lastpass_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"

	. "github.com/veloceapps/lastpass-go"
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
				err := client.Delete(context.Background(), acct)
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

	When("Client never logged in", func() {
		BeforeEach(func() {
			client = &Client{}
		})
		AssertUnauthenticatedBehavior()
	})

	When("NewClient()", func() {
		var loginForm url.Values
		var user, passwd string
		contentTypeVerifier := ghttp.VerifyContentType("application/x-www-form-urlencoded")

		BeforeEach(func() {
			user = readFile("user.txt")
			passwd = readFile("passwd.txt")

			loginForm = url.Values{}
			loginForm.Set("method", "cli")
			loginForm.Set("xml", "1")
			loginForm.Set("username", user)
			loginForm.Set("iterations", "100100")
		})

		When("username is empty", func() {
			It("returns a descriptive error", func() {
				_, err := NewClient(context.Background(), "", passwd, WithBaseURL(server.URL()))
				Expect(err).To(MatchError("username must not be empty"))
			})
		})
		When("password is empty", func() {
			It("returns a descriptive error", func() {
				_, err := NewClient(context.Background(), user, "", WithBaseURL(server.URL()))
				Expect(err).To(MatchError("masterPassword must not be empty"))
			})
		})

		Context("with 1 password iteration", func() {
			BeforeEach(func() {
				respLoginCheck := `<response> <ok accts_version="111"/> </response>`
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodPost, EndpointLogin),
						contentTypeVerifier,
						ghttp.VerifyForm(loginForm),
						ghttp.RespondWith(http.StatusOK, "<response><error iterations=\"1\"/></response>"),
					),
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodPost, EndpointLogin),
						contentTypeVerifier,
						ghttp.VerifyFormKV("iterations", "1"),
						ghttp.RespondWith(http.StatusOK, fmt.Sprintf("<ok token=\"%s\" privatekeyenc=\"%s\"/>",
							"fakeToken", readFile("privatekeyencrypted-1iteration.txt"))),
					),
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodPost, EndpointLoginCheck),
						ghttp.RespondWith(http.StatusOK, respLoginCheck),
					),
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodGet, EndpointGetAccts,
							"requestsrc=cli&mobile=1&b64=1&hasplugin=1.3.3"),
						ghttp.RespondWith(http.StatusOK, readFile("blob-1iteration.txt")),
					),
				)
				var err error
				client, err = NewClient(context.Background(), user, passwd, WithBaseURL(server.URL()))
				Expect(err).NotTo(HaveOccurred())
			})
			It("derives correct encryption key", func() {
				accts, err := client.Accounts(context.Background())
				Expect(err).NotTo(HaveOccurred())
				Expect(accts).To(ConsistOf(
					&Account{
						ID:              readFile("id-name3.txt"),
						Name:            "name3",
						URL:             "http://url3",
						LastModifiedGMT: "1566374004",
						LastTouch:       "1566374009",
					},
				))
				// /login.php, /login.php, /login_check.php, /getaccts.php
				Expect(server.ReceivedRequests()).To(HaveLen(4))
			})
		})

		Context("empty privatekeyenc", func() {
			BeforeEach(func() {
				respLoginCheck := `<response> <ok accts_version="111"/> </response>`
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodPost, EndpointLogin),
						contentTypeVerifier,
						ghttp.VerifyForm(loginForm),
						ghttp.RespondWith(http.StatusOK, "<response><error iterations=\"1\"/></response>"),
					),
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodPost, EndpointLogin),
						contentTypeVerifier,
						ghttp.VerifyFormKV("iterations", "1"),
						ghttp.RespondWith(http.StatusOK, "<ok token=\"fakeToken\" privatekeyenc=\"\"/>"),
					),
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodPost, EndpointLoginCheck),
						ghttp.RespondWith(http.StatusOK, respLoginCheck),
					),
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodGet, EndpointGetAccts,
							"requestsrc=cli&mobile=1&b64=1&hasplugin=1.3.3"),
						ghttp.RespondWith(http.StatusOK, readFile("blob-1iteration.txt")),
					),
				)
				var err error
				client, err = NewClient(context.Background(), user, passwd, WithBaseURL(server.URL()))
				Expect(err).NotTo(HaveOccurred())
			})
			It("works", func() {
				accts, err := client.Accounts(context.Background())
				Expect(err).NotTo(HaveOccurred())
				Expect(accts).To(ConsistOf(
					&Account{
						ID:              readFile("id-name3.txt"),
						Name:            "name3",
						URL:             "http://url3",
						LastModifiedGMT: "1566374004",
						LastTouch:       "1566374009",
					},
				))
				// /login.php, /login.php, /login_check.php, /getaccts.php
				Expect(server.ReceivedRequests()).To(HaveLen(4))
			})
		})

		When("authentication fails", func() {
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
				It("returns AuthenticationError", func() {
					client, err := NewClient(context.Background(), user, passwd, WithBaseURL(server.URL()))
					Expect(client).To(BeNil())
					Expect(err).To(MatchError(fmt.Sprintf("%s: %s", cause, msg)))
					_, ok := err.(*AuthenticationError)
					Expect(ok).To(BeTrue())
					// /login.php
					Expect(server.ReceivedRequests()).To(HaveLen(1))
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
				})
				Context("until MaxLoginRetries is reached", func() {
					JustBeforeEach(func() {
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
					It("returns AuthenticationError", func() {
						client, err := NewClient(context.Background(), user, passwd, WithBaseURL(server.URL()))
						Expect(client).To(BeNil())
						Expect(err).To(MatchError(MatchRegexp(`^didn't receive out-of-band approval within the last \d seconds$`)))
						// /login.php, MaxLoginRetries * /login/php
						Expect(server.ReceivedRequests()).To(HaveLen(1 + MaxLoginRetries))
					})
				})
				When("re-trying due to unknown error", func() {
					var retryCause, retryMsg string
					JustBeforeEach(func() {
						retryMsg = "unknown"
						retryCause = "some cause"
						server.AppendHandlers(
							ghttp.CombineHandlers(
								ghttp.VerifyRequest(http.MethodPost, EndpointLogin),
								contentTypeVerifier,
								ghttp.VerifyForm(loginRetryForm),
								ghttp.RespondWith(http.StatusOK,
									fmt.Sprintf("<response><error message=\"%s\" cause=\"%s\"/></response>", retryMsg, retryCause)),
							),
						)
					})
					It("returns AuthenticationError", func() {
						client, err := NewClient(context.Background(), user, passwd, WithBaseURL(server.URL()))
						Expect(client).To(BeNil())
						Expect(err).To(MatchError(fmt.Sprintf("%s: %s", retryCause, retryMsg)))
						// /login.php, /login/php
						Expect(server.ReceivedRequests()).To(HaveLen(2))
					})
				})
			})
		})

		When("NewClient() succeeds", func() {
			var form url.Values
			const token = "fakeToken"
			const otp = "654321"

			BeforeEach(func() {
				privateKeyEncrypted := readFile("privatekeyencrypted.txt")
				loginForm.Set("otp", otp)

				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodPost, EndpointLogin),
						contentTypeVerifier,
						ghttp.VerifyForm(loginForm),
						ghttp.RespondWith(http.StatusOK, fmt.Sprintf("<ok token=\"%s\" privatekeyenc=\"%s\"/>",
							token, privateKeyEncrypted)),
					),
				)
			})

			Context("trust", func() {
				var configDir, trustIDFile, trustLabel string

				BeforeEach(func() {
					var err error
					configDir, err = ioutil.TempDir("", "lastpass-go-unit-test")
					Expect(err).ToNot(HaveOccurred())
					trustIDFile = filepath.Join(configDir, "trusted_id")

					hostname, err := os.Hostname()
					Expect(err).NotTo(HaveOccurred())
					trustLabel = fmt.Sprintf("%s %s %s", hostname, runtime.GOOS, "lastpass-go")
				})

				AfterEach(func() {
					Expect(os.RemoveAll(configDir)).To(Succeed())
				})

				When("trusted_id file is present", func() {
					const fakeTrustID string = "!@#$0123456789abcdexyzABCDEFGXYZ"

					BeforeEach(func() {
						Expect(ioutil.WriteFile(trustIDFile, []byte(fakeTrustID), 0600)).To(Succeed())
					})

					AfterEach(func() {
						trustID, err := ioutil.ReadFile(trustIDFile)
						Expect(err).NotTo(HaveOccurred())
						Expect(string(trustID)).To(Equal(fakeTrustID), "trusted_id file should not be modified")
					})

					When("WithTrust() option is not set", func() {
						It("requests only /login.php, but not /trust.php", func() {
							var err error
							client, err = NewClient(context.Background(), user, passwd, WithOneTimePassword(otp), WithBaseURL(server.URL()),
								WithConfigDir(configDir),
							)
							Expect(err).NotTo(HaveOccurred())

							Expect(server.ReceivedRequests()).To(HaveLen(1))
						})
						It("uses trust ID to log in", func() {
							loginForm.Set("uuid", fakeTrustID)

							var err error
							client, err = NewClient(context.Background(), user, passwd, WithOneTimePassword(otp), WithBaseURL(server.URL()),
								WithConfigDir(configDir),
							)
							Expect(err).NotTo(HaveOccurred())
						})
					})

					When("WithTrust() option is set", func() {
						It("uses trust ID to login and posts to /trust.php endpoint to update the label", func() {
							loginForm.Set("uuid", fakeTrustID)
							loginForm.Set("trustlabel", trustLabel)

							trustForm := url.Values{}
							trustForm.Set("uuid", fakeTrustID)
							trustForm.Set("token", token)
							trustForm.Set("trustlabel", trustLabel)
							server.AppendHandlers(
								ghttp.CombineHandlers(
									ghttp.VerifyRequest(http.MethodPost, EndpointTrust),
									contentTypeVerifier,
									ghttp.VerifyForm(trustForm),
									ghttp.RespondWith(http.StatusOK, nil),
								),
							)

							var err error
							client, err = NewClient(context.Background(), user, passwd, WithOneTimePassword(otp), WithBaseURL(server.URL()),
								WithConfigDir(configDir),
								WithTrust(),
							)
							Expect(err).NotTo(HaveOccurred())
						})
					})
				})

				When("trusted_id file is absent and WithTrust() option is set", func() {
					It("creates a new trust ID", func() {
						By("posting the new trust label to /trust.php endpoint")
						server.AppendHandlers(
							ghttp.CombineHandlers(
								ghttp.VerifyRequest(http.MethodPost, EndpointTrust),
								contentTypeVerifier,
								ghttp.VerifyFormKV("token", token),
								ghttp.VerifyFormKV("trustlabel", trustLabel),
								// form value for generated uuid is not known in advance and therefore tested at the end of this test case
								ghttp.RespondWith(http.StatusOK, nil),
							),
						)

						Expect(trustIDFile).ToNot(BeAnExistingFile())

						var err error
						client, err = NewClient(context.Background(), user, passwd, WithOneTimePassword(otp), WithBaseURL(server.URL()),
							WithConfigDir(configDir),
							WithTrust(),
						)
						Expect(err).NotTo(HaveOccurred())

						By("creating a new trusted_id file")
						Expect(trustIDFile).To(BeARegularFile())
						uuid, err := ioutil.ReadFile(trustIDFile)
						Expect(err).NotTo(HaveOccurred())
						Expect(uuid).To(MatchRegexp(`^[a-zA-Z0-9!@#\$]{32}$`))

						By("making the new file only accessible to the user")
						fileInfo, err := os.Stat(trustIDFile)
						Expect(err).NotTo(HaveOccurred())
						Expect(fileInfo.Mode()).To(Equal(os.FileMode(0600)))

						By("posting the new trust ID to /trust.php endpoint")
						// /login.php, /trust.php
						Expect(server.ReceivedRequests()).To(HaveLen(2))
						trustRequest := server.ReceivedRequests()[1]
						Expect(trustRequest.FormValue("uuid")).To(Equal(string(uuid)))
					})
				})
			})

			Context("no trust, i.e. neither WithTrust() option is set nor trusted_id file exists", func() {
				BeforeEach(func() {
					var err error
					client, err = NewClient(context.Background(), user, passwd, WithOneTimePassword(otp), WithBaseURL(server.URL()))
					Expect(err).NotTo(HaveOccurred())
				})

				Describe("NewClient()", func() {
					It("requests /login.php", func() {
						Expect(server.ReceivedRequests()).To(HaveLen(1))
					})
				})

				When("session is live", func() {
					rsp := `<response> <ok accts_version="111"/> </response>`
					BeforeEach(func() {
						server.AppendHandlers(
							ghttp.CombineHandlers(
								ghttp.VerifyRequest(http.MethodPost, EndpointLoginCheck),
								ghttp.RespondWith(http.StatusOK, rsp),
							),
						)
					})
					When("successfully operating on a single account", func() {
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
							// /login.php, /login_check.php, /show_website.php
							Expect(server.ReceivedRequests()).To(HaveLen(3))
						})
						When("upserting", func() {
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
									form.Set("aid", "0")
								})
								When("server returns 'accountadded'", func() {
									BeforeEach(func() {
										rspMsg = "accountadded"
									})
									It("requests /show_website.php with aid=0 and sets account ID correctly", func() {
										acct.ID = "ignored"
										Expect(client.Add(context.Background(), acct)).To(Succeed())
										Expect(acct.ID).To(Equal("test ID"))
									})
								})
								When("server does not return 'accountadded'", func() {
									BeforeEach(func() {
										rspMsg = "not added"
									})
									It("returns a descriptive error", func() {
										Expect(client.Add(context.Background(), acct)).To(MatchError("failed to add account"))
									})
								})
							})
							Describe("Update()", func() {
								BeforeEach(func() {
									form.Set("aid", acct.ID)
								})
								When("server returns 'accountupdated'", func() {
									BeforeEach(func() {
										rspMsg = "accountupdated"
									})
									It("requests /show_website.php with correct aid", func() {
										Expect(client.Update(context.Background(), acct)).To(Succeed())
									})
								})
								When("server does not return 'accountupdated'", func() {
									BeforeEach(func() {
										rspMsg = "not updated"
									})
									It("returns a descriptive error", func() {
										Expect(client.Update(context.Background(), acct)).To(MatchError(
											fmt.Sprintf("failed to update account (ID=%s)", acct.ID)))
									})
								})
							})
						})
						Describe("Delete()", func() {
							BeforeEach(func() {
								form = url.Values{}
								form.Set("delete", "1")
								form.Set("extjs", "1")
								form.Set("token", token)
								form.Set("aid", acct.ID)
							})
							When("server returns 'accountdeleted'", func() {
								BeforeEach(func() {
									rspMsg = "accountdeleted"
								})
								It("requests /show_website.php with correct aid and delete=1", func() {
									Expect(client.Delete(context.Background(), acct)).To(Succeed())
								})
							})
							When("server does not return 'accountdeleted'", func() {
								BeforeEach(func() {
									rspMsg = "not deleted"
								})
								It("returns a descriptive error", func() {
									Expect(client.Delete(context.Background(), acct)).To(MatchError(
										fmt.Sprintf("failed to delete account (ID=%s)", acct.ID)))
								})
							})
						})
					})
					When("account does not exist", func() {
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
							// /login.php, /login_check.php, /show_website.php
							Expect(server.ReceivedRequests()).To(HaveLen(3))
						})
						Describe("Update()", func() {
							It("returns AccountNotFoundError", func() {
								Expect(client.Update(context.Background(), acct)).To(MatchError(&AccountNotFoundError{acct.ID}))
							})
						})
						Describe("Delete()", func() {
							It("returns AccountNotFoundError", func() {
								acct := &Account{ID: "notExisting"}
								Expect(client.Delete(context.Background(), acct)).To(
									MatchError(&AccountNotFoundError{acct.ID}))
							})
						})
					})

					When("HTTP error response", func() {
						var err error
						var path string
						BeforeEach(func() {
							server.AppendHandlers(
								ghttp.RespondWith(http.StatusInternalServerError, ""),
							)
						})
						AfterEach(func() {
							Expect(err).To(MatchError(MatchRegexp(
								`POST http://127\.0\.0\.1:[0-9]{1,5}` + path + `: 500 Internal Server Error$`)))
						})
						Context("returned by /show_website.php", func() {
							BeforeEach(func() {
								path = EndpointShowWebsite
							})
							Describe("Add()", func() {
								It("returns error including HTTP status code", func() {
									err = client.Add(context.Background(), acct)
								})
							})
							Describe("Update()", func() {
								It("returns error including HTTP status code", func() {
									err = client.Update(context.Background(), acct)
								})
							})
							Describe("Delete()", func() {
								It("returns error including HTTP status code", func() {
									err = client.Delete(context.Background(), &Account{ID: "fakeID"})
								})
							})
						})
						Describe("Logout()", func() {
							It("returns error including HTTP status code", func() {
								err = client.Logout(context.Background())
								path = EndpointLogout
							})
						})
					})
					When("Client Logout()", func() {
						BeforeEach(func() {
							form = url.Values{}
							form.Set("method", "cli")
							form.Set("noredirect", "1")

							server.AppendHandlers(
								ghttp.CombineHandlers(
									ghttp.VerifyRequest(http.MethodPost, EndpointLogout),
									contentTypeVerifier,
									ghttp.VerifyForm(form),
									ghttp.RespondWith(http.StatusOK, ""),
								),
							)
							Expect(client.Logout(context.Background())).To(Succeed())
						})
						AfterEach(func() {
							// /login.php, /login_check.php, /logout.php
							Expect(server.ReceivedRequests()).To(HaveLen(3))
						})
						AssertUnauthenticatedBehavior()
					})
				})
				When("session becomes dead (e.g. when session cookie expires)", func() {
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
						// /login.php, /login_check.php
						Expect(server.ReceivedRequests()).To(HaveLen(2))
					})
					AssertUnauthenticatedBehavior()
				})
			})
		})
	})
	Describe("Add()", func() {
		When("account.Name is empty", func() {
			BeforeEach(func() {
				client = &Client{}
				acct.Name = ""
			})
			It("returns a descriptive error", func() {
				Expect(client.Add(context.Background(), acct)).To(MatchError("account.Name must not be empty"))
			})
		})
	})
})

func readFile(file string) string {
	content, err := ioutil.ReadFile(filepath.Join("test", "unit", "data", file))
	Expect(err).NotTo(HaveOccurred())
	return strings.TrimSuffix(string(content), "\n")
}
