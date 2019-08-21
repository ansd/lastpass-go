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
		var user, passwd, passwdIterations string
		contentTypeVerifier := ghttp.VerifyContentType("application/x-www-form-urlencoded")

		BeforeEach(func() {
			user = readFile("user.txt")
			passwd = readFile("passwd.txt")

			loginForm = url.Values{}
			loginForm.Set("method", "cli")
			loginForm.Set("xml", "1")
			loginForm.Set("username", user)
		})

		Context("when username is empty", func() {
			It("returns a descriptive error", func() {
				_, err := NewClient(context.Background(), "", passwd, WithBaseURL(server.URL()))
				Expect(err).To(MatchError("username must not be empty"))
			})
		})
		Context("when password is empty", func() {
			It("returns a descriptive error", func() {
				_, err := NewClient(context.Background(), user, "", WithBaseURL(server.URL()))
				Expect(err).To(MatchError("masterPassword must not be empty"))
			})
		})

		Context("with 1 password iteration", func() {
			BeforeEach(func() {
				passwdIterations = "1"
				loginForm.Set("iterations", passwdIterations)
				respLoginCheck := `<response> <ok accts_version="111"/> </response>`
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodPost, EndpointIterations),
						contentTypeVerifier,
						ghttp.VerifyFormKV("email", user),
						ghttp.RespondWith(http.StatusOK, passwdIterations),
					),
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodPost, EndpointLogin),
						contentTypeVerifier,
						ghttp.VerifyForm(loginForm),
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
						ID:   readFile("id-name3.txt"),
						Name: "name3",
						URL:  "http://url3",
					},
				))
				// /iterations.php, /login.php, /login_check.php, /getaccts.php
				Expect(server.ReceivedRequests()).To(HaveLen(4))
			})
		})

		Context("with default password iterations", func() {
			BeforeEach(func() {
				passwdIterations = "100100"
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
					It("returns AuthenticationError", func() {
						client, err := NewClient(context.Background(), user, passwd, WithBaseURL(server.URL()))
						Expect(client).To(BeNil())
						Expect(err).To(MatchError(fmt.Sprintf("%s: %s", cause, msg)))
						_, ok := err.(*AuthenticationError)
						Expect(ok).To(BeTrue())
						// /iterations.php, /login.php
						Expect(server.ReceivedRequests()).To(HaveLen(2))
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
							// /iterations.php, /login.php, MaxLoginRetries * /login/php
							Expect(server.ReceivedRequests()).To(HaveLen(2 + MaxLoginRetries))
						})
					})
					Context("when re-trying due to unknown error", func() {
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
							// /iterations.php, /login.php, /login/php
							Expect(server.ReceivedRequests()).To(HaveLen(3))
						})
					})
				})
			})

			Context("when NewClient() succeeds", func() {
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
					var err error
					client, err = NewClient(context.Background(), user, passwd, WithOneTimePassword(otp), WithBaseURL(server.URL()))
					Expect(err).NotTo(HaveOccurred())
				})

				Describe("NewClient()", func() {
					It("requests /iterations.php and /login.php", func() {
						Expect(server.ReceivedRequests()).To(HaveLen(2))
					})
				})
				Context("when session is live", func() {
					rsp := `<response> <ok accts_version="111"/> </response>`
					BeforeEach(func() {
						server.AppendHandlers(
							ghttp.CombineHandlers(
								ghttp.VerifyRequest(http.MethodPost, EndpointLoginCheck),
								ghttp.RespondWith(http.StatusOK, rsp),
							),
						)
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
									form.Set("aid", "0")
								})
								Context("when server returns 'accountadded'", func() {
									BeforeEach(func() {
										rspMsg = "accountadded"
									})
									It("requests /show_website.php with aid=0 and sets account ID correctly", func() {
										acct.ID = "ignored"
										Expect(client.Add(context.Background(), acct)).To(Succeed())
										Expect(acct.ID).To(Equal("test ID"))
									})
								})
								Context("when server does not return 'accountadded'", func() {
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
								Context("when server returns 'accountupdated'", func() {
									BeforeEach(func() {
										rspMsg = "accountupdated"
									})
									It("requests /show_website.php with correct aid", func() {
										Expect(client.Update(context.Background(), acct)).To(Succeed())
									})
								})
								Context("when server does not return 'accountupdated'", func() {
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
							Context("when server returns 'accountdeleted'", func() {
								BeforeEach(func() {
									rspMsg = "accountdeleted"
								})
								It("requests /show_website.php with correct aid and delete=1", func() {
									Expect(client.Delete(context.Background(), acct.ID)).To(Succeed())
								})
							})
							Context("when server does not return 'accountdeleted'", func() {
								BeforeEach(func() {
									rspMsg = "not deleted"
								})
								It("returns a descriptive error", func() {
									Expect(client.Delete(context.Background(), acct.ID)).To(MatchError(
										fmt.Sprintf("failed to delete account (ID=%s)", acct.ID)))
								})
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
									err = client.Delete(context.Background(), "fakeID")
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
					Context("when Client Logout()", func() {
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
							// /iterations.php, /login.php, /login_check.php, /logout.php
							Expect(server.ReceivedRequests()).To(HaveLen(4))
						})
						AssertUnauthenticatedBehavior()
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
	Describe("Add()", func() {
		Context("when account.Name is empty", func() {
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
	content, err := ioutil.ReadFile("test/unit/data/" + file)
	Expect(err).NotTo(HaveOccurred())
	return strings.TrimSuffix(string(content), "\n")
}
