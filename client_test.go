package lastpass_test

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"

	. "github.com/ansd/lastpass-go"
)

var _ = Describe("Client", func() {
	var client *Client
	var server *ghttp.Server
	var acct *Account
	var form url.Values
	const user = "lastpass-go@gmx.de"
	const passwd = "thisAccountDoesN0tExist :-)"
	const passwdIterations = "100100"
	const token = "fakeToken"
	contentTypeVerifier := ghttp.VerifyContentType("application/x-www-form-urlencoded")

	BeforeEach(func() {
		server = ghttp.NewServer()
		client = &Client{BaseURL: server.URL()}
		form = url.Values{}
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

	Context("when user is logged in", func() {
		BeforeEach(func() {
			loginForm := url.Values{}
			loginForm.Set("method", "cli")
			loginForm.Set("xml", "1")
			loginForm.Set("username", user)
			loginForm.Set("iterations", passwdIterations)

			server.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest(http.MethodPost, "/iterations.php"),
					contentTypeVerifier,
					ghttp.VerifyFormKV("email", user),
					ghttp.RespondWith(http.StatusOK, passwdIterations),
				),
				ghttp.CombineHandlers(
					ghttp.VerifyRequest(http.MethodPost, "/login.php"),
					contentTypeVerifier,
					ghttp.VerifyForm(loginForm),
					ghttp.RespondWith(http.StatusOK, fmt.Sprintf("<ok token=\"%s\"/>", token)),
				),
			)
			Expect(client.Login(user, passwd)).To(Succeed())
		})

		Describe("Login()", func() {
			It("requests /iterations.php and /login.php", func() {
				Expect(server.ReceivedRequests()).To(HaveLen(2))
			})
		})

		Describe("Logout()", func() {
			BeforeEach(func() {
				form.Set("method", "cli")
				form.Set("noredirect", "1")

				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodPost, "/logout.php"),
						contentTypeVerifier,
						ghttp.VerifyForm(form),
						ghttp.RespondWith(http.StatusOK, ""),
					),
				)
			})
			It("requests /logout.php", func() {
				Expect(client.Logout()).To(Succeed())
			})
		})

		Describe("Accounts()", func() {
			const rsp = `<?xml version="1.0" encoding="UTF-8"?>
<response>
		<accounts accts_version="7" updated_enc="1" encrypted_username="oPESriXvEY2ueIIThKKVjAiq6XfbtiQCskxw9egZYJQ=" cbc="1">
				<account name="!Sd7ykqSvqcfaJhAzuJ2qkA==|Qu7rG7ItX2NQpXGXCCAoCw==" urid="0" id="redacted1" url="68747470733a2f2f7369746531" m="" http="" fav="0" favico="0" autologin="0" basic_auth="0" group="!BqCZIGQw3tcL8jfEulTKSw==|B5hQA6I0/diUEVAD8hzwXA==" fiid="redacted" genpw="0" extra="!NQgdpU3aNJLSEh2FUIaURg==|GXMdUvoG+BhQ1U/jKSp6kg==" isbookmark="0" never_autofill="0" last_touch="0" last_modified="1563546859" sn="0" realm="" sharedfromaid="" pwprotect="0" launch_count="0" username="!s0V0uZIaoFAoEy+1EWsyrw==|4uKEWau+7UuI5EqkkWhaag==" groupid="0">
						<login urid="0" url="68747470733a2f2f7369746531" submit_id="" captcha_id="" custom_js="" u="!s0V0uZIaoFAoEy+1EWsyrw==|4uKEWau+7UuI5EqkkWhaag==" p="!Y/yjpv4ksvKTqOpm4HNhSg==|orxTv9dqhjFhnKtxY6G9QA==" o="" method=""></login>
				</account>
				<account name="!sHHZM24iYdEHcUUGuKZVww==|IsQNyfNcIhOQ5FjAdMaONg==" urid="0" id="redacted2" url="687474703a2f2f736e" m="" http="" fav="0" favico="0" autologin="0" basic_auth="0" group="!pY4qTqb2Y10IWKW9GKVobg==|0vYyCoEorZ42a6NqNrGscA==" fiid="redacted" genpw="0" extra="!W3jfGc4ZMR7JbfxvF10dqA==|IwRxNsF6s1gc+BRoaqkffvyTKWolCYhy4PAQj8aceKM=" isbookmark="0" never_autofill="0" last_touch="1563561286" last_modified="1563546886" sn="1" realm="" sharedfromaid="" pwprotect="0" launch_count="0" username="" groupid="1">
						<login urid="0" url="687474703a2f2f736e" submit_id="" captcha_id="" custom_js="" u="" p="" o="" method=""></login>
				</account>
				<account name="!+3GSvmsTMBcoGUzPYQphIw==|W3go8Ms4XdblWJJJsuZjVQ==" urid="0" id="redacted3" url="68747470733a2f2f7369746533" m="" http="" fav="0" favico="0" autologin="0" basic_auth="0" group="" fiid="redacted" genpw="0" extra="" isbookmark="0" never_autofill="0" last_touch="1563562773" last_modified="1563548373" sn="0" realm="" sharedfromaid="" pwprotect="0" launch_count="0" username="">
						<login urid="0" url="68747470733a2f2f7369746533" submit_id="" captcha_id="" custom_js="" u="" p="" o="" method=""></login>
				</account>
		</accounts>
</response>`
			BeforeEach(func() {
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodGet, "/getaccts.php", "requestsrc=cli"),
						ghttp.RespondWith(http.StatusOK, rsp),
					),
				)
			})
			It("requests /getaccts.php", func() {
				accts, err := client.Accounts()
				Expect(err).NotTo(HaveOccurred())
				Expect(accts).To(ConsistOf(
					&Account{
						ID:       "redacted1",
						Name:     "name1",
						Username: "user1",
						Password: "pwd1",
						URL:      "https://site1",
						Group:    "folder1",
						Notes:    "notes1",
					},
					&Account{
						ID:    "redacted2",
						Name:  "name2",
						URL:   "http://sn",
						Group: "folder1",
						Notes: "some secure note",
					},
					&Account{
						ID:   "redacted3",
						Name: "name3",
						URL:  "https://site3",
					},
				))
			})
		})

		Context("when operating on a single account", func() {
			var rspMsg string
			JustBeforeEach(func() {
				server.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest(http.MethodPost, "/show_website.php"),
						contentTypeVerifier,
						ghttp.VerifyForm(form),
						ghttp.RespondWith(http.StatusOK, fmt.Sprintf(
							"<xmlresponse><result aid=\"%s\" msg=\"%s\"></result></xmlresponse>",
							acct.ID, rspMsg),
						),
					),
				)
			})

			Context("when upserting", func() {
				BeforeEach(func() {
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
					It("requests /show_website.php with aid=0", func() {
						addedID, err := client.Add(
							acct.Name,
							acct.Username,
							acct.Password,
							acct.URL,
							acct.Group,
							acct.Notes,
						)
						Expect(err).NotTo(HaveOccurred())
						Expect(addedID).To(Equal(acct.ID))
					})
				})
				Describe("Update()", func() {
					BeforeEach(func() {
						rspMsg = "accountupdated"
						form.Set("aid", acct.ID)
					})
					It("requests /show_website.php with correct aid", func() {
						Expect(client.Update(acct)).To(Succeed())
					})
				})
			})
			Describe("Delete()", func() {
				BeforeEach(func() {
					rspMsg = "accountdeleted"
					form.Set("delete", "1")
					form.Set("extjs", "1")
					form.Set("token", token)
					form.Set("aid", acct.ID)
				})
				It("requests /show_website.php with correct aid and delete=1", func() {
					Expect(client.Delete(acct.ID)).To(Succeed())
				})
			})
		})
	})
})
