/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.eva

import app.passwordstore.data.passfile.PasswordEntry
import app.passwordstore.util.time.UserClock
import app.passwordstore.util.totp.Otp
import app.passwordstore.util.totp.UriTotpFinder
import com.github.michaelbull.result.getOrThrow
import java.io.File
import java.nio.file.Files
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class EvaCredentialTest {

  private val clock =
    object : UserClock() {
      override fun instant(): Instant = Instant.ofEpochSecond(1_700_000_020)
    }

  private fun entry(content: String) = PasswordEntry(clock, UriTotpFinder(), content.toCharArray())

  private fun reply(
    content: String,
    username: EvaCredential.Username? = null,
    isPasskey: Boolean = false,
    fields: List<String> = emptyList(),
    path: String = "github.com/alice",
  ): JsonObject {
    val entry = entry(content)
    return Json.parseToJsonElement(
        EvaCredential.reply(
          path,
          entry,
          username ?: EvaCredential.username(entry, null, null),
          isPasskey,
          fields,
        )
      )
      .jsonObject
  }

  private fun visible(reply: JsonObject) = "${reply["content"]}${reply["structuredContent"]}"

  private fun text(reply: JsonObject) =
    reply.getValue("content").jsonArray.single().jsonObject.getValue("text").jsonPrimitive.content

  private fun json(literal: String) = Json.parseToJsonElement(literal)

  private val card =
    "card-pin-8642\n" +
      "name: Alice Example\n" +
      "number: 4111 1111 1111 1111\n" +
      "expiry: 12/29\n" +
      "cvv: 737\n" +
      "zip: 90210\n" +
      "pin:\n"

  @Test
  fun requestedFieldsTravelOnlyAsSecrets() {
    val reply = reply(card, fields = listOf("Number", "zip"), path = "cards/visa")
    assertEquals(
      json(
        """{
          "password": {"value": "card-pin-8642", "label": "Password for cards/visa"},
          "number": {"value": "4111 1111 1111 1111", "label": "number of cards/visa"},
          "zip": {"value": "90210", "label": "zip of cards/visa"}
        }"""
      ),
      reply.getValue("secrets"),
    )
    val data = reply.getValue("structuredContent").jsonObject
    assertEquals(
      json("""[{"field": "number", "secret": "number"}, {"field": "zip", "secret": "zip"}]"""),
      data.getValue("fieldSecrets"),
    )
    assertEquals(json("[]"), data.getValue("unavailableFields"))
    assertEquals(
      "Decrypted cards/visa. Its password is available as the secret \"password\". Requested " +
        "fields handed over as secrets: \"number\" as \"number\", \"zip\" as \"zip\".",
      text(reply),
    )
    listOf("card-pin-8642", "4111", "90210", "737", "12/29").forEach {
      assertFalse(it in visible(reply), "leaked $it")
    }
  }

  @Test
  fun unavailableFieldsAreNamedWithTheEntrysFields() {
    val reply =
      reply(
        card + "blob: ${"x".repeat(EvaProtocol.SECRET_VALUE_CODE_POINTS + 1)}\n",
        fields = listOf("card number", "pin", "blob", "cvv", "CVV"),
        path = "cards/visa",
      )
    assertEquals("completed", reply.getValue("status").jsonPrimitive.content)
    assertEquals(
      setOf("password", "cvv"),
      reply.getValue("secrets").jsonObject.keys,
    )
    assertEquals(
      json(
        """[
          {"field": "card number", "reason": "not_found"},
          {"field": "pin", "reason": "empty"},
          {"field": "blob", "reason": "too_long"}
        ]"""
      ),
      reply.getValue("structuredContent").jsonObject.getValue("unavailableFields"),
    )
    assertEquals(
      "Decrypted cards/visa. Its password is available as the secret \"password\". Requested " +
        "fields handed over as secrets: \"cvv\" as \"cvv\". Not handed over: \"card number\" " +
        "(no such field), \"pin\" (empty), \"blob\" (over EVA's 4096-character limit). Its " +
        "fields are \"number\", \"expiry\", \"cvv\", \"zip\", \"pin\", \"blob\".",
      text(reply),
    )
    assertFalse("xxxx" in visible(reply))
  }

  @Test
  fun fieldSecretNamesAvoidCollisions() {
    val reply =
      reply(
        "pw\nPassword: old-pw\nOTP: 1111\nZip Code: 90210\nzip_code: 94117\n" +
          "3DS PIN: 2468\nКод: 9999\n",
        fields = listOf("password", "otp", "Zip Code", "zip_code", "3DS PIN", "Код"),
      )
    assertEquals(
      json(
        """{
          "password": {"value": "pw", "label": "Password for github.com/alice"},
          "password_2": {"value": "old-pw", "label": "Password of github.com/alice"},
          "otp_2": {"value": "1111", "label": "OTP of github.com/alice"},
          "zip_code": {"value": "90210", "label": "Zip Code of github.com/alice"},
          "zip_code_2": {"value": "94117", "label": "zip_code of github.com/alice"},
          "field_3ds_pin": {"value": "2468", "label": "3DS PIN of github.com/alice"},
          "field": {"value": "9999", "label": "Код of github.com/alice"}
        }"""
      ),
      reply.getValue("secrets"),
    )
  }

  @Test
  fun repliesWithoutFieldsKeepTheirShape() {
    val data = reply(card).getValue("structuredContent").jsonObject
    assertNull(data["fieldSecrets"])
    assertNull(data["unavailableFields"])
    assertEquals(
      listOf("number", "expiry", "cvv", "zip", "pin"),
      data.getValue("fieldNames").jsonArray.map { it.jsonPrimitive.content },
    )
  }

  @Test
  fun secretValuesOnlyTravelAsSecrets() {
    val reply =
      reply(
        "hunter2-Password\n" +
          "login: alice@example.org\n" +
          "url: https://github.com/login\n" +
          "pin: 4321-pin\n" +
          "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n" +
          "\n" +
          "recovery codes are aaaa-bbbb-notes\n"
      )
    val otp =
      Otp.calculateCode("JBSWY3DPEHPK3PXP", 1_700_000_020 / 30, "sha1", "6", "GitHub").getOrThrow()
    val secrets = reply.getValue("secrets").jsonObject
    assertEquals(
      "hunter2-Password",
      secrets.getValue("password").jsonObject.getValue("value").jsonPrimitive.content,
    )
    assertEquals(otp, secrets.getValue("otp").jsonObject.getValue("value").jsonPrimitive.content)

    val shown = visible(reply)
    listOf("hunter2-Password", otp, "4321-pin", "JBSWY3DPEHPK3PXP", "aaaa-bbbb-notes").forEach {
      assertFalse(it in shown, "leaked $it")
    }
    val data = reply.getValue("structuredContent").jsonObject
    assertEquals("alice@example.org", data.getValue("username").jsonPrimitive.content)
    assertEquals("entry", data.getValue("usernameSource").jsonPrimitive.content)
    assertEquals("https://github.com/login", data.getValue("url").jsonPrimitive.content)
    assertEquals(
      listOf("pin"),
      data.getValue("fieldNames").jsonArray.map { it.jsonPrimitive.content },
    )
    assertTrue(data.getValue("hasOtp").jsonPrimitive.boolean)
    assertTrue(data.getValue("hasNotes").jsonPrimitive.boolean)
    assertEquals("20", data.getValue("otpValidForSeconds").jsonPrimitive.content)
    assertTrue("valid for 20 more seconds" in reply["content"].toString())
  }

  @Test
  fun passkeyEntriesHandOverNoPassword() {
    val reply = reply("bm90LWEtcmVhbC1wYXNza2V5\nlogin: alice", isPasskey = true)
    assertNull(reply["secrets"])
    val data = reply.getValue("structuredContent").jsonObject
    assertTrue(data.getValue("isPasskey").jsonPrimitive.boolean)
    assertFalse(data.getValue("hasPassword").jsonPrimitive.boolean)
    assertFalse("bm90LWEtcmVhbC1wYXNza2V5" in visible(reply))
  }

  @Test
  fun usernameFollowsTheAutofillOrder() {
    val withLine = entry("pw\nusername: fromline")
    assertEquals(
      EvaCredential.Username("fromline", "entry"),
      EvaCredential.username(withLine, "frompath", "default"),
    )
    val bare = entry("pw")
    assertEquals(
      EvaCredential.Username("frompath", "path"),
      EvaCredential.username(bare, "frompath", "default"),
    )
    assertEquals(
      EvaCredential.Username("default", "default"),
      EvaCredential.username(bare, null, "default"),
    )
    assertNull(EvaCredential.username(bare, null, null))
    assertTrue("No username" in reply("pw")["content"].toString())
  }

  @Test
  fun resolveStaysInsideTheStore() {
    val parent = Files.createTempDirectory("eva").toFile()
    try {
      val root = File(parent, "store").apply { mkdirs() }
      File(root, "github.com").mkdirs()
      File(root, "github.com/alice.gpg").writeText("x")
      File(parent, "outside.gpg").writeText("x")
      val expected = File(root, "github.com/alice.gpg")
      assertEquals(expected, EvaCredential.resolve(root, "github.com/alice"))
      assertEquals(expected, EvaCredential.resolve(root, "/github.com/alice.gpg"))
      listOf(
          "../outside",
          "github.com/../../outside",
          "github.com",
          "missing",
          "",
          "github.com//alice",
        )
        .forEach { assertNull(EvaCredential.resolve(root, it), it) }
    } finally {
      parent.deleteRecursively()
    }
  }
}
