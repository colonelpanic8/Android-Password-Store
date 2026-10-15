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
  ): JsonObject {
    val entry = entry(content)
    return Json.parseToJsonElement(
        EvaCredential.reply(
          "github.com/alice",
          entry,
          username ?: EvaCredential.username(entry, null, null),
          isPasskey,
        )
      )
      .jsonObject
  }

  private fun visible(reply: JsonObject) = "${reply["content"]}${reply["structuredContent"]}"

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
