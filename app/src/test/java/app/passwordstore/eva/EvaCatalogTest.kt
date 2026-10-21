/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.eva

import app.passwordstore.eva.EvaCatalog.Admission
import app.passwordstore.eva.EvaCatalog.Call
import app.passwordstore.eva.EvaCatalog.Features
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class EvaCatalogTest {

  private val plain = Features.of(emptySet())
  private val secrets = Features.of(setOf("secrets"))
  private val withCredentials = Features.of(setOf("secrets", "credentials"))
  private val secretsRevision = EvaCatalog.revision(secrets)
  private val plainRevision = EvaCatalog.revision(plain)
  private val credentialsRevision = EvaCatalog.revision(withCredentials)

  private fun toolNames(features: Features) =
    EvaCatalog.descriptor(features).getValue("capabilities").jsonArray.map {
      it.jsonObject.getValue("tool").jsonObject.getValue("name").jsonPrimitive.content
    }

  private fun reasonOf(admission: Admission): String {
    val reply = Json.parseToJsonElement(assertIs<Admission.Rejected>(admission).reply).jsonObject
    assertEquals("not_executed", reply.getValue("status").jsonPrimitive.content)
    return reply.getValue("reasonCode").jsonPrimitive.content
  }

  private fun search(args: String) =
    assertIs<Call.Search>(
        assertIs<Admission.Accepted>(EvaCatalog.admit(plainRevision, EvaCatalog.SEARCH, args)).call
      )
      .request

  @Test
  fun credentialToolIsOnlyAdvertisedToEvaThatStripsSecrets() {
    assertEquals(listOf(EvaCatalog.SEARCH), toolNames(plain))
    assertEquals(listOf(EvaCatalog.SEARCH, EvaCatalog.GET_CREDENTIAL), toolNames(secrets))
    assertNotEquals(secretsRevision, plainRevision)
    assertEquals(secretsRevision, EvaCatalog.revision(Features.of(setOf("secrets"))))
  }

  @Test
  fun passphraseIsDeclaredOnlyToEvaThatStoresCredentials() {
    assertNull(EvaCatalog.descriptor(plain)["credentials"])
    assertNull(EvaCatalog.descriptor(secrets)["credentials"])
    assertEquals(plain, Features.of(setOf("credentials")))
    val declared = EvaCatalog.descriptor(withCredentials).getValue("credentials").jsonArray.single()
    assertEquals("passphrase", declared.jsonObject.getValue("name").jsonPrimitive.content)
    assertEquals("password", declared.jsonObject.getValue("kind").jsonPrimitive.content)
    assertEquals(3, setOf(plainRevision, secretsRevision, credentialsRevision).size)
  }

  @Test
  fun credentialsAreStrippedBeforeValidationAndNeverEchoed() {
    val secret = "S3cret-pass"
    val call =
      assertIs<Call.Credential>(
        assertIs<Admission.Accepted>(
            EvaCatalog.admit(
              credentialsRevision,
              EvaCatalog.GET_CREDENTIAL,
              """{"path":"github.com/alice","_credentials":{"passphrase":"$secret"}}""",
            )
          )
          .call
      )
    assertEquals("github.com/alice", call.path)
    assertEquals(secret, call.passphrase?.chars?.concatToString())
    assertFalse(secret in call.toString())
    assertIs<Admission.Accepted>(
      EvaCatalog.admit(
        credentialsRevision,
        EvaCatalog.SEARCH,
        """{"query":"git","_credentials":{"passphrase":"$secret"}}""",
      )
    )
    listOf(
        EvaCatalog.GET_CREDENTIAL to
          """{"path":"a","extra":1,"_credentials":{"passphrase":"$secret"}}""",
        EvaCatalog.GET_CREDENTIAL to """{"_credentials":{"passphrase":"$secret"}}""",
        EvaCatalog.GET_CREDENTIAL to """{"path":"a","_credentials":"$secret"}""",
        EvaCatalog.GET_CREDENTIAL to """{"path":"a","_credentials":{"passphrase":["$secret"]}}""",
        EvaCatalog.SEARCH to """{"limit":0,"_credentials":{"passphrase":"$secret"}}""",
      )
      .forEach { (tool, args) ->
        val rejected =
          assertIs<Admission.Rejected>(EvaCatalog.admit(credentialsRevision, tool, args))
        assertFalse(secret in rejected.reply, args)
      }
  }

  @Test
  fun describeRequestFeatures() {
    fun parse(json: String) = assertNotNull(EvaProtocol.parseDescribeRequest(json))
    val modern =
      parse("""{"protocolVersion":1,"supportedProtocolVersions":[1],"features":["secrets"]}""")
    assertTrue(modern.supportsV1)
    assertEquals(setOf("secrets"), modern.features)
    val legacy = parse("""{"protocolVersion":1,"supportedProtocolVersions":[1]}""")
    assertTrue(legacy.supportsV1 && legacy.features.isEmpty())
    assertFalse(parse("""{"protocolVersion":2,"supportedProtocolVersions":[2]}""").supportsV1)
    assertNull(EvaProtocol.parseDescribeRequest("[1]"))
  }

  @Test
  fun credentialCallNeedsTheSecretsDescriptor() {
    val args = """{"path":"github.com/alice"}"""
    assertEquals(
      "invalid_arguments",
      reasonOf(EvaCatalog.admit(plainRevision, EvaCatalog.GET_CREDENTIAL, args)),
    )
    val call =
      assertIs<Admission.Accepted>(
        EvaCatalog.admit(secretsRevision, EvaCatalog.GET_CREDENTIAL, args)
      )
    assertEquals(Call.Credential("github.com/alice"), call.call)
    assertEquals(
      Call.Credential("a", fields = listOf("number", "zip code")),
      assertIs<Admission.Accepted>(
          EvaCatalog.admit(
            secretsRevision,
            EvaCatalog.GET_CREDENTIAL,
            """{"path":"a","fields":[" number ","zip code"]}""",
          )
        )
        .call,
    )
  }

  @Test
  fun unknownRevisionIsStale() {
    assertEquals("stale_descriptor", reasonOf(EvaCatalog.admit("v1-old", EvaCatalog.SEARCH, "{}")))
  }

  @Test
  fun searchArgumentsAndDefaults() {
    assertEquals(EvaStoreSearch.Request(null, 0, EvaStoreSearch.DEFAULT_LIMIT), search("{}"))
    assertEquals(EvaStoreSearch.Request(null, 0, 50), search("""{"query":"   "}"""))
    assertEquals(
      EvaStoreSearch.Request("git hub", 10, 200),
      search("""{"query":" git hub ","offset":10,"limit":200}"""),
    )
  }

  @Test
  fun malformedArgumentsAreRejectedBeforeExecution() {
    listOf(
        """{"limit":0}""",
        """{"limit":201}""",
        """{"offset":-1}""",
        """{"limit":"5"}""",
        """{"limit":5.5}""",
        """{"query":1}""",
        """{"query":"${"a".repeat(EvaStoreSearch.MAX_QUERY + 1)}"}""",
        """{"query":"a","query":"b"}""",
        """{"other":true}""",
        """{"query":"a"} trailing""",
        "[]",
        "{\"query\":\"\uD800\"}",
      )
      .forEach {
        assertEquals(
          "invalid_arguments",
          reasonOf(EvaCatalog.admit(plainRevision, EvaCatalog.SEARCH, it)),
          it,
        )
      }
    listOf(
        "{}",
        """{"path":""}""",
        """{"path":"a","extra":1}""",
        """{"path":"a","fields":"number"}""",
        """{"path":"a","fields":[1]}""",
        """{"path":"a","fields":[" "]}""",
        """{"path":"a","fields":["${"n".repeat(EvaCredential.MAX_FIELD_NAME + 1)}"]}""",
        """{"path":"a","fields":["a","b","c","d","e","f","g"]}""",
      )
      .forEach {
        assertEquals(
          "invalid_arguments",
          reasonOf(EvaCatalog.admit(secretsRevision, EvaCatalog.GET_CREDENTIAL, it)),
          it,
        )
      }
  }
}
