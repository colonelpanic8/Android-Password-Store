/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.eva

import app.passwordstore.eva.EvaCatalog.Admission
import app.passwordstore.eva.EvaCatalog.Call
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

  private val secretsRevision = EvaCatalog.revision(true)
  private val plainRevision = EvaCatalog.revision(false)

  private fun toolNames(secrets: Boolean) =
    EvaCatalog.descriptor(secrets).getValue("capabilities").jsonArray.map {
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
    assertEquals(listOf(EvaCatalog.SEARCH), toolNames(secrets = false))
    assertEquals(listOf(EvaCatalog.SEARCH, EvaCatalog.GET_CREDENTIAL), toolNames(secrets = true))
    assertNotEquals(secretsRevision, plainRevision)
    assertEquals(secretsRevision, EvaCatalog.revision(true))
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
    listOf("{}", """{"path":""}""", """{"path":"a","extra":1}""").forEach {
      assertEquals(
        "invalid_arguments",
        reasonOf(EvaCatalog.admit(secretsRevision, EvaCatalog.GET_CREDENTIAL, it)),
        it,
      )
    }
  }
}
