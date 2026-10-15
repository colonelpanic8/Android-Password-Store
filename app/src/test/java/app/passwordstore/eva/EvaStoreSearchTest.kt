/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.eva

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class EvaStoreSearchTest {

  private fun reply(matches: List<String>, request: EvaStoreSearch.Request) =
    Json.parseToJsonElement(EvaStoreSearch.reply(matches, request)).jsonObject

  @Test
  fun listsEntriesWithoutGitOrHiddenFiles() {
    val root = Files.createTempDirectory("store").toFile()
    try {
      listOf(
          "github.com/alice.gpg",
          "work/mail.gpg",
          ".git/objects/x.gpg",
          ".hidden/secret.gpg",
          ".gpg-id",
          "notes.txt",
        )
        .forEach { File(root, it).apply { parentFile?.mkdirs() }.writeText("x") }
      assertEquals(listOf("github.com/alice", "work/mail"), EvaStoreSearch.listEntries(root, false))
      assertEquals(
        listOf(".hidden/secret", "github.com/alice", "work/mail"),
        EvaStoreSearch.listEntries(root, true),
      )
    } finally {
      root.deleteRecursively()
    }
  }

  @Test
  fun everyTermMustMatchAndExactSegmentsRankFirst() {
    val paths = listOf("archive/old-github", "github.com/alice", "github.com/bob", "work/GitHub")
    assertEquals(paths, EvaStoreSearch.match(paths, null))
    assertEquals(
      listOf("work/GitHub", "github.com/alice", "github.com/bob", "archive/old-github"),
      EvaStoreSearch.match(paths, "github"),
    )
    assertEquals(listOf("github.com/bob"), EvaStoreSearch.match(paths, "BOB git"))
    assertEquals(emptyList(), EvaStoreSearch.match(paths, "carol"))
  }

  @Test
  fun pagesReportTruncationAndNextOffset() {
    val matches = (1..5).map { "site$it" }
    val first = reply(matches, EvaStoreSearch.Request(null, 0, 2))
    val data = first.getValue("structuredContent").jsonObject
    assertTrue(first.getValue("truncated").jsonPrimitive.boolean)
    assertEquals(
      listOf("site1", "site2"),
      data.getValue("entries").jsonArray.map {
        it.jsonObject.getValue("path").jsonPrimitive.content
      },
    )
    assertEquals(5, data.getValue("totalMatches").jsonPrimitive.int)
    assertEquals(2, data.getValue("nextOffset").jsonPrimitive.int)

    val last = reply(matches, EvaStoreSearch.Request(null, 4, 2))
    assertFalse(last.getValue("truncated").jsonPrimitive.boolean)
    assertFalse("nextOffset" in last.getValue("structuredContent").jsonObject)
  }

  @Test
  fun oversizedPagesDropWholeEntriesToFit() {
    val matches = (1..EvaStoreSearch.MAX_LIMIT).map { "folder/${"x".repeat(200)}$it" }
    val raw =
      EvaStoreSearch.reply(matches, EvaStoreSearch.Request(null, 0, EvaStoreSearch.MAX_LIMIT))
    assertTrue(EvaProtocol.utf8Size(raw) <= EvaProtocol.RESULT_BYTES)
    val data = Json.parseToJsonElement(raw).jsonObject.getValue("structuredContent").jsonObject
    val returned = data.getValue("entries").jsonArray
    assertTrue(returned.size in 1 until matches.size)
    assertTrue(data.getValue("truncated").jsonPrimitive.boolean)
    assertEquals(returned.size, data.getValue("nextOffset").jsonPrimitive.int)
    assertEquals(
      matches.first(),
      returned.first().jsonObject.getValue("path").jsonPrimitive.content,
    )
  }
}
