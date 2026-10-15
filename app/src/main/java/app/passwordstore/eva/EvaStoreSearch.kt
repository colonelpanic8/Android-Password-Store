/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.eva

import app.passwordstore.eva.EvaProtocol.Status
import java.io.File
import java.util.Locale
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Path-only search over the store; nothing is decrypted. */
object EvaStoreSearch {
  const val DEFAULT_LIMIT = 50
  const val MAX_LIMIT = 200
  const val MAX_OFFSET = 1_000_000
  const val MAX_QUERY = 256

  data class Request(val query: String?, val offset: Int, val limit: Int)

  /** Entry paths relative to [root], without the `.gpg` extension, sorted. */
  fun listEntries(root: File, showHidden: Boolean): List<String> =
    root
      .walkTopDown()
      .onEnter { it == root || (it.name != ".git" && (showHidden || !it.name.startsWith("."))) }
      .filter { it.isFile && it.extension == "gpg" && (showHidden || !it.name.startsWith(".")) }
      .map { it.relativeTo(root).invariantSeparatorsPath.removeSuffix(".gpg") }
      .sorted()
      .toList()

  /**
   * Entries whose path contains every whitespace-separated term, case-insensitively. Paths with a
   * segment equal to the whole query come first, then those with a segment starting with the first
   * term.
   */
  fun match(paths: List<String>, query: String?): List<String> {
    val needle = query?.trim()?.lowercase(Locale.ROOT).orEmpty()
    if (needle.isEmpty()) return paths
    val terms = needle.split(Regex("\\s+"))
    return paths
      .map { it to it.lowercase(Locale.ROOT) }
      .filter { (_, lower) -> terms.all(lower::contains) }
      .sortedWith(
        compareBy<Pair<String, String>> { (_, lower) ->
            val segments = lower.split('/')
            when {
              needle in segments -> 0
              segments.any { it.startsWith(terms.first()) } -> 1
              else -> 2
            }
          }
          .thenBy { it.first }
      )
      .map { it.first }
  }

  fun reply(matches: List<String>, request: Request): String {
    val total = matches.size
    var page = matches.drop(request.offset).take(request.limit)
    while (true) {
      val reply = render(page, total, request)
      if (EvaProtocol.utf8Size(reply) <= EvaProtocol.RESULT_BYTES || page.isEmpty()) return reply
      page = page.dropLast(maxOf(1, page.size / 8))
    }
  }

  private fun render(page: List<String>, total: Int, request: Request): String {
    val query = request.query
    val end = request.offset + page.size
    val truncated = end < total
    val noun = if (total == 1) "entry" else "entries"
    val subject = if (query == null) noun else "$noun matching \"$query\""
    val text = buildString {
      when {
        total == 0 && query == null -> append("The password store has no entries.")
        total == 0 -> append("No entries matching \"$query\".")
        page.isEmpty() -> append("Offset ${request.offset} is past the last of $total $subject.")
        else -> append("Found $total $subject; showing ${request.offset + 1}–$end.")
      }
      if (truncated) append(" More results exist: call again with offset $end.")
    }
    val structured = buildJsonObject {
      query?.let { put("query", it) }
      put(
        "entries",
        buildJsonArray {
          page.forEach { path ->
            add(
              buildJsonObject {
                put("path", path)
                put("folder", path.substringBeforeLast('/', ""))
              }
            )
          }
        },
      )
      put("totalMatches", total)
      put("offset", request.offset)
      put("truncated", truncated)
      if (truncated) put("nextOffset", end)
    }
    return EvaProtocol.result(Status.COMPLETED, null, text, structured, truncated = truncated)
  }
}
