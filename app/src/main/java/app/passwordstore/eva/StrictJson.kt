/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.eva

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * JSON parser that rejects what the protocol forbids and kotlinx accepts: duplicate keys, invalid
 * Unicode, trailing content and payloads over a byte bound.
 */
object StrictJson {

  fun parseObject(text: String, maxBytes: Int): JsonObject? =
    try {
      ensure(EvaProtocol.validUnicode(text) && EvaProtocol.utf8Size(text) <= maxBytes)
      Parser(text).run {
        val value = value(0)
        skipSpace()
        ensure(pos == text.length)
        value as? JsonObject
      }
    } catch (_: Malformed) {
      null
    } catch (_: IndexOutOfBoundsException) {
      null
    } catch (_: NumberFormatException) {
      null
    }

  private class Malformed : Exception()

  private fun ensure(condition: Boolean) {
    if (!condition) throw Malformed()
  }

  private class Parser(private val s: String) {
    var pos = 0

    fun skipSpace() {
      while (pos < s.length && s[pos] in " \t\r\n") pos++
    }

    fun value(depth: Int): JsonElement {
      ensure(depth < 32)
      skipSpace()
      ensure(pos < s.length)
      return when (s[pos]) {
        '{' -> obj(depth)
        '[' -> array(depth)
        '"' -> JsonPrimitive(string())
        't' -> literal("true", JsonPrimitive(true))
        'f' -> literal("false", JsonPrimitive(false))
        'n' -> literal("null", JsonNull)
        else -> number()
      }
    }

    private fun obj(depth: Int): JsonObject {
      pos++
      val map = LinkedHashMap<String, JsonElement>()
      skipSpace()
      if (peek() == '}') {
        pos++
        return JsonObject(map)
      }
      while (true) {
        skipSpace()
        ensure(peek() == '"')
        val key = string()
        ensure(key !in map)
        skipSpace()
        expect(':')
        map[key] = value(depth + 1)
        skipSpace()
        when (s.getOrNull(pos++)) {
          ',' -> continue
          '}' -> return JsonObject(map)
          else -> throw Malformed()
        }
      }
    }

    private fun array(depth: Int): JsonArray {
      pos++
      val items = mutableListOf<JsonElement>()
      skipSpace()
      if (peek() == ']') {
        pos++
        return JsonArray(items)
      }
      while (true) {
        items += value(depth + 1)
        skipSpace()
        when (s.getOrNull(pos++)) {
          ',' -> continue
          ']' -> return JsonArray(items)
          else -> throw Malformed()
        }
      }
    }

    private fun string(): String {
      expect('"')
      val out = StringBuilder()
      while (true) {
        val c = s[pos++]
        when {
          c == '"' -> break
          c == '\\' -> {
            when (val e = s[pos++]) {
              '"',
              '\\',
              '/' -> out.append(e)
              'b' -> out.append('\b')
              'f' -> out.append('\u000C')
              'n' -> out.append('\n')
              'r' -> out.append('\r')
              't' -> out.append('\t')
              'u' -> {
                out.append(s.substring(pos, pos + 4).toInt(16).toChar())
                pos += 4
              }
              else -> throw Malformed()
            }
          }
          c < ' ' -> throw Malformed()
          else -> out.append(c)
        }
      }
      val text = out.toString()
      ensure(EvaProtocol.validUnicode(text))
      return text
    }

    private fun number(): JsonPrimitive {
      val match = NUMBER.matchAt(s, pos) ?: throw Malformed()
      pos += match.value.length
      val literal = match.value
      val integral = literal.none { it in ".eE" }
      return if (integral) JsonPrimitive(literal.toBigInteger())
      else JsonPrimitive(literal.toDouble())
    }

    private fun literal(word: String, value: JsonElement): JsonElement {
      ensure(s.startsWith(word, pos))
      pos += word.length
      return value
    }

    private fun peek() = s.getOrNull(pos)

    private fun expect(c: Char) {
      ensure(s.getOrNull(pos) == c)
      pos++
    }
  }

  private val NUMBER = Regex("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?")
}
