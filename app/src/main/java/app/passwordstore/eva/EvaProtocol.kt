/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.eva

import java.security.MessageDigest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Wire shapes of EVA's installed-app AIDL protocol v1, plus the `secrets`, `credentials` and
 * `credential-check` extensions.
 */
object EvaProtocol {
  const val VERSION = 1
  const val RESULT_BYTES = 16_384
  const val DESCRIBE_BYTES = 65_536
  const val ARGUMENT_BYTES = 16_384
  const val FEATURE_SECRETS = "secrets"
  const val FEATURE_CREDENTIALS = "credentials"
  const val FEATURE_CREDENTIAL_CHECK = "credential-check"
  const val MAX_SECRETS = 8
  const val SECRET_VALUE_CODE_POINTS = 4096
  const val SECRET_LABEL_CODE_POINTS = 120
  private const val TEXT_CODE_POINTS = 4000
  private val SECRET_NAME = Regex("[a-z][a-z0-9_]{0,31}")

  enum class Status(val wire: String) {
    COMPLETED("completed"),
    NOT_EXECUTED("not_executed"),
    FAILED("failed"),
  }

  enum class Reason(val wire: String) {
    STALE_DESCRIPTOR("stale_descriptor"),
    NOT_CONFIGURED("not_configured"),
    BUSY("busy"),
    INVALID_ARGUMENTS("invalid_arguments"),
    UNAUTHORIZED_CALLER("unauthorized_caller"),
    DEADLINE_EXCEEDED("deadline_exceeded"),
  }

  /** A value EVA withholds from the model; [toString] never reveals it. */
  class Secret(val value: String, label: String) {
    val label: String = truncate(label, SECRET_LABEL_CODE_POINTS).first

    init {
      require(
        value.isNotEmpty() && value.codePointCount(0, value.length) <= SECRET_VALUE_CODE_POINTS
      ) {
        "Secret values hold 1 to $SECRET_VALUE_CODE_POINTS code points"
      }
      require(validUnicode(value)) { "Secret values must be valid Unicode" }
    }

    override fun toString() = "Secret(label=$label)"
  }

  data class DescribeRequest(val supportsV1: Boolean, val features: Set<String>)

  /** Returns null when [json] is not a describe request object. Unknown fields are tolerated. */
  fun parseDescribeRequest(json: String): DescribeRequest? {
    val root = StrictJson.parseObject(json, DESCRIBE_BYTES) ?: return null
    val versions =
      (root["supportedProtocolVersions"] as? JsonArray)?.mapNotNull {
        (it as? JsonPrimitive)?.takeIf { p -> !p.isString }?.content?.toIntOrNull()
      } ?: listOfNotNull((root["protocolVersion"] as? JsonPrimitive)?.content?.toIntOrNull())
    val features =
      (root["features"] as? JsonArray)
        ?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
        ?.toSet() ?: emptySet()
    return DescribeRequest(VERSION in versions, features)
  }

  fun result(
    status: Status,
    reason: Reason?,
    text: String,
    structured: JsonObject? = null,
    secrets: Map<String, Secret> = emptyMap(),
    truncated: Boolean = false,
    rejectedCredentials: Set<String> = emptySet(),
  ): String {
    require(status != Status.COMPLETED || reason == null) { "Completed replies carry no reason" }
    require(secrets.isEmpty() || status == Status.COMPLETED) {
      "Only completed replies carry secrets"
    }
    require(secrets.size <= MAX_SECRETS && secrets.keys.all(SECRET_NAME::matches)) {
      "At most $MAX_SECRETS secrets with lowercase names"
    }
    require(rejectedCredentials.isEmpty() || status != Status.COMPLETED) {
      "Only unsuccessful replies reject credentials"
    }
    val (bounded, cut) = truncate(text, TEXT_CODE_POINTS)
    return buildJsonObject {
      put("protocolVersion", VERSION)
      put("status", status.wire)
      put("reasonCode", reason?.wire?.let(::JsonPrimitive) ?: JsonNull)
      put("truncated", truncated || cut)
      put("content", content(bounded))
      structured?.let { put("structuredContent", it) }
      if (rejectedCredentials.isNotEmpty())
        put("rejectedCredentials", stringArray(rejectedCredentials))
      if (secrets.isNotEmpty())
        put(
          "secrets",
          buildJsonObject {
            secrets.forEach { (name, secret) ->
              put(
                name,
                buildJsonObject {
                  put("value", secret.value)
                  put("label", secret.label)
                },
              )
            }
          },
        )
    }
      .toString()
  }

  fun rejection(reason: Reason, text: String, rejectedCredentials: Set<String> = emptySet()) =
    result(Status.NOT_EXECUTED, reason, text, rejectedCredentials = rejectedCredentials)

  /** The reply to EVA's `eva.check_credential`: a verdict on the one credential it sent. */
  fun verdict(accepted: Boolean, text: String) =
    result(
      Status.COMPLETED,
      null,
      text,
      buildJsonObject { put("verdict", if (accepted) "accepted" else "rejected") },
    )

  fun describeReply(descriptor: JsonObject): String = buildJsonObject {
    put("protocolVersion", VERSION)
    put("status", Status.COMPLETED.wire)
    put("reasonCode", JsonNull)
    put("truncated", false)
    put("content", JsonArray(emptyList()))
    put("descriptor", descriptor)
  }
    .toString()

  fun describeFailure(reason: Reason, text: String): String = buildJsonObject {
    put("protocolVersion", VERSION)
    put("status", Status.NOT_EXECUTED.wire)
    put("reasonCode", reason.wire)
    put("truncated", false)
    put("content", content(text))
    put("descriptor", JsonNull)
  }
    .toString()

  fun utf8Size(text: String) = text.toByteArray(Charsets.UTF_8).size

  fun sha256Hex(text: String): String =
    MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)).joinToString("") {
      "%02x".format(it)
    }

  fun validUnicode(text: String): Boolean {
    var i = 0
    while (i < text.length) {
      val c = text[i]
      if (Character.isHighSurrogate(c)) {
        if (i + 1 >= text.length || !Character.isLowSurrogate(text[i + 1])) return false
        i += 2
      } else if (Character.isLowSurrogate(c)) return false else i++
    }
    return true
  }

  /** Cuts [text] to [max] code points; the flag reports whether anything was removed. */
  fun truncate(text: String, max: Int): Pair<String, Boolean> {
    if (text.codePointCount(0, text.length) <= max) return text to false
    return text.substring(0, text.offsetByCodePoints(0, max - 1)) + "…" to true
  }

  private fun content(text: String): JsonArray = buildJsonArray {
    add(
      buildJsonObject {
        put("type", "text")
        put("text", text)
      }
    )
  }

  fun stringArray(values: Iterable<String>): JsonElement = JsonArray(values.map(::JsonPrimitive))
}
