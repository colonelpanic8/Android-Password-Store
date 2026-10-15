/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.eva

import app.passwordstore.data.passfile.PasswordEntry
import app.passwordstore.eva.EvaProtocol.Secret
import app.passwordstore.eva.EvaProtocol.Status
import java.io.File
import java.util.Locale
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Builds the `get_credential` reply. Field values other than the username and URL never leave this
 * object; the password and one-time code go only into `secrets`.
 */
object EvaCredential {
  private val URL_KEYS = listOf("url", "uri", "website", "site", "link")
  private const val MAX_FIELD_NAME = 64

  data class Username(val value: String, val source: String)

  /** Resolves a path argument to a `.gpg` file inside [root], or null if it names none. */
  fun resolve(root: File, path: String): File? {
    val relative = path.trim().trim('/').removeSuffix(".gpg")
    val segments = relative.split('/')
    if (relative.isEmpty() || segments.any { it.isEmpty() || it == "." || it == ".." }) return null
    val file = File(root, "$relative.gpg")
    val canonicalRoot = root.canonicalFile
    val inside = file.canonicalFile.toPath().startsWith(canonicalRoot.toPath())
    return file.takeIf { inside && it.isFile }
  }

  /**
   * The app's autofill order: a username line in the entry, then the directory-structure setting
   * applied to the path, then the default autofill username.
   */
  fun username(entry: PasswordEntry, fromPath: String?, default: String?): Username? =
    entry.username?.let { Username(String(it), "entry") }
      ?: fromPath?.takeIf { it.isNotBlank() }?.let { Username(it, "path") }
      ?: default?.takeIf { it.isNotBlank() }?.let { Username(it, "default") }

  fun reply(path: String, entry: PasswordEntry, username: Username?, isPasskey: Boolean): String {
    val password = entry.password?.let(::String)?.takeIf { it.isNotBlank() && !isPasskey }
    val fitting = password?.takeIf {
      it.codePointCount(0, it.length) <= EvaProtocol.SECRET_VALUE_CODE_POINTS
    }
    val passwordFits = fitting != null
    val otp = if (entry.hasTotp()) entry.currentOtp else null
    val fields = entry.extraContent.keys.filter { it != PasswordEntry.EXTRA_CONTENT }
    val urlKey = fields.firstOrNull { it.lowercase(Locale.ROOT) in URL_KEYS }
    val url =
      urlKey?.let { entry.extraContent[it]?.let(::String)?.trim() }?.takeIf { it.isNotEmpty() }
    val names = fields.filter { it != urlKey && it.length <= MAX_FIELD_NAME }
    val hasNotes =
      PasswordEntry.EXTRA_CONTENT in entry.extraContent || fields.any { it.length > MAX_FIELD_NAME }

    val secrets = buildMap {
      fitting?.let { put("password", Secret(it, "Password for $path")) }
      otp?.let { put("otp", Secret(it.value, "Current one-time code for $path")) }
    }
    val text = buildString {
      append("Decrypted $path.")
      append(
        when {
          isPasskey -> " It holds a passkey, not a password; no password was handed over."
          passwordFits -> " Its password is available as the secret \"password\"."
          password != null -> " Its password is longer than EVA accepts, so it was not handed over."
          else -> " It has no password."
        }
      )
      if (username == null) append(" No username is stored for it.")
      otp?.let {
        append(
          " The current one-time code (secret \"otp\") is valid for " +
            "${it.remainingTime.inWholeSeconds} more seconds; ask again for a fresh one after that."
        )
      }
    }
    val full =
      structured(
        path,
        username,
        url,
        passwordFits,
        isPasskey,
        otp?.remainingTime?.inWholeSeconds,
        names,
        hasNotes,
      )
    val reply = EvaProtocol.result(Status.COMPLETED, null, text, full, secrets)
    if (EvaProtocol.utf8Size(reply) <= EvaProtocol.RESULT_BYTES) return reply
    val lean =
      structured(
        path,
        username,
        null,
        passwordFits,
        isPasskey,
        otp?.remainingTime?.inWholeSeconds,
        emptyList(),
        hasNotes,
      )
    val leaner =
      EvaProtocol.result(
        Status.COMPLETED,
        null,
        "$text Field names and URL were left out to fit the reply.",
        lean,
        secrets,
        truncated = true,
      )
    if (EvaProtocol.utf8Size(leaner) <= EvaProtocol.RESULT_BYTES) return leaner
    return EvaProtocol.result(
      Status.NOT_EXECUTED,
      null,
      "The entry $path is too large to hand over to EVA. Open it in Password Store (EVA) instead.",
    )
  }

  private fun structured(
    path: String,
    username: Username?,
    url: String?,
    hasPassword: Boolean,
    isPasskey: Boolean,
    otpSeconds: Long?,
    fieldNames: List<String>,
    hasNotes: Boolean,
  ): JsonObject = buildJsonObject {
    put("path", path)
    put("folder", path.substringBeforeLast('/', ""))
    username?.let {
      put("username", it.value)
      put("usernameSource", it.source)
    }
    url?.let { put("url", it) }
    put("hasPassword", hasPassword)
    put("isPasskey", isPasskey)
    put("hasOtp", otpSeconds != null)
    otpSeconds?.let { put("otpValidForSeconds", it) }
    put("fieldNames", EvaProtocol.stringArray(fieldNames))
    put("hasNotes", hasNotes)
  }
}
