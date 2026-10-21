/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.eva

import app.passwordstore.eva.EvaProtocol.Reason
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/** The descriptor this app advertises and validation of calls against it. */
object EvaCatalog {
  const val SEARCH = "search_entries"
  const val GET_CREDENTIAL = "get_credential"
  private const val TITLE = "Password Store (EVA)"
  private const val SCOPE_REVISION = "local-store.1"
  private const val MAX_PATH = 1024
  /** Reserved argument through which EVA passes the user's saved credentials. */
  private const val CREDENTIALS_KEY = "_credentials"
  const val PASSPHRASE = "passphrase"
  /** EVA's reserved request to check one declared credential; tool names never contain a dot. */
  const val CHECK_CREDENTIAL = "eva.check_credential"

  /**
   * What the describing EVA understands; each combination is its own descriptor revision, so an
   * execute call's expected revision says which features its EVA speaks.
   */
  data class Features(
    val secrets: Boolean,
    val credentials: Boolean,
    val credentialCheck: Boolean = false,
  ) {
    companion object {
      val ALL =
        listOf(
          Features(false, false),
          Features(true, false),
          Features(true, true),
          Features(true, true, true),
        )

      /** Only get_credential uses the passphrase, so credentials are declared only with secrets. */
      fun of(names: Set<String>): Features {
        val secrets = EvaProtocol.FEATURE_SECRETS in names
        val credentials = secrets && EvaProtocol.FEATURE_CREDENTIALS in names
        return Features(
          secrets,
          credentials,
          credentials && EvaProtocol.FEATURE_CREDENTIAL_CHECK in names,
        )
      }
    }
  }

  /** EVA's saved passphrase for one call; [toString] never reveals it. */
  class Passphrase(val chars: CharArray) {
    fun wipe() = chars.fill('\u0000')

    override fun toString() = "Passphrase(redacted)"
  }

  sealed interface Call {
    data class Search(val request: EvaStoreSearch.Request) : Call

    /**
     * With [reportsRejection], a wrong [passphrase] is named in the reply's rejectedCredentials.
     */
    data class Credential(
      val path: String,
      val passphrase: Passphrase? = null,
      val reportsRejection: Boolean = false,
    ) : Call

    /** EVA asks whether [passphrase] unlocks the store's key; nothing is decrypted. */
    data class CheckPassphrase(val passphrase: Passphrase) : Call
  }

  sealed interface Admission {
    data class Accepted(val call: Call) : Admission

    data class Rejected(val reply: String) : Admission
  }

  fun revision(features: Features): String =
    "v1-" + EvaProtocol.sha256Hex(body(features).toString()).take(24)

  fun descriptor(features: Features): JsonObject = buildJsonObject {
    put("protocolVersion", EvaProtocol.VERSION)
    put("descriptorRevision", revision(features))
    body(features).forEach { (key, value) -> put(key, value) }
  }

  /**
   * Validates a call. `_credentials` is removed before the arguments are checked and never appears
   * in a reply; only a get_credential call or a check keeps the passphrase.
   */
  fun admit(expectedRevision: String, capability: String, argumentsJson: String): Admission {
    val features =
      Features.ALL.firstOrNull { revision(it) == expectedRevision }
        ?: return reject(
          Reason.STALE_DESCRIPTOR,
          "Password Store (EVA) changed its actions since EVA last read them. Nothing was done.",
        )
    val parsed =
      StrictJson.parseObject(argumentsJson, EvaProtocol.ARGUMENT_BYTES)
        ?: return invalid("Arguments must be one JSON object within 16 KiB.")
    val credentials =
      when (val value = parsed[CREDENTIALS_KEY]) {
        null -> emptyMap()
        is JsonObject ->
          value.mapValues { (_, secret) ->
            string(secret) ?: return invalid("Every $CREDENTIALS_KEY value must be a string.")
          }
        else -> return invalid("$CREDENTIALS_KEY must be an object.")
      }
    val args = JsonObject(parsed - CREDENTIALS_KEY)
    return when {
      capability == SEARCH -> search(args)
      capability == GET_CREDENTIAL && features.secrets ->
        credential(
          args,
          credentials[PASSPHRASE]?.takeIf { it.isNotEmpty() },
          features.credentialCheck,
        )
      capability == CHECK_CREDENTIAL && features.credentialCheck -> check(args, credentials)
      else -> invalid("Password Store (EVA) has no action named \"$capability\".")
    }
  }

  private fun search(args: JsonObject): Admission {
    unknownKey(args, setOf("query", "offset", "limit"))?.let {
      return invalid("Unknown argument \"$it\".")
    }
    val query =
      when (val value = args["query"]) {
        null -> null
        else ->
          string(value)?.trim()?.takeIf {
            it.codePointCount(0, it.length) <= EvaStoreSearch.MAX_QUERY
          }
            ?: return invalid(
              "query must be a string of at most ${EvaStoreSearch.MAX_QUERY} characters."
            )
      }
    val offset =
      integer(args["offset"], 0, 0, EvaStoreSearch.MAX_OFFSET)
        ?: return invalid("offset must be an integer from 0 to ${EvaStoreSearch.MAX_OFFSET}.")
    val limit =
      integer(args["limit"], EvaStoreSearch.DEFAULT_LIMIT, 1, EvaStoreSearch.MAX_LIMIT)
        ?: return invalid("limit must be an integer from 1 to ${EvaStoreSearch.MAX_LIMIT}.")
    return Admission.Accepted(
      Call.Search(EvaStoreSearch.Request(query?.ifEmpty { null }, offset, limit))
    )
  }

  private fun check(args: JsonObject, credentials: Map<String, String>): Admission {
    val passphrase = credentials[PASSPHRASE]
    if (args.isNotEmpty() || credentials.size != 1 || passphrase.isNullOrEmpty())
      return invalid("A credential check carries only the $PASSPHRASE credential.")
    return Admission.Accepted(Call.CheckPassphrase(Passphrase(passphrase.toCharArray())))
  }

  private fun credential(
    args: JsonObject,
    passphrase: String?,
    reportsRejection: Boolean,
  ): Admission {
    unknownKey(args, setOf("path"))?.let {
      return invalid("Unknown argument \"$it\".")
    }
    val path =
      args["path"]?.let(::string)?.trim()?.takeIf {
        it.isNotEmpty() && it.codePointCount(0, it.length) <= MAX_PATH
      } ?: return invalid("path is required: an entry path returned by search_entries.")
    return Admission.Accepted(
      Call.Credential(path, passphrase?.let { Passphrase(it.toCharArray()) }, reportsRejection)
    )
  }

  private fun unknownKey(args: JsonObject, allowed: Set<String>) =
    args.keys.firstOrNull {
      it !in allowed
    }

  private fun string(value: JsonElement) =
    (value as? JsonPrimitive)?.takeIf { it.isString }?.content

  private fun integer(value: JsonElement?, default: Int, min: Int, max: Int): Int? {
    if (value == null) return default
    val number = (value as? JsonPrimitive)?.takeIf { !it.isString }?.content?.toLongOrNull()
    return number?.takeIf { it in min..max }?.toInt()
  }

  private fun invalid(text: String) = reject(Reason.INVALID_ARGUMENTS, "$text Nothing was done.")

  private fun reject(reason: Reason, text: String) =
    Admission.Rejected(EvaProtocol.rejection(reason, text))

  private fun body(features: Features): JsonObject = buildJsonObject {
    put("authorizationScopeRevision", SCOPE_REVISION)
    put("title", TITLE)
    putJsonArray("capabilities") {
      add(searchCapability(features.secrets))
      if (features.secrets) add(credentialCapability())
    }
    if (features.credentials)
      putJsonArray("credentials") {
        add(
          buildJsonObject {
            put("name", PASSPHRASE)
            put("title", "PGP key passphrase")
            put(
              "description",
              "Unlocks the password store's private PGP key, so EVA can fill passwords from " +
                "Password Store (EVA) even while the phone is locked. EVA keeps it encrypted on " +
                "this device and passes it only to Password Store (EVA) for each lookup.",
            )
            put("kind", "password")
            if (features.credentialCheck) put("checkable", true)
          }
        )
      }
  }

  private fun searchCapability(secrets: Boolean) =
    capability(
      name = SEARCH,
      title = "Search password entries",
      description =
        "Search the user's pass-compatible password store by entry path (folder and file names, " +
          "for example \"github.com/alice\") without decrypting anything. Every " +
          "whitespace-separated word of query must appear in the path, ignoring case; omit query " +
          "to list all entries. Results are paged: when truncated is true, call again with " +
          "offset set to nextOffset. " +
          if (secrets) "Pass a returned path to get_credential to sign in."
          else "Returns entry paths only.",
      waitMillis = 15_000,
      input = {
        putJsonObject("query") {
          put("type", "string")
          put("maxLength", EvaStoreSearch.MAX_QUERY)
          put("description", "Words to find in entry paths, such as a site or account name.")
        }
        putJsonObject("offset") {
          put("type", "integer")
          put("minimum", 0)
          put("maximum", EvaStoreSearch.MAX_OFFSET)
          put("description", "Number of matches to skip; defaults to 0.")
        }
        putJsonObject("limit") {
          put("type", "integer")
          put("minimum", 1)
          put("maximum", EvaStoreSearch.MAX_LIMIT)
          put("description", "Most matches to return; defaults to ${EvaStoreSearch.DEFAULT_LIMIT}.")
        }
      },
      required = emptyList(),
      output =
        outputObject(
          listOf("entries", "totalMatches", "offset", "truncated"),
          "query" to scalar("string"),
          "entries" to
            buildJsonObject {
              put("type", "array")
              put(
                "items",
                outputObject(
                  listOf("path", "folder"),
                  "path" to scalar("string", "Entry path without the .gpg extension."),
                  "folder" to
                    scalar("string", "Folder holding the entry; empty at the store root."),
                ),
              )
            },
          "totalMatches" to scalar("integer"),
          "offset" to scalar("integer"),
          "truncated" to scalar("boolean", "Whether more matches follow this page."),
          "nextOffset" to scalar("integer", "offset for the next page, present when truncated."),
        ),
    )

  private fun credentialCapability() =
    capability(
      name = GET_CREDENTIAL,
      title = "Get a login from Password Store",
      description =
        "Decrypt one password store entry, given its path from search_entries. Returns the " +
          "username (from the entry, else derived from its path by the app's directory-structure " +
          "setting), the URL if stored, whether it has a one-time code, and the names of its " +
          "other fields. The password and the current one-time code are returned only as secrets: " +
          "you receive handles you can type into a field, never the values. While the key " +
          "is locked this fails with not_configured; the user must unlock any entry in Password " +
          "Store (EVA) with \"Keep passphrase until screen-off\" checked, then ask again.",
      waitMillis = 20_000,
      input = {
        putJsonObject("path") {
          put("type", "string")
          put("minLength", 1)
          put("maxLength", MAX_PATH)
          put("description", "Entry path exactly as search_entries returned it.")
        }
      },
      required = listOf("path"),
      output =
        outputObject(
          listOf("path", "folder", "hasPassword", "isPasskey", "hasOtp", "fieldNames", "hasNotes"),
          "path" to scalar("string"),
          "folder" to scalar("string"),
          "username" to scalar("string"),
          "usernameSource" to
            scalar(
              "string",
              "entry: a username line; path: the entry path; default: the app setting.",
            ),
          "url" to scalar("string"),
          "hasPassword" to scalar("boolean", "Whether the secret \"password\" was returned."),
          "isPasskey" to scalar("boolean", "The entry stores a passkey rather than a password."),
          "hasOtp" to scalar("boolean", "Whether the secret \"otp\" was returned."),
          "otpValidForSeconds" to scalar("integer"),
          "fieldNames" to
            buildJsonObject {
              put("type", "array")
              put("items", scalar("string"))
              put("description", "Names of other fields; their values are not returned.")
            },
          "hasNotes" to scalar("boolean", "The entry has free-form notes, which are not returned."),
        ),
    )

  private fun capability(
    name: String,
    title: String,
    description: String,
    waitMillis: Int,
    input: JsonObjectBuilder.() -> Unit,
    required: List<String>,
    output: JsonObject,
  ) = buildJsonObject {
    putJsonObject("tool") {
      put("name", name)
      put("title", title)
      put("description", description)
      putJsonObject("inputSchema") {
        put("type", "object")
        putJsonObject("properties", input)
        put("required", EvaProtocol.stringArray(required))
        put("additionalProperties", false)
      }
      put("outputSchema", output)
      putJsonObject("annotations") {
        put("readOnlyHint", true)
        put("openWorldHint", false)
      }
    }
    put("effects", "read")
    putJsonObject("execution") {
      put("mode", "synchronous")
      put("requiresForeground", false)
      put("maxWaitMillis", waitMillis)
    }
    putJsonObject("result") { put("maxBytes", EvaProtocol.RESULT_BYTES) }
  }

  private fun scalar(type: String, description: String? = null) = buildJsonObject {
    put("type", type)
    description?.let { put("description", it) }
  }

  private fun outputObject(required: List<String>, vararg properties: Pair<String, JsonElement>) =
    buildJsonObject {
      put("type", "object")
      putJsonObject("properties") { properties.forEach { (key, value) -> put(key, value) } }
      put("required", EvaProtocol.stringArray(required))
      put("additionalProperties", false)
    }
}
