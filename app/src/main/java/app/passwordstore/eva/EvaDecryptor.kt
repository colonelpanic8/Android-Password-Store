/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.eva

import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.errors.IncorrectPassphraseException
import app.passwordstore.crypto.errors.NoDecryptionKeyAvailableException
import app.passwordstore.data.crypto.CryptoRepository
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.extensions.substringBefore
import app.passwordstore.util.extensions.toCharArray
import app.passwordstore.util.extensions.wipe
import com.github.michaelbull.result.getError
import com.github.michaelbull.result.getOrThrow
import java.io.ByteArrayOutputStream
import java.io.File
import javax.inject.Inject
import kotlinx.coroutines.withContext

/**
 * Decrypts an entry without UI. A passphrase-protected key unlocks with the passphrase EVA supplied
 * for this call or, failing that, the app's own in-memory cache ("Keep passphrase until
 * screen-off"); nothing is prompted for or written anywhere.
 */
class EvaDecryptor
@Inject
constructor(
  private val repository: CryptoRepository,
  private val dispatchers: DispatcherProvider,
  private val cache: EvaPassphraseCache,
) {

  sealed interface Outcome {
    class Decrypted(val chars: CharArray) : Outcome

    data class Unavailable(val message: String) : Outcome

    /** EVA's passphrase does not unlock the entry's key; [message] names the key. */
    data class WrongSupplied(val message: String) : Outcome

    data class Failed(val message: String) : Outcome
  }

  /** What [check] learned about EVA's passphrase without decrypting anything. */
  sealed interface Check {
    val message: String

    data class Accepted(override val message: String) : Check

    data class Rejected(override val message: String) : Check

    data class Unavailable(override val message: String) : Check
  }

  /**
   * Whether [supplied] unlocks the secret key of the store's root `.gpg-id`, the same test
   * [decrypt] applies before it reads an entry. No entry is opened.
   */
  suspend fun check(root: File, supplied: CharArray): Check {
    val ids =
      withContext(dispatchers.io()) { identifiers(root, root) }
        ?: return Check.Unavailable(
          "The password store has no .gpg-id file at its root, so Password Store (EVA) cannot " +
            "tell which key to check the passphrase against. It is still used for each entry."
        )
    missingKey(ids)?.let {
      return Check.Unavailable(it)
    }
    if (!repository.isPasswordProtected(ids))
      return Check.Accepted(
        "The store's PGP key has no passphrase, so Password Store (EVA) does not need this one."
      )
    return if (ids.any { repository.isPasswordCorrect(it, null, supplied) })
      Check.Accepted("It unlocks the store's PGP key. Nothing was decrypted.")
    else
      Check.Rejected(
        "It does not unlock the store's PGP key (${ids.joinToString()}). Nothing was decrypted."
      )
  }

  /** [supplied] is EVA's saved passphrase; it is copied, never kept, and the caller wipes it. */
  suspend fun decrypt(file: File, root: File, supplied: CharArray?): Outcome {
    val ids =
      withContext(dispatchers.io()) { identifiers(file.parentFile ?: root, root) }
        ?: return Outcome.Unavailable(
          "This entry's folder has no .gpg-id file, so Password Store (EVA) cannot tell which " +
            "key encrypts it. Open the entry in the app to choose a key."
        )
    missingKey(ids)?.let {
      return Outcome.Unavailable(it)
    }

    val protected = repository.isPasswordProtected(ids)
    val useSupplied = protected && supplied != null
    val passphrases: Map<String, CharArray?> =
      when {
        !protected -> mapOf("" to null)
        supplied != null -> {
          if (ids.none { repository.isPasswordCorrect(it, null, supplied) })
            return wrongSupplied(ids)
          mapOf("" to supplied.copyOf())
        }
        !cache.available() -> return Outcome.Unavailable(NO_SECURE_CACHE)
        else ->
          cache.passphrases(ids.map { it.toString() }.toSet()).ifEmpty {
            return Outcome.Unavailable(LOCKED)
          }
      }

    val ciphertext = withContext(dispatchers.io()) { file.readBytes() }.inputStream()
    val plaintext = ByteArrayOutputStream()
    val results =
      try {
        withContext(dispatchers.default()) {
          repository.decrypt(passphrases, ids, ciphertext, plaintext)
        }
      } finally {
        passphrases.values.forEach { it?.wipe() }
      }
    val last = results.last().second
    if (last.isOk) {
      val bytes = last.getOrThrow().toByteArray()
      plaintext.reset()
      return Outcome.Decrypted(bytes.toCharArray().also { bytes.wipe() })
    }
    val errors = results.mapNotNull { it.second.getError() }
    return when {
      useSupplied && errors.any { it is IncorrectPassphraseException } -> wrongSupplied(ids)
      errors.any { it is IncorrectPassphraseException } ->
        Outcome.Unavailable(
          "The passphrase Password Store (EVA) kept no longer unlocks this entry's key. " + LOCKED
        )
      errors.any { it is NoDecryptionKeyAvailableException } ->
        Outcome.Unavailable(
          "None of Password Store (EVA)'s keys can decrypt this entry. Import the right secret " +
            "key in Settings → PGP settings → Key manager."
        )
      else ->
        Outcome.Failed(
          "Password Store (EVA) could not decrypt this entry " +
            "(${errors.firstOrNull()?.let { it::class.simpleName } ?: "unknown error"})."
        )
    }
  }

  private fun wrongSupplied(ids: List<PGPIdentifier>) =
    Outcome.WrongSupplied(
      "The PGP key passphrase saved in EVA does not unlock this entry's key " +
        "(${ids.joinToString()}); update it in EVA's settings for Password Store (EVA). " +
        "Nothing was decrypted."
    )

  /** Why none of [ids] has a usable secret key here, or null when one does. */
  private fun missingKey(ids: List<PGPIdentifier>): String? =
    when {
      ids.isEmpty() -> "The .gpg-id file lists no usable key IDs. Fix it in Password Store (EVA)."
      !repository.hasKeys() ->
        "Password Store (EVA) has no PGP key. Import one in Settings → PGP settings → Key manager."
      ids.none { repository.hasDecKey(it) } ->
        "Password Store (EVA) has no secret key for ${ids.joinToString()}. Import it in " +
          "Settings → PGP settings → Key manager."
      else -> null
    }

  /**
   * The app's .gpg-id lookup: nearest file from [dir] up to [root], comments and subkey marks cut.
   */
  private fun identifiers(dir: File, root: File): List<PGPIdentifier>? {
    val top = root.canonicalFile
    var current: File? = dir.canonicalFile
    while (current != null && current.toPath().startsWith(top.toPath())) {
      val gpgId = File(current, ".gpg-id")
      if (gpgId.isFile)
        return gpgId
          .readLines()
          .map { it.substringBefore(Regex("\\s*#|!")) }
          .filter { it.isNotBlank() && it != "gpg-id" }
          .filterNot { it.removePrefix("0x").matches(SHORT_ID) }
          .mapNotNull(PGPIdentifier::fromString)
      if (current == top) break
      current = current.parentFile
    }
    return null
  }

  private companion object {
    const val LOCKED =
      "Password Store (EVA) is locked: its PGP key needs the passphrase. Either save the " +
        "passphrase in EVA's settings for Password Store (EVA), which also works on a locked " +
        "phone, or open Password Store (EVA) and unlock any entry with \"Keep passphrase until " +
        "screen-off\" checked (the app forgets it when the screen turns off). Then ask again."
    val SHORT_ID = Regex("[a-fA-F0-9]{8}")
    const val NO_SECURE_CACHE =
      "This entry's PGP key needs a passphrase. Save it in EVA's settings for Password Store " +
        "(EVA), then ask again. This device has no hardware-backed keystore, so Password Store " +
        "(EVA) itself cannot keep the passphrase in memory."
  }
}
