/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.eva

import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.errors.IncorrectPassphraseException
import app.passwordstore.crypto.errors.NoDecryptionKeyAvailableException
import app.passwordstore.data.crypto.CryptoRepository
import app.passwordstore.ui.crypto.BasePGPActivity
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.crypto.AESEncryption
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
 * Decrypts an entry without UI. Passphrase-protected keys only unlock through the app's own
 * in-memory cache ("Keep passphrase until screen-off"), which the app wipes when the screen turns
 * off; nothing is prompted for or written anywhere.
 */
class EvaDecryptor
@Inject
constructor(
  private val repository: CryptoRepository,
  private val dispatchers: DispatcherProvider,
) {

  sealed interface Outcome {
    class Decrypted(val chars: CharArray) : Outcome

    data class Unavailable(val message: String) : Outcome

    data class Failed(val message: String) : Outcome
  }

  suspend fun decrypt(file: File, root: File, cacheEnabled: Boolean): Outcome {
    val ids =
      withContext(dispatchers.io()) { identifiers(file.parentFile ?: root, root) }
        ?: return Outcome.Unavailable(
          "This entry's folder has no .gpg-id file, so Password Store (EVA) cannot tell which " +
            "key encrypts it. Open the entry in the app to choose a key."
        )
    if (ids.isEmpty())
      return Outcome.Unavailable(
        "The .gpg-id file for this entry lists no usable key IDs. Fix it in Password Store (EVA)."
      )
    if (!repository.hasKeys())
      return Outcome.Unavailable(
        "Password Store (EVA) has no PGP key. Import one in Settings → PGP settings → Key manager."
      )
    if (ids.none { repository.hasDecKey(it) })
      return Outcome.Unavailable(
        "Password Store (EVA) has no secret key for this entry (encrypted for " +
          "${ids.joinToString()}). Import it in Settings → PGP settings → Key manager."
      )

    val passphrases: Map<String, CharArray?> =
      if (!repository.isPasswordProtected(ids)) mapOf("" to null)
      else {
        val names = ids.map { it.toString() }.toSet()
        val cached =
          withContext(dispatchers.main()) {
            BasePGPActivity.cachedPassphrases
              .filterKeys { it in names }
              .mapValues { it.value.copyOf() }
          }
        if (cached.isEmpty())
          return Outcome.Unavailable(
            if (AESEncryption.isHardwareBacked()) locked(cacheEnabled) else NO_SECURE_CACHE
          )
        cached.mapValues { (_, encrypted) ->
          (AESEncryption.decrypt(encrypted) ?: charArrayOf()).also { encrypted.wipe() }
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
      errors.any { it is IncorrectPassphraseException } ->
        Outcome.Unavailable(
          "The passphrase Password Store (EVA) kept no longer unlocks this entry's key. " +
            locked(cacheEnabled)
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

  private fun locked(cacheEnabled: Boolean) =
    "Password Store (EVA) is locked: its PGP key needs the passphrase, and the app has none in " +
      "memory. Open Password Store (EVA), open any entry and unlock it" +
      (if (cacheEnabled) "" else " with \"Keep passphrase until screen-off\" checked") +
      ", then ask again. The app forgets the passphrase whenever the screen turns off."

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
    val SHORT_ID = Regex("[a-fA-F0-9]{8}")
    const val NO_SECURE_CACHE =
      "This entry's PGP key needs a passphrase, and this device has no hardware-backed " +
        "keystore, so Password Store (EVA) cannot keep one in memory for EVA. Open the entry in " +
        "Password Store (EVA) instead, or use a key without a passphrase."
  }
}
