/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.eva

import app.passwordstore.ui.crypto.BasePGPActivity
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.extensions.wipe
import javax.inject.Inject
import kotlinx.coroutines.withContext

/** Read access to passphrases the app itself keeps in memory until screen-off. */
interface EvaPassphraseCache {
  /** False when the device has no hardware-backed keystore, so the app never keeps any. */
  fun available(): Boolean

  /** Decrypted passphrases kept for [ids]; the caller wipes them. */
  suspend fun passphrases(ids: Set<String>): Map<String, CharArray>
}

class AppPassphraseCache @Inject constructor(private val dispatchers: DispatcherProvider) :
  EvaPassphraseCache {

  override fun available() = AESEncryption.isHardwareBacked()

  override suspend fun passphrases(ids: Set<String>): Map<String, CharArray> {
    // The screen-off receiver wipes the cached arrays in place on the main thread.
    val encrypted =
      withContext(dispatchers.main()) {
        BasePGPActivity.cachedPassphrases.filterKeys { it in ids }.mapValues { it.value.copyOf() }
      }
    return encrypted.mapValues { (_, value) ->
      (AESEncryption.decrypt(value) ?: charArrayOf()).also { value.wipe() }
    }
  }
}
