/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.eva

import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPKey
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.crypto.PGPainlessCryptoHandler
import app.passwordstore.data.crypto.CryptoRepository
import app.passwordstore.eva.EvaDecryptor.Outcome
import app.passwordstore.util.coroutines.DispatcherProvider
import com.github.ivanshafran.sharedpreferencesmock.SPMockBuilder
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

class EvaDecryptorTest {

  private val dir = Files.createTempDirectory("eva-decrypt").toFile()
  private val root = File(dir, "store")
  private val entry = File(root, "site/login.gpg")
  private val keyId = requireNotNull(PGPIdentifier.fromString(USER_ID))
  private val repository =
    CryptoRepository(
      PGPKeyManager(File(dir, "pgp").absolutePath).apply {
        val key =
          requireNotNull(EvaDecryptorTest::class.java.getResourceAsStream("protected-test-key.asc"))
        addKey(PGPKey(key.use { it.readBytes() }))
      },
      PGPainlessCryptoHandler(),
      object : DispatcherProvider {},
      SPMockBuilder().createSharedPreferences(),
    )

  init {
    File(root, ".gpg-id").apply { parentFile?.mkdirs() }.writeText("$USER_ID\n")
    val ciphertext = ByteArrayOutputStream()
    repository.encrypt(listOf(keyId), CONTENT.byteInputStream(), ciphertext)
    entry.apply { parentFile?.mkdirs() }.writeBytes(ciphertext.toByteArray())
  }

  @AfterTest
  fun cleanUp() {
    dir.deleteRecursively()
  }

  private class FakeCache(private val available: Boolean, private val kept: String?) :
    EvaPassphraseCache {
    var reads = 0

    override fun available() = available

    override suspend fun passphrases(ids: Set<String>): Map<String, CharArray> {
      reads++
      return if (kept == null) emptyMap() else ids.associateWith { kept.toCharArray() }
    }
  }

  private fun decrypt(supplied: String?, cache: FakeCache) = runBlocking {
    EvaDecryptor(repository, object : DispatcherProvider {}, cache)
      .decrypt(entry, root, supplied = supplied?.toCharArray())
  }

  private fun decrypted(outcome: Outcome) =
    assertIs<Outcome.Decrypted>(outcome).chars.concatToString()

  @Test
  fun suppliedPassphraseTakesPrecedenceOverTheCache() {
    val cache = FakeCache(available = true, kept = "stale passphrase")
    assertEquals(CONTENT, decrypted(decrypt(PASSPHRASE, cache)))
    assertEquals(0, cache.reads)
  }

  @Test
  fun wrongSuppliedPassphraseFailsWithoutFallingBackToTheCache() {
    val cache = FakeCache(available = true, kept = PASSPHRASE)
    val outcome = assertIs<Outcome.Unavailable>(decrypt("not the passphrase", cache))
    assertTrue("passphrase saved in EVA is wrong" in outcome.message, outcome.message)
    assertEquals(0, cache.reads)
  }

  @Test
  fun withoutASuppliedPassphraseTheCacheIsUsed() {
    assertEquals(CONTENT, decrypted(decrypt(null, FakeCache(available = true, kept = PASSPHRASE))))
  }

  @Test
  fun lockedStoreNamesBothFixes() {
    val message = assertIs<Outcome.Unavailable>(decrypt(null, FakeCache(true, null))).message
    assertTrue("EVA's settings for Password Store (EVA)" in message, message)
    assertTrue("Keep passphrase until screen-off" in message, message)
    val noKeystore = assertIs<Outcome.Unavailable>(decrypt(null, FakeCache(false, null))).message
    assertTrue("EVA's settings for Password Store (EVA)" in noKeystore, noKeystore)
  }

  private companion object {
    const val USER_ID = "eva-test@example.invalid"
    const val PASSPHRASE = "correct horse battery"
    const val CONTENT = "pw-123\nlogin: me\n"
  }
}
