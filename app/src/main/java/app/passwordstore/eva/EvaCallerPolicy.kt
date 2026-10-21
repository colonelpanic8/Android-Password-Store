/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.eva

import java.util.Locale

/**
 * Trusts a calling UID only when every package sharing it is an allowlisted EVA package signed by
 * one of its pinned certificates. Pins are SHA-256 digests of the signing certificate; a rotated
 * signer stays trusted while the pinned certificate remains in the package's proven lineage.
 */
class EvaCallerPolicy(private val pins: Map<String, Set<String>>) {

  fun trusts(packages: Array<String>?, signedBy: (packageName: String, sha256: String) -> Boolean) =
    !packages.isNullOrEmpty() &&
      packages.all { name -> pins[name].orEmpty().any { pin -> signedBy(name, pin) } }

  companion object {
    const val EVA = "com.colonelpanic.eva"
    const val EVA_DEBUG = "com.colonelpanic.eva.debug"
    /** EVA's release certificate, checked against the v0.68.0 release APK with apksigner. */
    const val EVA_RELEASE_CERT = "688df17827dd9a002705baf0400c80f8f4650c6e87c3fc91d41f32be287f8b68"
    /** The development debug keystore that signs EVA debug builds. */
    const val EVA_DEBUG_CERT = "7e2a02d4ac64162c3ff78af6e8b1ed24cb26649dc6bdd3955fe9410efa5666e3"

    /** [extraDebugCert] is another EVA Debug signer, such as a local debug keystore's. */
    fun forBuild(debug: Boolean, extraDebugCert: String = "") =
      EvaCallerPolicy(
        buildMap {
          put(EVA, setOf(EVA_RELEASE_CERT))
          if (debug) put(EVA_DEBUG, setOfNotNull(EVA_DEBUG_CERT, extraDebugCert.ifEmpty { null }))
        }
      )

    fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(Locale.ROOT, it) }

    fun bytes(hex: String) =
      ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
  }
}
