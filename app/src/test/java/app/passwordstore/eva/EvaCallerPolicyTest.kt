/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.eva

import app.passwordstore.eva.EvaCallerPolicy.Companion.EVA
import app.passwordstore.eva.EvaCallerPolicy.Companion.EVA_DEBUG
import app.passwordstore.eva.EvaCallerPolicy.Companion.EVA_DEBUG_CERT
import app.passwordstore.eva.EvaCallerPolicy.Companion.EVA_RELEASE_CERT
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class EvaCallerPolicyTest {

  private val signers =
    mapOf(
      EVA to EVA_RELEASE_CERT,
      EVA_DEBUG to EVA_DEBUG_CERT,
      "com.example.spoof" to EVA_RELEASE_CERT,
    )

  private fun EvaCallerPolicy.trusts(
    vararg packages: String,
    signer: (String) -> String? = signers::get,
  ) = trusts(arrayOf(*packages)) { name, pin -> signer(name) == pin }

  @Test
  fun releaseTrustsOnlySignedProductionEva() {
    val policy = EvaCallerPolicy.forBuild(debug = false)
    assertTrue(policy.trusts(EVA))
    assertFalse(policy.trusts(EVA, signer = { EVA_DEBUG_CERT }))
    assertFalse(policy.trusts(EVA_DEBUG))
    assertFalse(policy.trusts("com.example.spoof"))
    assertFalse(policy.trusts(EVA, "com.example.spoof"))
    assertFalse(policy.trusts())
    assertFalse(policy.trusts(null) { _, _ -> true })
  }

  @Test
  fun debugAlsoTrustsDebugEvaWithItsDevelopmentSigner() {
    val policy = EvaCallerPolicy.forBuild(debug = true)
    assertTrue(policy.trusts(EVA))
    assertTrue(policy.trusts(EVA_DEBUG))
    assertFalse(policy.trusts(EVA_DEBUG, signer = { EVA_RELEASE_CERT }))
  }

  @Test
  fun aBuildTimeDebugSignerIsTrustedOnlyInDebugBuilds() {
    val local = "0d0f59cd1640ed8fd7d9754932c85f4434c282ec274c6a24985986c9046d3dda"
    val debug = EvaCallerPolicy.forBuild(debug = true, extraDebugCert = local)
    assertTrue(debug.trusts(EVA_DEBUG, signer = { local }))
    assertTrue(debug.trusts(EVA_DEBUG))
    assertFalse(debug.trusts(EVA, signer = { local }))
    val release = EvaCallerPolicy.forBuild(debug = false, extraDebugCert = local)
    assertFalse(release.trusts(EVA_DEBUG, signer = { local }))
  }
}
