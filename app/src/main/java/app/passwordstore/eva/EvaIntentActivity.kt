/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.eva

import android.app.Activity
import android.app.SearchManager
import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.core.net.toUri
import app.passwordstore.R
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.ui.crypto.BasePGPActivity
import app.passwordstore.ui.main.LaunchActivity
import java.util.UUID

/**
 * Exported handoffs for assistants: open an entry's decrypted view, or the list with a search
 * prefilled. Both go through [LaunchActivity], so the app's own unlock UI applies; nothing is
 * returned to the caller.
 */
class EvaIntentActivity : Activity() {

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    // Unique data keeps a repeat handoff from matching the app task's root intent, which Android
    // would only bring to the front.
    forward()?.let {
      startActivity(
        it
          .setData("eva-handoff:${UUID.randomUUID()}".toUri())
          .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
      )
    }
    finish()
  }

  private fun forward(): Intent? =
    when (intent?.action) {
      ACTION_OPEN_ENTRY -> {
        val root = PasswordRepository.getRepositoryDirectory()
        val path = intent.getStringExtra(EXTRA_PATH)
        val file = path?.let { EvaCredential.resolve(root, it) }
        if (file == null) {
          val message =
            if (path.isNullOrBlank()) getString(R.string.eva_open_entry_missing_path)
            else getString(R.string.eva_open_entry_not_found, path)
          Toast.makeText(this, message, Toast.LENGTH_LONG).show()
          null
        } else
          Intent(this, LaunchActivity::class.java)
            .setAction(LaunchActivity.ACTION_DECRYPT_PASS)
            .putExtra(BasePGPActivity.EXTRA_FILE_PATH, file.absolutePath)
            .putExtra(BasePGPActivity.EXTRA_REPO_PATH, root.absolutePath)
      }
      ACTION_SEARCH -> {
        Intent(this, LaunchActivity::class.java)
          .setAction(Intent.ACTION_SEARCH)
          .putExtra(SearchManager.QUERY, intent.getStringExtra(EXTRA_QUERY)?.trim())
      }
      else -> null
    }

  companion object {
    const val ACTION_OPEN_ENTRY = "app.passwordstore.colonelpanic.action.OPEN_ENTRY"
    const val ACTION_SEARCH = "app.passwordstore.colonelpanic.action.SEARCH"
    const val EXTRA_PATH = "path"
    const val EXTRA_QUERY = SearchManager.QUERY
  }
}
