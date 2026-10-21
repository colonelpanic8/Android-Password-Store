/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.eva

import android.app.Service
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.RemoteException
import android.os.SystemClock
import app.passwordstore.BuildConfig
import app.passwordstore.data.passfile.PasswordEntry
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.eva.EvaProtocol.Reason
import app.passwordstore.eva.EvaProtocol.Status
import app.passwordstore.injection.prefs.SettingsPreferences
import app.passwordstore.util.autofill.AutofillPreferences
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.extensions.b64Decode
import app.passwordstore.util.extensions.wipe
import app.passwordstore.util.passkey.PasskeyCredential
import app.passwordstore.util.services.getDefaultUsername
import app.passwordstore.util.settings.PreferenceKeys
import com.colonelpanic.eva.extension.IEvaExtension
import com.colonelpanic.eva.extension.IEvaExtensionCallback
import dagger.hilt.android.AndroidEntryPoint
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicInteger
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import logcat.LogPriority
import logcat.logcat

/**
 * Exported binder EVA discovers through `com.colonelpanic.eva.action.EXTENSION`. Binder threads
 * only authenticate, validate and enqueue; decryption runs on a bounded number of coroutines.
 */
@AndroidEntryPoint
class EvaExtensionService : Service() {

  @Inject lateinit var decryptor: EvaDecryptor
  @Inject lateinit var entryFactory: PasswordEntry.Factory
  @Inject lateinit var dispatchers: DispatcherProvider
  @SettingsPreferences @Inject lateinit var settings: SharedPreferences

  private val policy = EvaCallerPolicy.forBuild(BuildConfig.DEBUG)
  private val inFlight = AtomicInteger()
  private lateinit var scope: CoroutineScope

  override fun onCreate() {
    super.onCreate()
    scope = CoroutineScope(SupervisorJob() + dispatchers.default())
  }

  override fun onDestroy() {
    scope.cancel()
    super.onDestroy()
  }

  override fun onBind(intent: Intent): IBinder = binder

  private val binder =
    object : IEvaExtension.Stub() {
      override fun describe(
        requestId: String,
        requestJson: String,
        deadline: Long,
        callback: IEvaExtensionCallback,
      ) {
        val reply =
          if (!trusted(Binder.getCallingUid()))
            EvaProtocol.describeFailure(Reason.UNAUTHORIZED_CALLER, "Caller is not authorized.")
          else {
            val request = EvaProtocol.parseDescribeRequest(requestJson)
            when {
              request == null ->
                EvaProtocol.describeFailure(
                  Reason.INVALID_ARGUMENTS,
                  "The describe request is not a JSON object.",
                )
              !request.supportsV1 ->
                EvaProtocol.describeFailure(
                  Reason.NOT_CONFIGURED,
                  "Password Store (EVA) only speaks EVA extension protocol 1. Update EVA or this app.",
                )
              else ->
                EvaProtocol.describeReply(
                  EvaCatalog.descriptor(EvaCatalog.Features.of(request.features))
                )
            }
          }
        send(callback, requestId, reply)
      }

      override fun execute(
        invocationId: String,
        expectedRevision: String,
        capability: String,
        argumentsJson: String,
        deadline: Long,
        callback: IEvaExtensionCallback,
      ) {
        if (!trusted(Binder.getCallingUid())) {
          send(
            callback,
            invocationId,
            EvaProtocol.rejection(Reason.UNAUTHORIZED_CALLER, "Caller is not authorized."),
          )
          return
        }
        if (deadline <= SystemClock.elapsedRealtime()) {
          send(callback, invocationId, expired())
          return
        }
        val call =
          when (val admission = EvaCatalog.admit(expectedRevision, capability, argumentsJson)) {
            is EvaCatalog.Admission.Rejected -> {
              send(callback, invocationId, admission.reply)
              return
            }
            is EvaCatalog.Admission.Accepted -> admission.call
          }
        if (inFlight.incrementAndGet() > MAX_IN_FLIGHT) {
          inFlight.decrementAndGet()
          wipe(call)
          send(
            callback,
            invocationId,
            EvaProtocol.rejection(
              Reason.BUSY,
              "Password Store (EVA) is busy with other EVA requests. Nothing was done.",
            ),
          )
          return
        }
        scope.launch {
          val reply =
            try {
              run(call, deadline)
            } catch (e: Exception) {
              logcat(LogPriority.ERROR) { "EVA request failed: ${e::class.simpleName}" }
              EvaProtocol.result(
                Status.FAILED,
                null,
                "Password Store (EVA) hit an internal error (${e::class.simpleName}). " +
                  "Nothing was changed.",
              )
            } finally {
              wipe(call)
              inFlight.decrementAndGet()
            }
          send(callback, invocationId, reply)
        }
      }
    }

  private suspend fun run(call: EvaCatalog.Call, deadline: Long): String {
    val root = PasswordRepository.getRepositoryDirectory()
    val hasStore =
      withContext(dispatchers.io()) { root.isDirectory && !root.list().isNullOrEmpty() }
    if (!hasStore)
      return EvaProtocol.rejection(
        Reason.NOT_CONFIGURED,
        "Password Store (EVA) has no password store yet. Open the app and clone or create one.",
      )
    return when (call) {
      is EvaCatalog.Call.Search -> {
        val showHidden = settings.getBoolean(PreferenceKeys.SHOW_HIDDEN_CONTENTS, false)
        val entries = withContext(dispatchers.io()) { EvaStoreSearch.listEntries(root, showHidden) }
        EvaStoreSearch.reply(EvaStoreSearch.match(entries, call.request.query), call.request)
      }
      is EvaCatalog.Call.Credential ->
        credential(root, call.path, call.passphrase?.chars, call.reportsRejection, deadline)
      is EvaCatalog.Call.CheckPassphrase ->
        when (val check = decryptor.check(root, call.passphrase.chars)) {
          is EvaDecryptor.Check.Accepted -> EvaProtocol.verdict(true, check.message)
          is EvaDecryptor.Check.Rejected -> EvaProtocol.verdict(false, check.message)
          is EvaDecryptor.Check.Unavailable ->
            EvaProtocol.rejection(Reason.NOT_CONFIGURED, check.message)
        }
    }
  }

  private suspend fun credential(
    root: File,
    requested: String,
    passphrase: CharArray?,
    reportsRejection: Boolean,
    deadline: Long,
  ): String {
    val file =
      withContext(dispatchers.io()) { EvaCredential.resolve(root, requested) }
        ?: return EvaProtocol.rejection(
          Reason.INVALID_ARGUMENTS,
          "No entry \"$requested\" exists in the password store. Use search_entries to find its " +
            "exact path. Nothing was done.",
        )
    if (deadline <= SystemClock.elapsedRealtime()) return expired()
    val path = file.relativeTo(root).invariantSeparatorsPath.removeSuffix(".gpg")
    return when (val outcome = decryptor.decrypt(file, root, passphrase)) {
      is EvaDecryptor.Outcome.Unavailable ->
        EvaProtocol.rejection(Reason.NOT_CONFIGURED, outcome.message)
      is EvaDecryptor.Outcome.WrongSupplied ->
        EvaProtocol.rejection(
          Reason.NOT_CONFIGURED,
          outcome.message,
          if (reportsRejection) setOf(EvaCatalog.PASSPHRASE) else emptySet(),
        )
      is EvaDecryptor.Outcome.Failed -> EvaProtocol.result(Status.FAILED, null, outcome.message)
      is EvaDecryptor.Outcome.Decrypted -> {
        val entry = entryFactory.create(outcome.chars)
        outcome.chars.wipe()
        try {
          val isPasskey =
            entry.password?.b64Decode()?.let { cbor ->
              PasskeyCredential.fromCbor(cbor).isOk.also { cbor.wipe() }
            } ?: false
          val fromPath =
            AutofillPreferences.directoryStructure(this)
              .getUsernameFor(File(file.relativeTo(root).invariantSeparatorsPath))
          EvaCredential.reply(
            path,
            entry,
            EvaCredential.username(entry, fromPath, getDefaultUsername()),
            isPasskey,
          )
        } finally {
          entry.clear()
        }
      }
    }
  }

  private fun wipe(call: EvaCatalog.Call) {
    when (call) {
      is EvaCatalog.Call.Credential -> call.passphrase?.wipe()
      is EvaCatalog.Call.CheckPassphrase -> call.passphrase.wipe()
      is EvaCatalog.Call.Search -> Unit
    }
  }

  private fun expired() =
    EvaProtocol.rejection(
      Reason.DEADLINE_EXCEEDED,
      "EVA's deadline passed before Password Store (EVA) started. Nothing was done.",
    )

  private fun send(callback: IEvaExtensionCallback, requestId: String, reply: String) {
    try {
      callback.onResult(requestId, reply)
    } catch (e: RemoteException) {
      logcat(LogPriority.WARN) { "EVA stopped waiting for a reply" }
    }
  }

  private fun trusted(uid: Int): Boolean {
    val packages = packageManager
    return policy.trusts(packages.getPackagesForUid(uid)) { name, pin ->
      signedBy(packages, name, pin)
    }
  }

  private fun signedBy(packages: PackageManager, name: String, pin: String): Boolean =
    try {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
        packages.hasSigningCertificate(
          name,
          EvaCallerPolicy.bytes(pin),
          PackageManager.CERT_INPUT_SHA256,
        )
      else {
        @Suppress("DEPRECATION")
        val signatures =
          packages.getPackageInfo(name, PackageManager.GET_SIGNATURES).signatures.orEmpty()
        signatures.size == 1 &&
          EvaCallerPolicy.hex(
            MessageDigest.getInstance("SHA-256").digest(signatures[0].toByteArray())
          ) == pin
      }
    } catch (_: PackageManager.NameNotFoundException) {
      false
    }

  private companion object {
    const val MAX_IN_FLIGHT = 4
  }
}
