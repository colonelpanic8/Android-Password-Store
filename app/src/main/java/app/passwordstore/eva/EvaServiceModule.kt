/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.eva

import app.passwordstore.util.totp.TotpFinder
import app.passwordstore.util.totp.UriTotpFinder
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.android.components.ServiceComponent

/** [app.passwordstore.injection.totp.TotpModule] only covers activities. */
@Module
@InstallIn(ServiceComponent::class)
interface EvaServiceModule {
  @Binds fun bindTotpFinder(impl: UriTotpFinder): TotpFinder
}
