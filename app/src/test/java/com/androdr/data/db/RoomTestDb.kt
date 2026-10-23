package com.androdr.data.db

import android.app.Instrumentation
import android.content.Context
import android.content.ContextWrapper
import android.content.res.AssetManager
import androidx.room.Room
import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.core.app.ApplicationProvider
import io.mockk.every
import io.mockk.mockk
import java.io.FileNotFoundException

/** JVM (Robolectric) Room fixtures; test classes using these must run with RobolectricTestRunner. */
object RoomTestDb {
    private fun context(): Context = ApplicationProvider.getApplicationContext()

    /** A fresh in-memory [AppDatabase] at the current schema version. */
    fun inMemory(): AppDatabase =
        Room.inMemoryDatabaseBuilder(context(), AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()

    /**
     * Opens historical schemas exported to app/schemas. Robolectric's merged assets exclude the
     * unit-test source set, so the exported JSON is read from the test classpath (app/build.gradle.kts
     * adds app/schemas as test resources) through an [AssetManager] stand-in handed to Room.
     */
    fun migrationHelper(): MigrationTestHelper = MigrationTestHelper(
        schemaInstrumentation(context()),
        AppDatabase::class.java,
        emptyList(),
        FrameworkSQLiteOpenHelperFactory()
    )

    private fun schemaInstrumentation(app: Context): Instrumentation {
        val assets = mockk<AssetManager>()
        every { assets.open(any()) } answers {
            val path = firstArg<String>()
            RoomTestDb::class.java.classLoader!!.getResourceAsStream(path)
                ?: throw FileNotFoundException("schema resource not on test classpath: $path")
        }
        val schemaContext = object : ContextWrapper(app) {
            override fun getAssets(): AssetManager = assets
        }
        return object : Instrumentation() {
            override fun getContext(): Context = schemaContext
            override fun getTargetContext(): Context = app
        }
    }
}
