package com.androdr.privacy.model

/**
 * Whether the tracker registry can be used. It starts [LOADING] (the bundled file is parsed lazily, off the main
 * thread); [UNAVAILABLE] means the bundled file was unusable and no verified refresh has landed yet. A later
 * verified refresh still moves [UNAVAILABLE] to [AVAILABLE]. Only [UNAVAILABLE] may be shown as "could not be
 * loaded": [LOADING] is not a failure.
 */
enum class RegistryState { LOADING, AVAILABLE, UNAVAILABLE }
