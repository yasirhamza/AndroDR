package com.androdr.ui.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.repo.SettingsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val settingsRepository: SettingsRepository
) : ViewModel() {

    val blocklistBlockMode = settingsRepository.blocklistBlockMode
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), true)

    val domainIocBlockMode = settingsRepository.domainIocBlockMode
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    fun setBlocklistBlockMode(value: Boolean) {
        viewModelScope.launch { settingsRepository.setBlocklistBlockMode(value) }
    }

    fun setDomainIocBlockMode(value: Boolean) {
        viewModelScope.launch { settingsRepository.setDomainIocBlockMode(value) }
    }
}
