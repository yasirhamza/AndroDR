package com.androdr.sigma

import org.junit.Assert.assertEquals
import org.junit.Test

class SeverityCapPolicyTest {

    @Test
    fun `incident category does not cap critical`() {
        assertEquals("critical", SeverityCapPolicy.applyCap(RuleCategory.INCIDENT, "critical"))
    }

    @Test
    fun `incident category does not cap high`() {
        assertEquals("high", SeverityCapPolicy.applyCap(RuleCategory.INCIDENT, "high"))
    }

    @Test
    fun `incident category does not cap medium`() {
        assertEquals("medium", SeverityCapPolicy.applyCap(RuleCategory.INCIDENT, "medium"))
    }

    @Test
    fun `incident category does not cap low`() {
        assertEquals("low", SeverityCapPolicy.applyCap(RuleCategory.INCIDENT, "low"))
    }

    @Test
    fun `device_posture category clamps critical to medium`() {
        assertEquals("medium", SeverityCapPolicy.applyCap(RuleCategory.DEVICE_POSTURE, "critical"))
    }

    @Test
    fun `device_posture category clamps high to medium`() {
        assertEquals("medium", SeverityCapPolicy.applyCap(RuleCategory.DEVICE_POSTURE, "high"))
    }

    @Test
    fun `device_posture category passes medium through unchanged`() {
        assertEquals("medium", SeverityCapPolicy.applyCap(RuleCategory.DEVICE_POSTURE, "medium"))
    }

    @Test
    fun `device_posture category passes low through unchanged`() {
        assertEquals("low", SeverityCapPolicy.applyCap(RuleCategory.DEVICE_POSTURE, "low"))
    }

    @Test
    fun `device_posture category passes informational through unchanged`() {
        assertEquals("informational", SeverityCapPolicy.applyCap(RuleCategory.DEVICE_POSTURE, "informational"))
    }

    @Test
    fun `applyCap is case insensitive on declared level`() {
        assertEquals("medium", SeverityCapPolicy.applyCap(RuleCategory.DEVICE_POSTURE, "CRITICAL"))
        assertEquals("medium", SeverityCapPolicy.applyCap(RuleCategory.DEVICE_POSTURE, "High"))
    }

    @Test
    fun `unknown severity value passes through unchanged`() {
        assertEquals("bogus", SeverityCapPolicy.applyCap(RuleCategory.DEVICE_POSTURE, "bogus"))
        assertEquals("bogus", SeverityCapPolicy.applyCap(RuleCategory.INCIDENT, "bogus"))
    }

    @Test
    fun `empty severity string passes through unchanged`() {
        assertEquals("", SeverityCapPolicy.applyCap(RuleCategory.DEVICE_POSTURE, ""))
    }

    @Test
    fun `incident category lowercases input`() {
        assertEquals("critical", SeverityCapPolicy.applyCap(RuleCategory.INCIDENT, "CRITICAL"))
        assertEquals("high", SeverityCapPolicy.applyCap(RuleCategory.INCIDENT, "High"))
    }
}
