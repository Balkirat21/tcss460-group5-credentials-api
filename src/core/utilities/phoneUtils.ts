// src/core/utilities/phoneUtils.ts

/**
 * Phone number utilities for normalization and validation
 */

/**
 * Normalize a phone number to a consistent format
 * Removes all non-digit characters and handles country codes
 *
 * @param phone - Raw phone number input (can include spaces, dashes, parentheses, etc.)
 * @returns Normalized 10-digit US phone number without country code
 *
 * @example
 * normalizePhoneNumber('(425) 555-1234') // '4255551234'
 * normalizePhoneNumber('+1-425-555-1234') // '4255551234'
 * normalizePhoneNumber('1 425 555 1234') // '4255551234'
 * normalizePhoneNumber('425.555.1234') // '4255551234'
 */
export const normalizePhoneNumber = (phone: string): string => {
    if (!phone) {
        return '';
    }

    // Remove all non-digit characters
    const digitsOnly = phone.replace(/\D/g, '');

    // Handle empty result
    if (!digitsOnly) {
        return '';
    }

    // Remove leading '1' country code for US numbers (11 digits starting with 1)
    if (digitsOnly.startsWith('1') && digitsOnly.length === 11) {
        return digitsOnly.substring(1);
    }

    // Return as-is (should be 10 digits for valid US number)
    return digitsOnly;
};

/**
 * Validate that a normalized phone number is a valid 10-digit US number
 *
 * @param phone - Normalized phone number (digits only)
 * @returns true if valid 10-digit US phone number, false otherwise
 *
 * @example
 * isValidUSPhoneNumber('4255551234') // true
 * isValidUSPhoneNumber('425555123') // false (too short)
 * isValidUSPhoneNumber('14255551234') // false (has country code)
 */
export const isValidUSPhoneNumber = (phone: string): boolean => {
    // Must be exactly 10 digits
    if (!phone || phone.length !== 10) {
        return false;
    }

    // Must contain only digits
    if (!/^\d{10}$/.test(phone)) {
        return false;
    }

    // First digit cannot be 0 or 1 (valid US area codes)
    if (phone[0] === '0' || phone[0] === '1') {
        return false;
    }

    return true;
};

/**
 * Format a normalized phone number for display
 *
 * @param phone - Normalized phone number (10 digits)
 * @returns Formatted phone number (425) 555-1234 or original if invalid
 *
 * @example
 * formatPhoneNumber('4255551234') // '(425) 555-1234'
 */
export const formatPhoneNumber = (phone: string): string => {
    if (!isValidUSPhoneNumber(phone)) {
        return phone;
    }

    // Format as (XXX) XXX-XXXX
    return `(${phone.slice(0, 3)}) ${phone.slice(3, 6)}-${phone.slice(6)}`;
};

/**
 * Normalize and validate phone number in one step
 *
 * @param phone - Raw phone number input
 * @returns Object with normalized phone and validation status
 *
 * @example
 * normalizeAndValidatePhone('(425) 555-1234')
 * // { normalized: '4255551234', isValid: true, error: null }
 *
 * normalizeAndValidatePhone('123')
 * // { normalized: '123', isValid: false, error: 'Phone number must be 10 digits' }
 */
export const normalizeAndValidatePhone = (
    phone: string
): { normalized: string; isValid: boolean; error: string | null } => {
    const normalized = normalizePhoneNumber(phone);

    if (!normalized) {
        return {
            normalized: '',
            isValid: false,
            error: 'Phone number is required',
        };
    }

    if (normalized.length < 10) {
        return {
            normalized,
            isValid: false,
            error: 'Phone number must be 10 digits',
        };
    }

    if (normalized.length > 10) {
        return {
            normalized,
            isValid: false,
            error: 'Phone number must be 10 digits (remove country code)',
        };
    }

    if (!isValidUSPhoneNumber(normalized)) {
        return {
            normalized,
            isValid: false,
            error: 'Invalid US phone number format',
        };
    }

    return {
        normalized,
        isValid: true,
        error: null,
    };
};
