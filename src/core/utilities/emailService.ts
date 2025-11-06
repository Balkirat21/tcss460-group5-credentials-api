// src/core/utilities/emailService.ts
import * as nodemailer from 'nodemailer';
import { getEnvVar, isProduction } from './envConfig';
import { SMS_GATEWAYS } from '@models';
import { renderEmailTemplate, preloadTemplates } from './emailTemplates';
import { normalizePhoneNumber } from './phoneUtils';

/**
 * Singleton email transporter instance
 */
let emailTransporter: nodemailer.Transporter | null = null;

/**
 * Initialize email transporter
 * Call this once at application startup
 */
export const initializeEmailService = (): void => {
    try {
        emailTransporter = nodemailer.createTransport({
            service: getEnvVar('EMAIL_SERVICE', 'gmail'),
            auth: {
                user: getEnvVar('EMAIL_USER'),
                pass: getEnvVar('EMAIL_PASSWORD'),
            },
        });

        // Preload email templates for better performance
        preloadTemplates();

        console.log('✅ Email service initialized successfully');
    } catch (error) {
        console.error('❌ Failed to initialize email service:', error);
        throw error;
    }
};

/**
 * Get the email transporter instance
 */
const getTransporter = (): nodemailer.Transporter => {
    if (!emailTransporter) {
        throw new Error('Email service not initialized. Call initializeEmailService() first.');
    }
    return emailTransporter;
};

/**
 * Send an email
 */
export const sendEmail = async (options: {
    to: string;
    subject: string;
    html?: string;
    text?: string;
}): Promise<boolean> => {
    try {
        const shouldSend = isProduction() || getEnvVar('SEND_EMAILS') === 'true';
        
        if (shouldSend) {
            await getTransporter().sendMail({
                from: getEnvVar('EMAIL_FROM', getEnvVar('EMAIL_USER')),
                ...options,
            });
            console.log(`📧 Email sent to ${options.to}`);
        } else {
            console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
            console.log('📧 MOCK EMAIL (Development Mode)');
            console.log(`To: ${options.to}`);
            console.log(`Subject: ${options.subject}`);
            if (options.text) console.log(`Text: ${options.text}`);
            console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        }
        
        return true;
    } catch (error) {
        console.error('Failed to send email:', error);
        return false;
    }
};

/**
 * Get carrier gateway for SMS
 */
const getCarrierGateway = (carrier?: string): string => {
    // Check if we should actually send SMS (production or explicitly enabled)
    const shouldSendReal = isProduction() || getEnvVar('SEND_SMS_EMAILS') === 'true';

    // In development, use mock gateway unless explicitly enabled
    if (!shouldSendReal) {
        console.log('📱 Using mock SMS gateway for development');
        return SMS_GATEWAYS['mock'];
    }

    // If a carrier is provided, use it
    if (carrier && SMS_GATEWAYS[carrier.toLowerCase()]) {
        return SMS_GATEWAYS[carrier.toLowerCase()];
    }

    // Default to configured carrier or AT&T
    const defaultCarrier = getEnvVar('DEFAULT_SMS_CARRIER', 'att');
    return SMS_GATEWAYS[defaultCarrier];
};

/**
 * Send SMS via Email-to-SMS gateway
 */
export const sendSMSViaEmail = async (
    phone: string,
    message: string,
    carrier?: string
): Promise<boolean> => {
    try {
        // Normalize phone number using utility function
        const phoneDigits = normalizePhoneNumber(phone);

        // Get carrier gateway
        const gateway = getCarrierGateway(carrier);
        const smsEmail = `${phoneDigits}${gateway}`;

        const shouldSend = isProduction() || getEnvVar('SEND_SMS_EMAILS') === 'true';
        
        if (shouldSend) {
            await getTransporter().sendMail({
                from: getEnvVar('EMAIL_USER'),
                to: smsEmail,
                subject: '', // Many gateways ignore subject
                text: message, // Use text only, not HTML
            });
            console.log(`📱 SMS sent via email gateway to ${smsEmail}`);
        } else {
            console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
            console.log('📱 MOCK SMS (Email-to-SMS Gateway)');
            console.log(`📧 Would send to: ${smsEmail}`);
            console.log(`📞 Phone: ${phone}`);
            console.log(`📨 Message: ${message}`);
            console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        }
        
        return true;
    } catch (error) {
        console.error('Failed to send SMS via email gateway:', error);
        return false;
    }
};

/**
 * Send verification email
 */
export const sendVerificationEmail = async (
    email: string,
    firstname: string,
    verificationUrl: string
): Promise<boolean> => {
    const html = renderEmailTemplate('verify-email', {
        firstname,
        verificationUrl,
    });

    return sendEmail({
        to: email,
        subject: 'Verify your Auth² account',
        html,
    });
};

/**
 * Send password reset email
 */
export const sendPasswordResetEmail = async (
    email: string,
    firstname: string,
    resetUrl: string
): Promise<boolean> => {
    const html = renderEmailTemplate('reset-password', {
        firstname,
        resetUrl,
    });

    return sendEmail({
        to: email,
        subject: 'Password Reset Request - Auth²',
        html,
    });
};