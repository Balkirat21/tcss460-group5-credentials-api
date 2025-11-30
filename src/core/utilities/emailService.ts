// src/core/utilities/emailService.ts
import * as nodemailer from 'nodemailer';
import { Resend } from 'resend';
import { getEnvVar, isProduction } from './envConfig';
import { SMS_GATEWAYS } from '@models';
import { renderEmailTemplate, preloadTemplates } from './emailTemplates';
import { normalizePhoneNumber } from './phoneUtils';

/**
 * Singleton instances for email providers
 */
let emailTransporter: nodemailer.Transporter | null = null;
let resendClient: Resend | null = null;

/**
 * Get the email provider type
 */
const getEmailProvider = (): 'resend' | 'smtp' => {
    const provider = getEnvVar('EMAIL_PROVIDER', 'smtp').toLowerCase();
    return provider === 'resend' ? 'resend' : 'smtp';
};

/**
 * Initialize email service
 * Call this once at application startup
 */
export const initializeEmailService = (): void => {
    try {
        const provider = getEmailProvider();

        if (provider === 'resend') {
            // Initialize Resend
            const apiKey = getEnvVar('RESEND_API_KEY');
            resendClient = new Resend(apiKey);
            console.log('✅ Email service initialized successfully (Resend)');
        } else {
            // Initialize SMTP (nodemailer)
            emailTransporter = nodemailer.createTransport({
                service: getEnvVar('EMAIL_SERVICE', 'gmail'),
                auth: {
                    user: getEnvVar('EMAIL_USER'),
                    pass: getEnvVar('EMAIL_PASSWORD'),
                },
                // Timeout configuration to prevent indefinite hangs
                connectionTimeout: 10000,  // 10 seconds to establish connection
                greetingTimeout: 10000,    // 10 seconds for server greeting
                socketTimeout: 10000,       // 10 seconds for socket inactivity
            });
            console.log('✅ Email service initialized successfully (SMTP)');
        }

        // Preload email templates for better performance
        preloadTemplates();

    } catch (error) {
        console.error('❌ Failed to initialize email service:', error);
        throw error;
    }
};

/**
 * Get the SMTP transporter instance
 */
const getTransporter = (): nodemailer.Transporter => {
    if (!emailTransporter) {
        throw new Error('SMTP transporter not initialized. Call initializeEmailService() first.');
    }
    return emailTransporter;
};

/**
 * Get the Resend client instance
 */
const getResendClient = (): Resend => {
    if (!resendClient) {
        throw new Error('Resend client not initialized. Call initializeEmailService() first.');
    }
    return resendClient;
};

/**
 * Send an email using the configured provider
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
            const provider = getEmailProvider();
            const from = getEnvVar('EMAIL_FROM', 'onboarding@resend.dev');

            if (provider === 'resend') {
                // Send via Resend
                const result = await getResendClient().emails.send({
                    from,
                    to: options.to,
                    subject: options.subject,
                    html: options.html || options.text || '',
                });

                if (result.error) {
                    console.error('Resend error:', result.error);
                    return false;
                }

                console.log(`📧 Email sent via Resend to ${options.to} (ID: ${result.data?.id})`);
            } else {
                // Send via SMTP
                await getTransporter().sendMail({
                    from,
                    ...options,
                });
                console.log(`📧 Email sent via SMTP to ${options.to}`);
            }
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
 * Note: This always uses SMTP, even if Resend is the main email provider
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
            // SMS via email always uses SMTP transporter (not Resend)
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
