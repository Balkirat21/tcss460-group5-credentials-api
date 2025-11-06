// src/core/utilities/emailTemplates.ts
import * as fs from 'fs';
import * as path from 'path';

/**
 * Template cache to avoid reading from disk on every email
 */
const templateCache = new Map<string, string>();

/**
 * Load an email template from disk
 */
const loadTemplate = (templateName: string): string => {
    // Check cache first
    if (templateCache.has(templateName)) {
        return templateCache.get(templateName)!;
    }

    // Load from disk - Try multiple possible paths
    // When running from dist: __dirname = dist/core/utilities
    // When running from src: __dirname = src/core/utilities
    const possiblePaths = [
        path.join(__dirname, '../../templates/email', `${templateName}.html`),      // src structure
        path.join(__dirname, '../../../src/templates/email', `${templateName}.html`), // dist to src
        path.join(process.cwd(), 'src/templates/email', `${templateName}.html`),     // project root
    ];

    for (const templatePath of possiblePaths) {
        try {
            if (fs.existsSync(templatePath)) {
                const template = fs.readFileSync(templatePath, 'utf-8');
                templateCache.set(templateName, template);
                console.log(`✅ Loaded email template from: ${templatePath}`);
                return template;
            }
        } catch (error) {
            // Try next path
            continue;
        }
    }

    // If we get here, none of the paths worked
    console.error(`❌ Failed to load email template: ${templateName}`);
    console.error(`Tried paths:`, possiblePaths);
    throw new Error(`Email template not found: ${templateName}`);
};

/**
 * Replace placeholders in template
 */
const replacePlaceholders = (template: string, variables: Record<string, string>): string => {
    let result = template;

    for (const [key, value] of Object.entries(variables)) {
        const placeholder = `{{${key}}}`;
        result = result.replace(new RegExp(placeholder, 'g'), value);
    }

    return result;
};

/**
 * Render an email template with variables
 */
export const renderEmailTemplate = (templateName: string, variables: Record<string, string>): string => {
    const template = loadTemplate(templateName);
    return replacePlaceholders(template, variables);
};

/**
 * Clear template cache (useful for development/testing)
 */
export const clearTemplateCache = (): void => {
    templateCache.clear();
};

/**
 * Pre-load all templates into cache
 * Call this at application startup for better performance
 */
export const preloadTemplates = (): void => {
    const templates = ['verify-email', 'reset-password', 'welcome', 'password-changed'];

    for (const templateName of templates) {
        try {
            loadTemplate(templateName);
            console.log(`✅ Loaded email template: ${templateName}`);
        } catch (error) {
            console.error(`❌ Failed to load template: ${templateName}`, error);
        }
    }
};
