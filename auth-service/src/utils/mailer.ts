import nodemailer from 'nodemailer'

const host = process.env.SMTP_HOST
const port = process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : undefined
const user = process.env.SMTP_USER
const pass = process.env.SMTP_PASS
const fromEmail = process.env.FROM_EMAIL

let transporter: nodemailer.Transporter | null = null

if (host && port && user && pass) {
    transporter = nodemailer.createTransport({
        host,
        port,
        auth: { user, pass }
    })
}

export const sendMail = async (to: string, subject: string, text: string, html?: string) => {
    if(!transporter) {
        console.log('--- Mail fallback (not sent) ---');
        console.log({ to, subject, text, html });
        console.log('-------------------------------');
        return;
    }
    await transporter.sendMail({
        to,
        from: fromEmail,
        subject,
        text,
        html
    })
}