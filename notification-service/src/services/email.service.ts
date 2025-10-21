import nodemailer from 'nodemailer'

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: false,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
})

export const sendInvitationAcceptedEmail = async (
        recipientEmail: string,
        recipientName: string,
        inviteeName: string,
        inviteeEmail: string,
        inviteeRole: string
    ) => {
    const mailOptions = {
        from: process.env.EMAIL_FROM,
        to: recipientEmail,
        subject: 'Your Invitation Has Been Accepted',
        html: `
            <div style="font-family: Arial, sans-serif; padding: 20px;">
            <h2>Invitation accepted</h2>
            <p>Hello ${recipientName || 'there'},</p>
            <p>Your invitation has been accepted!</p>
            
            <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <p><strong>New User Details:</strong></p>
                <ul style="list-style: none; padding: 0;">
                <li><strong>Email:</strong> ${inviteeEmail}</li>
                <li><strong>Name:</strong> ${inviteeName}</li>
                <li><strong>Role:</strong> ${inviteeRole}</li>
                </ul>
            </div>
            
            <p>The user has successfully registered and is now part of your team.</p>
            
            <p>Best regards,<br/>Your Team</p>
            </div>
        `,
    }

    try {
        await transporter.sendMail(mailOptions)
        console.log(`Email sent to ${recipientEmail}`)
        return true
    } catch (error) {
        console.error(`Error sending email to ${recipientEmail}:`, error)
        return false
    }
}
