import prisma from '../config/database.config'
import { sendInvitationAcceptedEmail } from './email.service'

export const createNotification = async (data: {
        type: string
        recipientEmail: string
        recipientName?: string
        inviteeEmail: string
        inviteeName: string
        inviteeRole: string
    }) => {
    try {
        const notification = await prisma.notification.create({
            data: {
                type: data.type,
                recipientEmail: data.recipientEmail,
                recipientName: data.recipientName || '',
                inviteeEmail: data.inviteeEmail,
                inviteeName: data.inviteeName,
                inviteeRole: data.inviteeRole,
            },
        })
        console.log('Notification created:', notification.id)
        return notification
    } catch (error) {
        console.error('Error creating notification:', error)
        throw error
    }
}

export const processNotification = async (notificationId: string) => {
    try {
        const notification = await prisma.notification.findUnique({
            where: { id: notificationId },
        })

        if (!notification || notification.sent) {
            return
        }

        const emailSent = await sendInvitationAcceptedEmail(
            notification.recipientEmail,
            notification.recipientName || '',
            notification.inviteeName,
            notification.inviteeEmail,
            notification.inviteeRole
        )

        if (emailSent) {
            await prisma.notification.update({
            where: { id: notificationId },
            data: {
                sent: true,
                sentAt: new Date(),
            },
            })
            console.log('✅ Notification processed successfully')
        }
    } catch (error) {
        console.error('Error processing notification:', error)
    }
}
