import { mockDeep } from 'jest-mock-extended'
import { PrismaClient } from '@prisma/client'
import * as crypto from 'crypto'

// mock prisma
jest.mock('../prisma/client.prisma', () => ({
    __esModule: true,
    default: mockDeep<PrismaClient>(),
}))
const prismaMock = require('../prisma/client.prisma').default

// mock mailer
jest.mock('../utils/mailer', () => ({
    sendMail: jest.fn().mockResolvedValue(true),
}))
import { sendMail } from '../utils/mailer'

import * as inviteService from '../services/invite.service'

describe('invite.service', () => {
    beforeEach(() => {
    jest.clearAllMocks()
    })

    describe('createInvitation', () => {
        it('creates an invite and sends mail', async () => {
            prismaMock.user.findUnique.mockResolvedValue({ id: 'inv1', role: 'SUPER_ADMIN' })
            prismaMock.invitation.create.mockResolvedValue({
                id: 'i1',
                email: 'test@mail.com',
                role: 'SITE_ADMIN',
                token: 'tok123',
                expiresAt: new Date(),
            })

            const invite = await inviteService.createInvitation('inv1', 'test@mail.com', 'SITE_ADMIN')

            expect(prismaMock.invitation.create).toHaveBeenCalled()
            expect(sendMail).toHaveBeenCalled()
            expect(invite).toHaveProperty('token')
        })

        it('throws if inviter not found', async () => {
            prismaMock.user.findUnique.mockResolvedValue(null)

            await expect(
                inviteService.createInvitation('inv1', 'test@mail.com', 'SITE_ADMIN')
            ).rejects.toMatchObject({ status: 404 })
        })

        it('throws if inviter role not allowed to invite target role', async () => {
            prismaMock.user.findUnique.mockResolvedValue({ id: 'u1', role: 'CLIENT_USER' })

            await expect(
                inviteService.createInvitation('u1', 'test@mail.com', 'SUPER_ADMIN')
            ).rejects.toMatchObject({ status: 403 })
        })
        })

        describe('verifyInvitation', () => {
        it('verifies a valid invite', async () => {
            const fakeInvite = {
                id: 'i1',
                used: false,
                expiresAt: new Date(Date.now() + 100000),
            }
            prismaMock.invitation.findUnique.mockResolvedValue(fakeInvite)

            const result = await inviteService.verifyInvitation('validToken')
            expect(result).toEqual(fakeInvite)
        })

        it('throws if invite not found', async () => {
            prismaMock.invitation.findUnique.mockResolvedValue(null)
            await expect(inviteService.verifyInvitation('bad')).rejects.toMatchObject({ status: 400 })
        })

        it('throws if invite already used', async () => {
            prismaMock.invitation.findUnique.mockResolvedValue({
                used: true,
                expiresAt: new Date(Date.now() + 10000),
            })
            await expect(inviteService.verifyInvitation('token')).rejects.toMatchObject({ status: 400 })
        })

        it('throws if invite expired', async () => {
            prismaMock.invitation.findUnique.mockResolvedValue({
                used: false,
                expiresAt: new Date(Date.now() - 10000),
            })
            await expect(inviteService.verifyInvitation('token')).rejects.toMatchObject({ status: 400 })
        })
    })

    describe('markInvitationAsUsed', () => {
    it('marks invite as used', async () => {
        prismaMock.invitation.update.mockResolvedValue({} as any)

        await inviteService.markInvitationAsUsed('i1')

        expect(prismaMock.invitation.update).toHaveBeenCalledWith({
            where: { id: 'i1' },
            data: { used: true },
        })
    })
    })

    describe('getInvitationsByUser', () => {
    it('returns all invitations for a user', async () => {
        const fakeInvites = [
            { id: '1', email: 'a@a.com', role: 'CLIENT_USER' },
            { id: '2', email: 'b@b.com', role: 'OPERATOR' },
        ]
        prismaMock.invitation.findMany.mockResolvedValue(fakeInvites as any)

        const result = await inviteService.getInvitationsByUser('u1')
        expect(result).toEqual(fakeInvites)
        expect(prismaMock.invitation.findMany).toHaveBeenCalledWith(
            expect.objectContaining({
                where: { invitedBy: 'u1' },
                orderBy: { createdAt: 'desc' },
            })
        )
    })
    })
})
