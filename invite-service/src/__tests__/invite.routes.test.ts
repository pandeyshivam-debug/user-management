import request from 'supertest'
import express, { Express } from 'express'
import inviteRoutes from '../routes/invite.routes'

jest.mock('../controller/invite.controller', () => ({
  createInvite: jest.fn((req, res) => res.json({ message: 'createInvite called' })),
  verifyInvite: jest.fn((req, res) => res.json({ message: 'verifyInvite called' })),
  markUsed: jest.fn((req, res) => res.status(200).json({ message: 'markUsed called' })),
  getMyInvites: jest.fn((req, res) => res.json({ message: 'getMyInvites called' })),
}))

jest.mock('../middleware/auth.middleware', () => ({
  authenticate: (req: any, res: any, next: any) => next(),
}))

jest.mock('../middleware/roles.middleware', () => ({
  requireRoles: (roles: string[]) => (req: any, res: any, next: any) => next(),
}))

const app: Express = express()
app.use(express.json())
app.use('/api/v1/invite', inviteRoutes)

describe('invite.routes', () => {
  it('POST /create calls createInvite', async () => {
    const res = await request(app).post('/api/v1/invite/create').send({ email: 'a@b.com', role: 'CLIENT_USER' })
    expect(res.body).toEqual({ message: 'createInvite called' })
  })

  it('POST /verify calls verifyInvite', async () => {
    const res = await request(app).post('/api/v1/invite/verify').send({ token: 'tok123' })
    expect(res.body).toEqual({ message: 'verifyInvite called' })
  })

  it('POST /mark-used calls markUsed', async () => {
    const res = await request(app).post('/api/v1/invite/mark-used').send({ inviteId: 'i1' })
    expect(res.body).toEqual({ message: 'markUsed called' })
    expect(res.status).toBe(200)
  })

  it('GET /my-invites calls getMyInvites', async () => {
    const res = await request(app).get('/api/v1/invite/my-invites')
    expect(res.body).toEqual({ message: 'getMyInvites called' })
  })
})
