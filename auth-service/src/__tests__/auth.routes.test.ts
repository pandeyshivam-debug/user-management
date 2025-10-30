import request from 'supertest'
import express, { Express } from 'express'
import router from '../routes/auth.routes'
import * as ctrl from '../controllers/auth.controller'
import { authenticate } from '../middleware/auth.middleware'

jest.mock('../controllers/auth.controller')
jest.mock('../middleware/auth.middleware', () => ({
  authenticate: jest.fn((req, res, next) => next()),
}))

const app: Express = express()
app.use(express.json())
app.use('/api/v1/auth', router)

describe('auth.routes', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('POST /register calls ctrl.register', async () => {
    (ctrl.register as jest.Mock).mockImplementation((req, res) => res.json({ ok: true }))

    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ token: 'tok', name: 'Alice', password: 'pass', phone: '987' })

    expect(ctrl.register).toHaveBeenCalled()
    expect(res.body).toEqual({ ok: true })
  })

  it('POST /login calls ctrl.login', async () => {
    (ctrl.login as jest.Mock).mockImplementation((req, res) => res.json({ token: 'abc' }))

    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'a@b.com', password: 'pass' })

    expect(ctrl.login).toHaveBeenCalled()
    expect(res.body).toEqual({ token: 'abc' })
  })

  it('POST /2fa/login calls ctrl.verifyLogin2FA', async () => {
    (ctrl.verifyLogin2FA as jest.Mock).mockImplementation((req, res) => res.json({ success: true }))

    const res = await request(app)
      .post('/api/v1/auth/2fa/login')
      .send({ tempToken: 'tmp', code: '123' })

    expect(ctrl.verifyLogin2FA).toHaveBeenCalled()
    expect(res.body).toEqual({ success: true })
  })

  it('POST /refresh calls ctrl.refresh', async () => {
    (ctrl.refresh as jest.Mock).mockImplementation((req, res) => res.json({ token: 'new' }))

    const res = await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: 'ref-1' })

    expect(ctrl.refresh).toHaveBeenCalled()
    expect(res.body).toEqual({ token: 'new' })
  })

  it('POST /password-reset/request calls ctrl.requestPasswordReset', async () => {
    (ctrl.requestPasswordReset as jest.Mock).mockImplementation((req, res) => 
      res.json({ message: 'sent' })
    )

    const res = await request(app)
      .post('/api/v1/auth/password-reset/request')
      .send({ email: 'a@b.com' })

    expect(ctrl.requestPasswordReset).toHaveBeenCalled()
    expect(res.body).toEqual({ message: 'sent' })
  })

  it('POST /password-reset/confirm calls ctrl.confirmPasswordReset', async () => {
    (ctrl.confirmPasswordReset as jest.Mock).mockImplementation((req, res) => 
      res.json({ message: 'confirmed' })
    )

    const res = await request(app)
      .post('/api/v1/auth/password-reset/confirm')
      .send({ email: 'a@b.com', code: '123', newPassword: 'newpass' })

    expect(ctrl.confirmPasswordReset).toHaveBeenCalled()
    expect(res.body).toEqual({ message: 'confirmed' })
  })

  it('GET /me calls authenticate and ctrl.me', async () => {
    (ctrl.me as jest.Mock).mockImplementation((req, res) => res.json({ user: 'me' }))

    const res = await request(app).get('/api/v1/auth/me')

    expect(authenticate).toHaveBeenCalled()
    expect(ctrl.me).toHaveBeenCalled()
    expect(res.body).toEqual({ user: 'me' })
  })

  it('POST /logout calls ctrl.logout', async () => {
    (ctrl.logout as jest.Mock).mockImplementation((req, res) => res.status(204).send())

    const res = await request(app)
      .post('/api/v1/auth/logout')
      .send({ refreshToken: 'ref-1' })

    expect(ctrl.logout).toHaveBeenCalled()
    expect(res.status).toBe(204)
  })

  it('POST /otp/request calls ctrl.requestOTP', async () => {
    (ctrl.requestOTP as jest.Mock).mockImplementation((req, res) => res.json({ message: 'otp sent' }))

    const res = await request(app)
      .post('/api/v1/auth/otp/request')
      .send({ email: 'a@b.com' })

    expect(ctrl.requestOTP).toHaveBeenCalled()
    expect(res.body).toEqual({ message: 'otp sent' })
  })

  it('POST /otp/verify calls ctrl.verifyOTP', async () => {
    (ctrl.verifyOTP as jest.Mock).mockImplementation((req, res) => res.json({ verified: true }))

    const res = await request(app)
      .post('/api/v1/auth/otp/verify')
      .send({ email: 'a@b.com', code: '123' })

    expect(ctrl.verifyOTP).toHaveBeenCalled()
    expect(res.body).toEqual({ verified: true })
  })

  it('POST /2fa/enable calls authenticate and ctrl.enable2FA', async () => {
    (ctrl.enable2FA as jest.Mock).mockImplementation((req, res) => res.json({ enabled: true }))

    const res = await request(app).post('/api/v1/auth/2fa/enable')

    expect(authenticate).toHaveBeenCalled()
    expect(ctrl.enable2FA).toHaveBeenCalled()
    expect(res.body).toEqual({ enabled: true })
  })

  it('POST /2fa/verify calls authenticate and ctrl.verify2FA', async () => {
    (ctrl.verify2FA as jest.Mock).mockImplementation((req, res) => res.json({ verified: true }))

    const res = await request(app)
      .post('/api/v1/auth/2fa/verify')
      .send({ code: '123' })

    expect(authenticate).toHaveBeenCalled()
    expect(ctrl.verify2FA).toHaveBeenCalled()
    expect(res.body).toEqual({ verified: true })
  })
})
