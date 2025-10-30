import { mockDeep, mockReset, DeepMockProxy } from 'jest-mock-extended'
import { PrismaClient } from '@prisma/client'

export const prismaMock = mockDeep<PrismaClient>()

jest.mock('../prisma/client.prisma.ts', () => ({
  __esModule: true,
  default: prismaMock,
}))
