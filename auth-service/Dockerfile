FROM node:20-alpine

WORKDIR /app

RUN npm install -g pnpm

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./

COPY prisma ./prisma/

RUN pnpm install 

COPY src ./src
COPY tsconfig.json ./

RUN pnpm prisma:generate

EXPOSE 3001

CMD ["pnpm", "dev"]
