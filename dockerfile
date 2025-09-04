FROM node:22-alpine3.21

WORKDIR /usr/src/app

COPY package*.json ./
COPY pnpm-lock.yaml ./

# Instalar pnpm globalmente
RUN npm install -g pnpm

RUN pnpm install 

COPY . .


EXPOSE 3001
