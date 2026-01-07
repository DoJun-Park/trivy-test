FROM node:22.17.1-alpine AS builder

RUN mkdir /usr/app
WORKDIR /usr/app

COPY package*.json ./

RUN npm install --production=false

COPY . .

FROM node:22.17.1-alpine

RUN mkdir /usr/app
WORKDIR /usr/app

RUN apk add --no-cache tini tzdata
RUN mkdir /var/log/nodejs
RUN chown node:node /var/log/nodejs

COPY --from=builder /usr/app/package*.json ./
COPY --from=builder /usr/app/node_modules ./node_modules
COPY --from=builder /usr/app/index.js ./

RUN npm prune --omit=dev

USER node

EXPOSE 3000

ENTRYPOINT ["/sbin/tini", "--"]

CMD ["node", "index.js"]
