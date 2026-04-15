FROM node:18-alpine

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install

COPY . .

# We drop privileges to prevent Docker escape
USER node

EXPOSE 8080
CMD ["npm", "start"]
