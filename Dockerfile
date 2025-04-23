FROM node
COPY ./DPdoc/package.json /app/package.json
WORKDIR /app
RUN npm install
