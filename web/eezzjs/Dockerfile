FROM node:latest

WORKDIR /app

COPY src /app

COPY start.sh /start.sh


RUN npm install
RUN chmod a+x /start.sh
RUN chown -R node:node /app

EXPOSE 3000

CMD [ "/bin/bash", "/start.sh" ]
