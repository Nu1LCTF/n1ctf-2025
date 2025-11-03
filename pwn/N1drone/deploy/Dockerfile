FROM px4io/px4-dev-simulation-jammy:2024-05-18

RUN apt update && apt install libgz-sim8 \
	libgz-sim8-plugins \
	libgz-physics7-dartsim-dev socat -y && \
	useradd -m ctf

COPY ./deploy.tar.gz /home/ctf
RUN tar -xzvf /home/ctf/deploy.tar.gz -C /home/ctf

WORKDIR /home/ctf

RUN cp ./libOpticalFlow.so /lib/x86_64-linux-gnu/libOpticalFlow.so && \
	cp ./docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh && \
	chmod +x /usr/local/bin/docker-entrypoint.sh && \
	chmod +x ./bin/px4

ENV PX4_SIM_MODEL=gz_x500 \
	HEADLESS=1 \
	PX4_SIMULATOR=gz \
	PX4_GZ_MODELS=/home/ctf/gz/models \
	PX4_GZ_WORLDS=/home/ctf/gz/worlds \
	PX4_GZ_PLUGINS=/home/ctf/gz/gz_plugins \
	PX4_GZ_SERVER_CONFIG=/home/ctf/gz/server.config

ENV	GZ_SIM_RESOURCE_PATH=$PX4_GZ_MODELS:$PX4_GZ_WORLDS \
	GZ_SIM_SYSTEM_PLUGIN_PATH=$PX4_GZ_PLUGINS \
	GZ_SIM_SERVER_CONFIG_PATH=$PX4_GZ_SERVER_CONFIG

USER ctf

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
