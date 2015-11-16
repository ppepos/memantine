dev: mongo

clean:
	sudo docker kill memantine
	sudo docker rm memantine

prod:
	sudo docker build -t memantine
	sudo docker run -i -p 1440:5000 -v ${PWD}/data/data.sqlite:/opt/memantine/src/data.sqlite -t memantine
