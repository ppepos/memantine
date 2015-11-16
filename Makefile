dev: mongo

clean:
	sudo docker kill memantine
	sudo docker rm memantine

prod:
	sudo docker build -t memantine container/prod
	sudo docker run -d -p 1440:5000 -v ${PWD}/src/db:/opt/memantine/src/db -t memantine
