dev: mongo

clean:
	sudo docker kill mongodb-memantine
	sudo docker rm mongodb-memantine
	sudo docker kill memantine
	sudo docker rm memantine

setup:
	sudo docker pull mongo

mongo:
	sudo docker run -d -p 27017:27017 -v ${PWD}/data/db:/data/db --name mongodb-memantine mongo

prod-mongo:
	sudo docker run -d -v ${PWD}/data/db:/data/db --name mongodb-memantine dockerfile/mongodb

prod:
	sudo docker build -t memantine container/prod
	sudo docker run -i -p 1440:5000 --link mongodb-memantine:mongodb -t memantine
