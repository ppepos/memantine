dev: mongo

clean:
	sudo docker kill mongodb-memantine
	sudo docker rm mongodb-memantine

setup:
	sudo docker pull dockerfile/mongodb

mongo:
	sudo docker run -d -p 27017:27017 -v ${PWD}/data/db:/data/db --name mongodb-memantine dockerfile/mongodb

