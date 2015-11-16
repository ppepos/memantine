dev: mongo

clean:
	sudo docker kill memantine
	sudo docker rm memantine

prod:
	sudo docker build -t memantine container/prod
	sudo docker run -i -p 1440:5000 -v /opt/memantine/data.sqlite data.sqlite -t memantine
