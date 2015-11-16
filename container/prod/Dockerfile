FROM ubuntu:trusty
Maintainer Philippe Pepos Petitclerc <ppeposp@gmail.com>

RUN apt-get update
RUN apt-get install -y python python-pip git

RUN git clone https://github.com/ppepos/memantine /opt/memantine
RUN mkdir -p /etc/memantine
COPY prod.key /etc/memantine/prod.key

RUN pip install -r /opt/memantine/requirements.txt

CMD 	export MEMANTINE_SECRET=$(cat /etc/memantine/prod.key) && \
	python /opt/memantine/src/app.py runserver -D -R --threaded -h 0.0.0.0
