## Stage 1: Build
#1 select the build image of python
FROM python:3.11-slim as builder

#2 Mention the workdir from where the file will be collected by COPY command
# /app should contain requirements.txt file and main.py the main application file
WORKDIR /app

#3 copy it from /app directory
COPY app/requirements.txt .

#4 install dependencies of python app
# like pip upgrade and other packages from the requirements.txt file
# --user will copy the binary file in /root/.local/bin directory
# and all the libraries in /root/.local/lib directory
RUN pip install --upgrade pip \
	&& pip install --user -r requirements.txt


## Stage2:

#1 select the app image of python
FROM python:3.11-slim

#2 set the environment variable to run the commands
ENV PATH="/root/.local/bin:$PATH"

#3 mention the work directory
WORKDIR /app

#4 copy the environment from the builder image to the final image
COPY --from=builder /root/.local /root/.local

#5 copy everything or just the main.py to the /app location of the final image
COPY app /app

#6 run the python app
CMD ["python", "main.py"]

