#Dockerize an SSH service

Image to test locally SSH connections with Paramiko.

https://docs.docker.com/engine/examples/running_ssh_service/

docker build -t eg_sshd .

docker run -d -P --name test_sshd eg_sshd

docker port test_sshd 22