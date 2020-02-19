# File to execute a series of commands in a remote machine. Useful for automting tasks like installing programs, 
#copying files, cloning git repos, restarting processes, etc.
# The definition of each line is: command, execute as sudo [true/false] 
# when executing as sudo the command will be executed as 'sudo -S -p %s', whereas %s is the command passed. 
# The Password prompt will be handled as plain text via the standard input.

docker pull shinojosa/bankjob:perform2020, False
docker stop bankjob, False
docker rm bankjob, False
docker run -d --name bankjob shinojosa/bankjob:perform2020, False