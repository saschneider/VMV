# Trusted and Transparent Voting Systems: Verify My Vote Demonstrator

This repository contains the Spring Boot application which runs the Trusted and Transparent Voting Systems: Verify My Vote Demonstrator VMV component. The demonstrator is used to implement verifiable voting. A full description of the requirements and high-level design can be found in (Casey, 2018).

## Prerequisites

The Spring Boot application requires Java 1.8.

If the application is being used to create and run tellers, then the Verificatum applications must also be installed. Note that to run the unit tests, Verificatum is required. VMV was tested with Verificatum version 3.0.3. For details on how to install Verificatum, see (Wikström, 2018).

## Building the JAR

Build the application JAR file and documentation using:
* Edit pom.xml to set the application version. This can be found in the `version` for the `project`. 
* Run `./mvnw clean package`. This will run all of the tests for the project and build the JAR file, placing it in the `target` directory. The JAR file will be named `'vmv-x.x.x.jar` where `x.x.x` matches to the version number set in the `pom.xml` file. Adding `-Dmaven.test.skip=true` will skip running the unit tests during the build.
* Run `./mvnw javadoc:jar`. This will build the JavaDoc JAR file and place it in the `target` directory. The JAR file will be named `'vmv-x.x.x-javadoc.jar` where `x.x.x` matches to the version number set in the `pom.xml` file.

## Running the Shell

The application and its dependencies are fully contained within the `vmv-x.x.x.jar` JAR file, where `x.x.x` refers to the software version.

To run the application, execute:
* `java -jar vmv-x.x.x.jar`

Help on the available commands can then be obtained using `help`. 

Alternatively, the sequence of commands needed to initialise an election can be run using:
* On teller 1 (assumed to be a secure computer with access to the plaintext votes):
```shell
election_initialisation.exp vmv_jar_file ssh_key_file sftp_host sftp_user "election_name" number_of_tellers threshold_tellers teller teller_ip teller_main_port teller_hint_port number_of_voters "ers_voters_file" "ers_associated_voters_file"
```
* On every other teller:
```shell
election_initialisation.exp vmv_jar_file ssh_key_file sftp_host sftp_user "election_name" number_of_tellers threshold_tellers teller teller_ip teller_main_port teller_hint_port
```

Once the election is complete and ready for encryption and mixing, this can then be completed using the following:
* On teller 1 (assumed to be a secure computer with access to the plaintext votes):
```shell
election_encrypt.exp vmv_jar_file ssh_key_file sftp_host sftp_user "election_name" number_of_tellers teller "ers_plaintext_voters_file" "ers_encrypted_voters_file"
```
* On every other teller:
```shell
election_encrypt.exp vmv_jar_file ssh_key_file sftp_host sftp_user "election_name" number_of_tellers teller
```

where
* `vmv_jar_file` is the full path to the VMV JAR file
* `ssh_key_file` is the full path to the SFTP key file needed for the SFTP server
* `sftp_host` the SFTP host domain name or IP address
* `sftp_user` the SFTP user name
* `election_name` is the (unique) election name
* `number_of_tellers` is the number of tellers being used in the election
* `threshold_tellers` is the threshold of tellers needed for teller operations
* `teller` is the local teller number
* `teller_ip` is the publicly accessible IP address for the local teller
* `teller_main_port` is the main port on which Verificatum will listen for teller operations
* `teller_hint_port` is the hint port on which Verificatum will advertise that it is available
* `number_of_voters` is the maximum number of voters in the election
* `ers_voters_file` is the import file containing the ERS voter identifiers
* `ers_associated_voters_file` is the export file which will contain voter parameters associated with ERS voters
* `ers_plaintext_voters_file` is the import file containing the ERS voters with their plaintext votes
* `ers_encrypted_voters_file` is the export file which will contain encrypted votes associated with ERS voters

The above needs Verificatum installed, as well as access to an SFTP server which is accessed by using the `ssh_key_file`, `sftp_host` and `sftp_user`. Note that no password should be required for the SFTP server.

## Testing the Shell

The application can be run to test the shell on a single machine using the following steps:
* Create the test ERS voter identifiers:
```shell
voters=10
echo "\"id\"" > ers-voters.csv
for i in $(seq 1 $voters)
do
  echo "$i" >> ers-voters.csv
done
```
* A separate shell can then be used to run the initialisation for teller 1, which will also record the start and end time:
```shell
file=1i.out
vmv_path="/full/path/to/vmv-x.x.x.jar"
key_path="/full/path/to/key_file"
name="Test Election"
user="user"
tellers=4
threshold=3
teller=1
main_port=8081
hint_port=4041
( nice date > $file ; nohup nice ./election_initialisation.exp $vmv_path $key_path localhost $user "$name" $tellers $threshold $teller 127.0.0.1 $main_port $hint_port $voters ers-voters.csv ers-associated-voters.csv >> $file ; nice date >> $file ) &
```
* While separate shells for each other teller also run the initialisation (illustrated here for teller 2):
```shell
voters=...
file=2i.out
vmv_path=...
key_path=...
name=...
user=...
tellers=4
threshold=3
teller=2
main_port=8082
hint_port=4042
( nice date > $file ; nohup nice ./election_initialisation.exp $vmv_path $key_path localhost $user "$name" $tellers $threshold $teller 127.0.0.1 $main_port $hint_port $voters >> $file ; nice date >> $file ) &
```
* Once initialised, create the plain text votes:
```shell
echo "\"plainTextVote\"" > plaintextvote.csv
for i in $(seq 1 $voters)
do
   echo "$i" >> plaintextvote.csv
done
paste -d',' <(cut -d',' -f-2 ers-associated-voters.csv) plaintextvote.csv <(cut -d',' -f3- ers-associated-voters.csv) > ers-plaintext-voters.csv
```
* Using the separate shell for teller 1, encrypt the votes:
```shell
file=1e.out
teller=1
( nice date > $file ; nohup nice ./election_encrypt.exp $vmv_path $key_path localhost $user "$name" $tellers $teller ers-plaintext-voters.csv ers-encrypted-voters.csv >> $file ; nice date >> $file ) &
```
* While the separate shells for the other tellers also run the encryption (illustrated here for teller 2):
```shell
file=2e.out
teller=2
( nice date > $file ; nohup nice ./election_encrypt.exp $vmv_path $key_path localhost $user "$name" $tellers $teller >> $file ; nice date >> $file ) &
```

## Docker Deployment
The production application can be deployed as a docker image to allow the app to be run via Docker. The image contains both the application and Verificatum.

To build the bespoke image, do the following:
* Commit all changes to git
* Ensure Docker is running
* `docker-compose build --build-arg JAR_FILE=target/vmv-x.x.x.jar`

The `x.x.x` must be replaced with the current version of the application.

To save the resulting image for deployment to a different machine:
* `docker save vmv_crypto | gzip > crypto.tar.gz`
* Move the image to the target machine
* Ensure Docker is running
* `docker load < crypto.tar.gz`

The image can now be used to run the application using:
```shell
docker run -p 8080:8080 -p 4040:4040 -it vmv_crypto java -jar /app/app.jar
```

This will automatically assume that the main and hint ports used by Verificatum are 8080 and 4040 and expose and publish these to the same ports on the host.  

Alternatively, as above, the sequence of commands needed to initialise an election can be run using:
* On teller 1 (assumed to be a secure computer with access to the plaintext votes):
```shell
docker network create --driver bridge teller_network
docker create -v "$PWD"/files:/app/files -it --network=teller_network --name=teller<teller> -p 8080:8080 -p 4040:4040 vmv_crypto
docker start teller<teller>
docker exec -it teller1 expect election_initialisation.exp /app/app.jar /app/files/key_file sftp_host sftp_user "election_name" number_of_tellers threshold_tellers teller teller_ip teller_main_port teller_hint_port number_of_voters "files/ers_voters_file" "files/ers_associated_voters_file" 
```
* On every other teller:
```shell
docker network create --driver bridge teller_network
docker create -v "$PWD"/files:/app/files -it --network=teller_network --name=teller<teller> -p 8080:8080 -p 4040:4040 vmv_crypto
docker start teller<teller>
docker exec -it teller<teller> expect election_initialisation.exp /app/app.jar /app/files/key_file sftp_host sftp_user "election_name" number_of_tellers threshold_tellers teller teller_ip teller_main_port teller_hint_port number_of_voters
```

Once the election is complete and ready for encryption and mixing, this can then be completed using the following:
* On teller 1 (assumed to be a secure computer with access to the plaintext votes):
```shell
docker exec -it teller<teller> expect election_encrypt.exp /app/app.jar /app/files/key_file sftp_host sftp_user "election_name" number_of_tellers teller "files/ers_plaintext_voters_file" "files/ers_encrypted_voters_file"
docker stop teller<teller>
docker network rm teller_network
```
* On every other teller:
```shell
docker exec -it teller<teller> expect election_encrypt.exp /app/app.jar /app/files/key_file sftp_host sftp_user "election_name" number_of_tellers teller
docker stop teller<teller>
docker network rm teller_network
```

where
* the local `files` directory has been created and the `key_file` placed within it
* for teller 1, the `files` directory also contains the `ers_voters_file` and `ers_plaintext_voters_file` files, and will contain the corresponding output files

Details of the other parameters can be found above.

Note that Docker needs to be run with the `-it` flag in order for the `expect` scripts to run correctly. If this flag is not supplied, the `expect` scripts will fail in an infinite loop when attempting to send commands to the Java command line. 

On each teller, the series of commands will create a dedicated bridge network for use by a named container, which is created. The container assumes that the main and hint ports for Verificatum are published to 8080 and 4040, respectively. The `teller_ip` must be the IP address at which the running container can be accessed. Once the container is created it is started and the initialisation and encryption commands can be run. When complete, the container can be stopped and and the network deleted.

Since each teller contains a share of the private election encryption key and other teller-specific data, it is prudent to backup each teller after each election stage. To backup a teller, execute the following:
```shell
docker commit -p teller<teller> backup
docker save backup | gzip > backup.tar.gz
```

where
* `backup` is a suitable name for the backup, such as a sequential number or date

This will commit the running container as an image and then save the image to a file which can be restored using load:
```shell
docker load < <backup>.tar.gz
```

### Example Docker Deployment on a Single Computer

The following shows how a network of 4 tellers can be executed using Docker on a single computer:

```shell
docker network create --driver bridge teller_network
docker create -v "$PWD"/files:/app/files -it --network=teller_network --name=teller1 vmv_crypto
docker create -v "$PWD"/files:/app/files -it --network=teller_network --name=teller2 vmv_crypto
docker create -v "$PWD"/files:/app/files -it --network=teller_network --name=teller3 vmv_crypto
docker create -v "$PWD"/files:/app/files -it --network=teller_network --name=teller4 vmv_crypto

docker start teller1
docker start teller2
docker start teller3
docker start teller4
```

Each line of the following should then be executed via a different terminal session or in the background:
```shell
docker exec -it teller1 expect election_initialisation.exp /app/app.jar /app/files/key_file sftp_host sftp_user "election_name" 4 3 1 teller1 8080 4040 number_of_voters "files/ers_voters_file" "files/ers_associated_voters_file" 
docker exec -it teller2 expect election_initialisation.exp /app/app.jar /app/files/key_file sftp_host sftp_user "election_name" 4 3 2 teller2 8080 4040 number_of_voters
docker exec -it teller3 expect election_initialisation.exp /app/app.jar /app/files/key_file sftp_host sftp_user "election_name" 4 3 3 teller3 8080 4040 number_of_voters
docker exec -it teller4 expect election_initialisation.exp /app/app.jar /app/files/key_file sftp_host sftp_user "election_name" 4 3 4 teller4 8080 4040 number_of_voters
```

Similarly, once the plaintext votes files has been generated:
```shell
docker exec -it teller1 expect election_encrypt.exp /app/app.jar /app/files/key_file sftp_host sftp_user "election_name" 4 1 "files/ers_plaintext_voters_file" "files/ers_encrypted_voters_file"
docker exec -it teller2 expect election_encrypt.exp /app/app.jar /app/files/key_file sftp_host sftp_user "election_name" 4 2
docker exec -it teller3 expect election_encrypt.exp /app/app.jar /app/files/key_file sftp_host sftp_user "election_name" 4 3
docker exec -it teller4 expect election_encrypt.exp /app/app.jar /app/files/key_file sftp_host sftp_user "election_name" 4 4
```

Finally, the tellers can be stopped using the following:
```shell
docker stop teller1
docker stop teller2
docker stop teller3
docker stop teller4

docker network rm teller_network
```

where
* the local `files` directory has been created and the `key_file` placed within it
* for teller 1, the `files` directory also contains the `ers_voters_file` and `ers_plaintext_voters_file` files, and will contain the corresponding output files

Details of the other parameters can be found above.

## References

M. C. Casey, "Trusted and Transparent Voting Systems: Verify My Vote Demonstrator Requirements and Design," 2018.

D. Wikström, available online: "https://www.verificatum.com/, 2018
