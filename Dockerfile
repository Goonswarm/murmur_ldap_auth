FROM ubuntu:16.04
MAINTAINER Vincent Ambo <tazjin@gmail.com>

# Add ZeroC repository
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv 5E6DA83306132997 && \
    echo "deb http://zeroc.com/download/apt/ubuntu16.04 stable main" > /etc/apt/sources.list.d/zeroc.list &&  \
    apt-get update

# Install dependencies
RUN apt-get install -y openjdk-8-jdk-headless gradle zeroc-ice-all-runtime \
     zeroc-ice-all-dev libzeroc-ice-java && \
    apt-get clean

# Add source and compile it
ADD . /opt/murmur_ldap_auth
WORKDIR /opt/murmur_ldap_auth
RUN gradle shadowJar

ENTRYPOINT ["java", "-jar", "build/libs/murmur_ldap_auth-1.0-SNAPSHOT-all.jar"]
