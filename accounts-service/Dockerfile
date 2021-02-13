FROM openjdk:11-jre-slim

WORKDIR /app
COPY ./target/users-service-0.0.1-SNAPSHOT.jar /app
EXPOSE 8080

CMD ["java", "-jar", "users-service-0.0.1-SNAPSHOT.jar"]