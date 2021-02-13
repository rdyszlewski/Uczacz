FROM openjdk:11-jre-slim

WORKDIR /app
COPY ./target/gateway-uczacz-0.0.1-SNAPSHOT.jar /app
EXPOSE 8080

CMD ["java", "-jar", "gateway-uczacz-0.0.1-SNAPSHOT.jar"]