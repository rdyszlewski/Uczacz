FROM openjdk:11-jre-slim

WORKDIR /app
COPY ./target/quiz-service-0.0.1-SNAPSHOT.jar /app
EXPOSE 8080

CMD ["java", "-jar", "quiz-service-0.0.1-SNAPSHOT.jar"]