FROM maven:3.9-eclipse-temurin-21 AS build

WORKDIR /app
COPY . .
RUN mvn -B -DskipTests clean package

FROM eclipse-temurin:21-jre

WORKDIR /app
COPY --from=build /app/target/eudi-pid-qr-generator-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8080
CMD ["sh", "-c", "java -Dserver.port=${PORT:-8080} -jar app.jar"]
