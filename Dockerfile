# Build stage
FROM maven:3.8.8-eclipse-temurin-17 as build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn -DskipTests package -DskipTests=true

# Runtime stage
FROM eclipse-temurin:17-jdk-jammy
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
ENV PORT 8080
EXPOSE 8080
CMD ["sh", "-c", "java -Dserver.port=${PORT} -jar /app/app.jar"]
