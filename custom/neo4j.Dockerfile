# Extend the official Neo4j 5.18 Docker image
FROM neo4j:5.18

COPY ./neo4j/neo4j.conf /var/lib/neo4j/conf/neo4j.conf
