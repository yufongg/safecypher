echo "Starting Neo4j..."

neo4j-admin dbms set-initial-password hellohello
neo4j start

until cypher-shell -u neo4j -p hellohello "RETURN 'Neo4j is up.'"; do
  >&2 echo "Neo4j is unavailable - sleeping"
  sleep 1
done

# Execute Cypher script to initialize data
cypher-shell -u neo4j -p hellohello < /var/lib/neo4j/import/init.cql
neo4j stop

# Set internet connectivity
echo 'nameserver 8.8.8.8' > /etc/resolv.conf

echo "done"
neo4j console
