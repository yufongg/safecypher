CREATE (u:User {username: 'admin', password: 'password'});
CREATE (k:Keyboard {name: 'Kohaku', description: 'Singakbd'})
CREATE (k1:Keyboard {name: '50FE', description: 'Hex Keyboards'});
CREATE (k2:Keyboard {name: 'Oku', description: 'NRD Designs'})

// Create Characters
CREATE (walter:Character {name: "Walter White", alias: "Heisenberg", occupation: "Chemistry Teacher turned Meth Producer"})
CREATE (jesse:Character {name: "Jesse Pinkman", occupation: "Meth Producer"})
CREATE (hank:Character {name: "Hank Schrader", occupation: "DEA Agent"})
CREATE (skyler:Character {name: "Skyler White", occupation: "Accountant"})
CREATE (saul:Character {name: "Saul Goodman", alias: "Jimmy McGill", occupation: "Lawyer"})

// Create Places
CREATE (carWash:Place {name: "A1A Car Wash"})
CREATE (pollos:Place {name: "Los Pollos Hermanos"})
CREATE (saulOffice:Place {name: "Saul Goodman & Associates"})

// Create Organizations
CREATE (dea:Organization {name: "DEA"})
CREATE (madrigal:Organization {name: "Madrigal Electromotive"})

// Define Relationships between Characters
CREATE (walter)-[:FAMILY]->(skyler)
CREATE (walter)-[:PARTNER]->(jesse)
CREATE (walter)-[:ENEMY]->(hank)
CREATE (jesse)-[:FRIEND]->(walter)
CREATE (hank)-[:WORKS_FOR]->(dea)

// Characters to Places
CREATE (walter)-[:OWNS]->(carWash)
CREATE (jesse)-[:VISITS]->(pollos)
CREATE (saul)-[:OWNS]->(saulOffice)

// Additional Relationships
CREATE (saul)-[:LAWYER_FOR]->(walter)
CREATE (saul)-[:LAWYER_FOR]->(jesse)
CREATE (walter)-[:WORKS_FOR]->(madrigal)
