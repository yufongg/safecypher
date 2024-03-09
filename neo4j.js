const express = require('express');
const router = express.Router();
const { neo4j:neo4jConfig } = require('../config.json')
const connection = require('../connection')

neo4jSession = connection.neo4j(neo4jConfig.uri,neo4jConfig.username, neo4jConfig.password, neo4jConfig.database, neo4jConfig.port)

const executeQuery = async (query) => {
    let result = ''
    try {
        result = await neo4jSession.run(query);
        result = result.records
    } catch (e) {
        result = e.toString()
    }
    return result
}

//Run arbitrary query - TRY IT OUT! :)
router.post('/raw', async (req, res) => {
    const query = req.body.query
    if(!query) {
        return next("No query was provided")
    }
    res.send(await executeQuery(query))
})

router.post('/create/characters', async (req, res, next ) => {
    const name = req.body.name
    if(!name){
        return next("No name was provided")
    }
    res.send(await executeQuery(`CREATE (c:Character {name: '${name}'}) return c`))
})

router.post('/create/places', async (req, res, next ) => {
    const name = req.body.name
    if(!name){
        return next("No name was provided")
    }
    res.send(await executeQuery(`CREATE (p:Place {name: '${name}'}) return p`))
})

router.get('/all/characters', async (req, res) => {
    res.send(await executeQuery('MATCH (c:Character) return c'))
})

router.get('/characters/id/:id', async (req, res) => {
    const id = req.params.id
    if(!id){
        return next("No id was provided")
    }
    res.send(await executeQuery('MATCH (c:Character) WHERE id(c) = ' + id + ' RETURN c'))
})

router.get('/places/id/:id', async (req, res) => {
    const id = req.params.id
    if(!id){
        return next("No id was provided")
    }
    res.send(await executeQuery('MATCH (p:Place) WHERE id(p) = ' + id + ' RETURN p'))
})

router.get('/all/places', async (req, res) => {
    res.send(await executeQuery('MATCH (p:Place) return p'))
})

router.get('/characters/name/:name', async (req, res) => {
    const name = req.params.name
    if(!name){
        return next("No name was provided")
    }
    res.send(await executeQuery("MATCH (c:Character) WHERE c.name = '" + name + "' RETURN c"))
})

router.get('/places/name/:name', async (req, res) => {
    const name = req.params.name
    if(!name){
        return next("No name was provided")
    }
    res.send(await executeQuery("MATCH (p:Place) WHERE p.name = '" + name + "' RETURN p"))
})

router.delete('/places/id/:id', async (req, res) => {
    const id = req.params.id
    if(!id){
        return next("No id was provided")
    }
    res.send(await executeQuery("MATCH (p:Place) WHERE ID(p) = " + id + " DETACH DELETE p"))
})

router.delete('/characters/id/:id', async (req, res) => {
    const id = req.params.id
    if(!id){
        return next("No id was provided")
    }
    res.send(await executeQuery("MATCH (c:Character) WHERE ID(c) = " + id + " DETACH DELETE c"))
})

router.get('/all', async (req, res) => {
    res.send(await executeQuery('MATCH (c:Character) MATCH (p:Place) RETURN c,p'))
})

//Top secret route!
router.get('/internal-api/keys.txt', async (req, res) => {
    const secret = "Krabby Patty Secret Formula - DO NOT EXPOSE AT ANY CIRCUMSTANCES"
    res.send(secret)
})

router.route('/characters')
    .get(async (req, res) => {
        const id = req.query.id;
        const name = req.query.name;

        if (!id && !name) {
            return res.status(400).json({ error: "No id or name was provided" });
        }

        if (id) {
            // Query by id
            res.send(await executeQuery('MATCH (c:Character) WHERE id(c) = ' + id + ' RETURN c'));
        } else {
            // Query by name
            res.send(await executeQuery("MATCH (c:Character) WHERE c.name = '" + name + "' RETURN c"));
        }
    })
    .post(async (req, res) => {
        const id = req.body.id;
        const name = req.body.name;

        if (!id && !name) {
            return res.status(400).json({ error: "No id or name was provided" });
        }

        if (id) {
            // Check if id is provided, then query by id
            res.send(await executeQuery('MATCH (c:Character) WHERE id(c) = ' + id + ' RETURN c'));
        } else {
            // Otherwise, query by name
            res.send(await executeQuery("MATCH (c:Character) WHERE c.name = '" + name + "' RETURN c"));
        }
    });

router.route('/places')
    .get(async (req, res) => {
        const id = req.query.id;
        const name = req.query.name;

        if (!id && !name) {
            return res.status(400).json({ error: "No id or name was provided" });
        }

        if (id) {
            // Query by id
            res.send(await executeQuery('MATCH (p:Place) WHERE id(p) = ' + id + ' RETURN p'));
        } else {
            // Query by name
            res.send(await executeQuery("MATCH (p:Place) WHERE p.name = '" + name + "' RETURN p"));
        }
    })
    .post(async (req, res) => {
        const id = req.body.id;
        const name = req.body.name;

        if (!id && !name) {
            return res.status(400).json({ error: "No id or name was provided" });
        }

        if (id) {
            // Check if id is provided, then query by id
            res.send(await executeQuery('MATCH (p:Place) WHERE id(p) = ' + id + ' RETURN p'));
        } else {
            // Otherwise, query by name
            res.send(await executeQuery("MATCH (p:Place) WHERE p.name = '" + name + "' RETURN p"));
        }
    });

module.exports = router;