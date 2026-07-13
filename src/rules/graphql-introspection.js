const { ApolloServer } = require('@apollo/server');

// ruleid: patronus-graphql-introspection-enabled
const server = new ApolloServer({ typeDefs, resolvers, introspection: true });

// ok: patronus-graphql-introspection-enabled
const safeServer = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
});
