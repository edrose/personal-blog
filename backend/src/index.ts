/**
 * Main entrypoint for the backend server
 * 
 * Configures logging, connects to the database, configures the app and
 * starts it running on the configured port.
 */

import express, { Express, Request, Response } from 'express';
import CookieParser from 'cookie-parser';
import Mongoose from 'mongoose';
import * as Log from 'winston';
import Config from 'config';

import Router from './routes';

console.log("Starting app...")

// Configure logging
Log.configure({
  level: Config.has('logLevel') ? Config.get('logLevel') : 'info',
  transports: [new Log.transports.Console()],
  format: Log.format.combine(Log.format.simple(), Log.format.colorize()),
})

// Read the required configuration
const port = Config.get('http.port') || 8081;

// Create the app
const app = express();
app.use(CookieParser());
app.use(Router);

// Connect to mongo
Log.debug(`Connecting to mongodb with '${Config.get('mongoUrl')}`);
Mongoose.connect(Config.get('mongoUrl'),
  {
    user: "root",
    pass: "example",
    authSource: "admin"
  }
)
  .then((a) => {
    Log.debug("Connected to Mongo")
    // Start listening on the required port
    app.listen(port, () => {
      Log.info(`Backend server running on port ${port}`);
    });
  })
  .catch((err) => Log.error(`Failed to connect to mongodb: ${err}`));

