/**
 * Main entrypoint for the backend server
 * 
 * Configures logging, connects to the database, configures the app and
 * starts it running on the configured port.
 */

import express, { Express, Request, Response } from 'express';
import * as Log from 'winston';
import Config from 'config';

import Router from './routes';

// Configure logging
Log.configure({
  level: Config.has('logLevel') ? Config.get('logLevel') : 'info',
  transports: [new Log.transports.Console()],
})

// Read the required configuration
const port = Config.get('http.port') || 8081;

// Create the app
const app = express();
app.use(Router);

// Start listening on the required port
app.listen(port, () => {
  Log.info(`Backend server running on port ${port}`);
});
