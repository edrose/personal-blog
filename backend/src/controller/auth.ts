/**
 * Authentication and authorisation module
 * 
 * Authentication is done using a two token strategy. When a user logs in, they
 * are issued with a refresh token. That refresh token has a long expiry date,
 * and can be used to fetch an access token which has a shorter expiry date.
 * The access token can be used to authenticate API requests.
 * 
 * The refresh token can be stored on the client between sessions, whereas an
 * access token is stored for just the session.
 * 
 * A refresh token contains an ID that is stored in the database, allowing the
 * token to be revoked by the server. The refresh token, on the other hand,
 * cannot be revoked by the server. As such, it has a very short lifetime of
 * just a few hours. The access token contains all of the information needed
 * to authenticate a request without going back to the database, and that
 * data is cryptographically signed. This reduces the load on the database
 * so that database requests are not required for every request.
 */

import { NextFunction, Request, Response } from 'express';
import Config from 'config';
import Jwt from 'jsonwebtoken';
import * as Log from 'winston';
import { access } from 'fs';
import { log } from 'console';
import { User } from '@/models/user';

enum TokenSubject {
  Access,
  Refresh,
}

interface TokenError extends Error {
  statusCode?: number,
}

/**
 * Validate that the provided token is valid
 * 
 * Checks that the token is valid, hasn't expired, and has the correct subject
 * for the intended use.
 * @param token The token to validate
 * @param subject Whether this is a refresh or access token
 * @returns The token payload if it's valid, or a TokenError if not
 */
function ValidateToken(token: string, subject: TokenSubject): Promise<Jwt.JwtPayload> {
  return new Promise((resolve, reject) => {
    Jwt.verify(token, Config.get('auth.jwtSecret'), (error, payload) => {
      if (error) {
        Log.error(`Failed to verify JWT: ${error}`);
        return reject({
          message: error.message,
          name: error.name,
          statusCode: 401,
        } as TokenError);
      }

      // Check that there is a valid payload
      if (!payload) {
        Log.error(`No payload in JWT`);
        return reject({
          message: 'No payload in JWT',
        } as TokenError);
      }

      
      // Check the issuer is correct
      let contents = payload as Jwt.JwtPayload;
      if (contents.iss !== Config.get('auth.issuer')) {
        Log.error(`Invalid token issuer. Expected '${Config.get('auth.issuer')}' but got ${contents.iss}`);
        return reject({
          message: 'Invalid token issuer',
          statusCode: 401,
        } as TokenError);

      }

      // Check the use is correct
      switch (subject) {
        case TokenSubject.Access:
          if (contents.sub !== 'access') {
            return reject({
              message: 'Invalid token subject',
              statusCode: 401,
            } as TokenError);
          }
          break;
        case TokenSubject.Refresh:
          if (contents.sub !== 'refresh') {
            return reject({
              message: 'Invalid token subject',
              statusCode: 401,
            } as TokenError);
          }
          break;
      }

      // Cast the payload to the correct type
      return resolve(payload as Jwt.JwtPayload);
    });
  });
}

/**
 * Authenticate a user and issue a refresh token
 * 
 * Accepts the user's email and password, validates them, and issues a 
 * refresh token than can be used to obtain an access token.
 * @param req 
 * @param res 
 */
export function Login(req: Request, res: Response) {

}

/**
 * Get an access token for a user
 * 
 * Accepts a refresh token, and issues an access token that can be used to
 * authenticate API calls.
 * @param req 
 * @param res 
 */
export function GetAccessToken(req: Request, res: Response) {
  // The refresh token could either be in a cookie, or in the auth header
  let token: string | null = null;
  if (req.cookies['refresh-token']) {
    Log.debug('Getting token from cookie');
    token = req.cookies['refresh-token'];
  } else if (req.headers['authorization']) {
    Log.debug('Getting token from header');
    token = req.headers['authorization'];
  }
  
  // Check that we managed to get a token
  if (!token) {
    return res.sendStatus(401);
  }

  // Validate the token
  ValidateToken(token, TokenSubject.Refresh)
    .then((payload) => {
      // Extract the ID
      let id = payload['id'];

      // TODO Fetch the 
    })
    .catch((err) => {

    });
}

/**
 * Middleware that performs authentication on requests
 * 
 * The access token is pulled out of the request, if it exists, and the jwt
 * is validated. If validation succeeds, the contents of the tokens payload
 * are attached to the User object to allow it to be used in subsequent
 * middlewares.
 * 
 * This does not perform any authorisation! If there is no valid token, the
 * request is still passed to the next middleware, just with a null user.
 * @param req Express request object
 * @param res Express response object
 * @param next Called to pass the request to the next middleware
 */
export function AuthenticateRequest(req: Request, res: Response, next: NextFunction) {
  // Try to extract the token from the request
  let authHeader = req.headers.authorization;
  Log.silly(`HTTP Authorization header contents: ${authHeader}`);
  if (!authHeader) {
    Log.debug(`Authorization header not provided, nothing to authorize`);
    return next();
  }

  // Pull the token out of the header
  let matches = /Bearer (.*)/.exec(authHeader);
  if (!matches) {
    Log.warn("Authorization header does not match expected format")
    return res.sendStatus(401);
  }

  let token = matches.at(1);
  if (!token) {
    Log.warn("Authorization header does not match expected format")
    return res.sendStatus(401);
  }

  // Validate the token
  Jwt.verify(token, Config.get("auth.jwtSecret"), (error, payload) => {
    if (error) {
      Log.error(`Failed to verify JWT: ${error}`);
      return res.sendStatus(401);
    }

    if (!payload) {
      Log.error(`No payload in JWT`);
      return res.sendStatus(401);
    }

    // Cast the poayload to the correct type
    let accessToken = payload as Jwt.JwtPayload;

    // Check the issuer, audience, and subject are valid
    Log.debug(`JWT contents: ${accessToken}`);
    if (accessToken.sub != "access" || accessToken.iss != Config.get("auth.issuer")) {
      Log.info(`JWT has incorrect subject or issuer`);
      return res.sendStatus(401);
    }

    // Construct a user object with the contents
    let user: User = {
      name: accessToken['name'],
      email: accessToken['email'],
      canPublish: accessToken['canPublish'],
    };

    // Check the required fields exist
    if (!user.name || !user.email || !user.canPublish) {
      Log.error(`Token payload missing required fields`)
      return res.sendStatus(401);
    }

    // Attach the user object and allow the request
    Log.debug(`Allowing auth request for ${user.email} to continue`);
    req.user = user;
    return next();
  });
}

/**
 * Middleware for authenticating an admin
 * 
 * Middleware that will only allow the request to proceed if the request is 
 * authenticated and the current user is an admin.
 * @param req 
 * @param res 
 * @param next 
 * @returns 
 */
export function AuthoriseAdmin(req: Request, res: Response, next: NextFunction) {
  // Check that a valid token was provided for an admin account
  if (!req.user || !req.user.canPublish) {
    return res.sendStatus(403);
  }

  return next();
}

/**
 * Middleware for authenticating a user
 * 
 * Middleware that will only allow the request to proceed if the request is 
 * authenticated.
 * @param req 
 * @param res 
 * @param next 
 * @returns 
 */
export function AuthoriseUser(req: Request, res: Response, next: NextFunction) {
  // Check that a valid token was provided
  if (!req.user) {
    return res.sendStatus(403);
  }

  return next();
}