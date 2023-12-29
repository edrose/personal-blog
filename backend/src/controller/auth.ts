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
import * as Bcrypt from 'bcrypt';
import Jwt from 'jsonwebtoken';
import * as Log from 'winston';

import { UserModel } from '@/models';
import { User, UserRole, UserToken } from '@/models/user';

enum TokenSubject {
  Access = 'access',
  Refresh = 'refresh',
}

interface TokenError extends Error {
  statusCode?: number,
}

/**
 * @brief Issue a new refresh token to a user 
 * @param user User to issue a token for
 * @returns A string containing the refresh token for the user
 */
async function IssueRefreshToken(user: User): Promise<string> {
  // Generate a new uuid for this token
  let expiry = new Date();
  expiry.setSeconds(expiry.getSeconds() + Config.get<number>('auth.refreshTokenExpiry'));

  let token_document = user.tokens.create({ expiry });
  user.tokens.push(token_document);
  return user.save()
    .then(() => new Promise((resolve, reject) => {
      Jwt.sign(
        { id: token_document.id },
        Config.get<string>('auth.jwtSecret'),
        {
          algorithm: 'HS256',
          subject: 'refresh',
          issuer: Config.get('auth.issuer'),
        },
        (error, token) => {
          if (error) {
            reject(error);
          } else if (!token) {
            reject(new Error('NoTokenProduced'));
          } else {
            resolve(token);
          }
        },
      );
    })
  );
}

/**
 * @brief Issue an access token to a user
 * @param user User to issue the token for
 * @returns A string containing the access token
 */
function IssueAccessToken(user: User): Promise<String> {
  return new Promise((resolve, reject) => {
    Jwt.sign(
      {
        name: user.name,
        email: user.email,
        role: user.role,
      },
      Config.get<string>('auth.jwtSecret'),
      {
        algorithm: 'HS256',
        subject: 'access',
        expiresIn: Config.get<number>('auth.accessTokenExpiry')  * 1000,
        issuer: Config.get('auth.issuer'),
      },
      (error, token) => {
        if (error) {
          reject(error);
        } else if (!token) {
          reject(new Error('NoTokenProduced'));
        } else {
          resolve(token);
        }
      },
    );
  });
}

/**
 * @brief Validate that the provided token is valid
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
 * @brief Authenticate a user and issue a refresh token
 * 
 * Accepts the user's email and password, validates them, and issues a 
 * refresh token than can be used to obtain an access token.
 * @param req Express request object
 * @param res Express response object
 */
export async function Login(req: Request, res: Response) {
  // Fetch the username and password from the request
  if (req.headers.authorization) {
    const base64Credentials = req.headers.authorization.split(' ')[1];
    const [username, password] = Buffer.from(base64Credentials, 'base64')
                                       .toString('utf8')
                                       .split(':');
    
    // Find the user document in mongo
    const user = await UserModel.findOne({ email: username });
    if (user && !!user.passwordHash) {
      if (await Bcrypt.compare(password, user.passwordHash)) {
        // Password correct, issue a refresh token
        let token = await IssueRefreshToken(user);

        // If the cookie query parameter is set, just set a cookie.
        if (req.query['cookie']) {
          res.cookie('refresh_token', token, {
            httpOnly: true,
            secure: true,
            maxAge: Config.get<number>('auth.refreshTokenExpiry') * 1000,
          })
          return res.sendStatus(204);
        } else {
          // Otherwise just return the token
          return res.send(token);
        }
      } else {
        Log.debug(`Password for user ${username} incorrect`);
        return res.sendStatus(401);
      }
    } else {
      Log.debug(`Username '${username}' not found in database`);
      return res.sendStatus(401);
    }
  } else {
      Log.debug('No authentication header provided');
      return res.sendStatus(401);
  }
}

/**
 * @brief Get an access token for a user
 * 
 * Accepts a refresh token, and issues an access token that can be used to
 * authenticate API calls.
 * @param req Express request object
 * @param res Express response object
 */
export function GetAccessToken(req: Request, res: Response) {
  // The refresh token could either be in a cookie, or in the auth header
  let token: string | null = null;
  if (req.cookies['refresh_token']) {
    Log.debug('Getting token from cookie');
    token = req.cookies['refresh_token'];
  } else if (req.headers['authorization']) {
    Log.debug('Getting token from header');
    token = req.headers['authorization'];
  }
  
  // Check that we managed to get a token
  if (!token) {
    return res.sendStatus(401);
  }

  // The token id
  let id: String | null = null;

  // Validate the token
  ValidateToken(token, TokenSubject.Refresh)
    .then((payload) => {
      // Extract the ID
      id = payload['id'];

      // Fetch the refresh token entry
      return UserModel.findOne({ "tokens._id": id });
    })
    .then((user) => {
      if (!user) {
        Log.debug('Unable to find refresh token with ID')
        throw new Error("InvalidToken");
      }

      // Check the token expiry
      let token = user.tokens.find((t) => t._id == id);
      if (!token) {
        Log.error("Token not found second time around");
        throw "";
      }

      // Issue the access token
      return IssueAccessToken(user);
    })
    .then((token) => res.send(token))
    .catch((err) => {
      if (err.message && err.message == "InvalidToken") {
        res.sendStatus(401);
      } else {
        Log.error(`Error  in GetAccessToken: ${err}`);
        res.sendStatus(500);
      }
    });
}

/**
 * @brief Middleware that performs authentication on requests
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
    let user: UserToken = {
      name: accessToken['name'],
      email: accessToken['email'],
      role: accessToken['role'],
    };

    // Check the required fields exist
    if (!user.name || !user.email || !user.role) {
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
 * @brief Middleware for authenticating an admin
 * 
 * Middleware that will only allow the request to proceed if the request is 
 * authenticated and the current user is an admin.
 * @param req Express request object
 * @param res Express response object
 * @param next Express next function
 * @returns 
 */
export function AuthoriseAdmin(req: Request, res: Response, next: NextFunction) {
  // Check that a valid token was provided for an admin account
  if (!req.user || req.user.role !== UserRole.Admin) {
    return res.sendStatus(403);
  }

  return next();
}

/**
 * @brief Middleware for authenticating a user
 * 
 * Middleware that will only allow the request to proceed if the request is 
 * authenticated.
 * @param req Express request object
 * @param res Express response object
 * @param next Express next function
 */
export function AuthoriseUser(req: Request, res: Response, next: NextFunction) {
  // Check that a valid token was provided
  if (!req.user) {
    return res.sendStatus(403);
  }

  return next();
}

/**
 * @brief Fetch information about the currently logged in user
 * @param req Express request object
 * @param res Express response object
 */
export function GetUser(req: Request, res: Response) {
  res.json(req.user);
}