/**
 * Controller module index
 * 
 * Contains common controllers, and re-exports the submodules under the same
 * namespace
 */

import { Request, Response } from 'express';
import * as Log from 'winston';

import * as Auth from './auth';
import * as Menu from './menu';

export enum HttpMethods {
  Get,
  Put,
  Post,
  Delete,
  Head,
  Options,
}

export function ErrorHandler(req: Request, res: Response, error: any) {
  Log.error(`Error occurred handling '${req.path}': ${error}`);
  res.sendStatus(500);
}

export function NotImplemented(req: Request, res: Response) {
  res.sendStatus(501);
}

export function MethodNotAllowed(allowedMethods: Array<HttpMethods>) {
  return (req: Request, res: Response) => {
    let allowHeader = allowedMethods.map(m => {
      switch (m) {
        case HttpMethods.Get: return "GET";
        case HttpMethods.Put: return "PUT";
        case HttpMethods.Post: return "POST";
        case HttpMethods.Delete: return "DELETE";
        case HttpMethods.Head: return "HEAD";
        case HttpMethods.Options: return "OPTIONS";
      }
    })
    .reduce((prev, current) => `${prev}, ${current}`, "")
    res.setHeader('allow', allowHeader);
    res.sendStatus(405);
  }
}

export {
  Auth,
  Menu,
}
