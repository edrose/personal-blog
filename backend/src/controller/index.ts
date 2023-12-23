/**
 * Controller module index
 * 
 * Contains common controllers, and re-exports the submodules under the same
 * namespace
 */

import { Request, Response } from 'express';

import * as Auth from './auth';

export function NotImplemented(req: Request, res: Response) {
  res.sendStatus(501);
}

export {
  Auth,
}
