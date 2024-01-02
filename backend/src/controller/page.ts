/**
 * Controller for page routes
 */

import { Request, Response } from 'express';

import * as Log from 'winston';
import * as PagesService from '@/services/page';
import { PageModel } from '@/models';
import { Page } from '@/models/page';

/**
 * @brief Fetch all pages from the system, with optional limits in place
 * 
 * Pages are returned with no content, just the metadata in an array
 * @param req Express request object
 * @param res Express response object
 */
export function GetAllPages(req: Request, res: Response) {
  // Parse the query params that could be provided
  let limit: number | undefined = undefined; // Default to no limit
  let page: number | undefined = undefined;  // Default to only the first page of results

  // Parse the limit query parameter
  if (!!req.query['limit'] && Number.isInteger(req.query['limit'])) {
    limit = Number.parseInt(req.query['limit'] as string);
  }

  // Parse the page query parameter
  if (!!req.query['page'] && Number.isInteger(req.query['page'])) {
    page = Number.parseInt(req.query['page'] as string);
  }

  // Get the list of pages and return it
  PagesService.GetAllPages(limit, page)
    .then((pages) => {
      res.json(pages.map((p) => ({
        title: p.title,
        path: p.path,
        published: p.published,
      })))
    })
    .catch((err) => {
      Log.error(`Error querying for all pages: ${err}`);
      res.sendStatus(500);
    });
}

/**
 * @brief Fetch a single page from the system
 * 
 * The 'Accept' header determines the format returned. If 'Accept' is set to
 * 'application/json' then the post is returned as a json object. By default
 * just the content will be returned, with metadata set in the headers.
 * 
 * @param req Express Request object
 * @param res Express Response object
 */
export function GetSinglePage(req: Request, res: Response) {
  
}

export function GetPageStyle(req: Request, res: Response) {

}

export function PatchSinglePage(req: Request, res: Response) {

}

export function DeleteSinglePage(req: Request, res: Response) {

}

