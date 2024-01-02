/**
 * Controller for reading and modifying menus
 */

import { NextFunction, Request, Response } from 'express';

import { ErrorHandler } from '@/controller';
import { MenuModel } from '@/models';

/**
 * @brief Get a list of all menus available on the system
 * @param req Express request object
 * @param res Express response object
 */
export function GetMenuList(req: Request, res: Response) {
  MenuModel.find()
    .then((menus) => menus.map(m => m.name))
    .then((menus) => res.json(menus))
    .catch(err => ErrorHandler(req, res, err));
}

/**
 * @brief Return the full data behind a menu
 * @param req Express request object
 * @param res Express response object
 */
export function GetMenu(req: Request, res: Response) {
  MenuModel.findOne({
    name: req.params.name,
  })
    .then((menu) => {
      if (!!menu) {
        res.json({
          name: menu.name,
          items: menu.items.map(m => ({
            title: m.title,
            tooltip: m.tooltip,
            link: m.link,
            children: m.subItems.map(c => ({
              title: c.title,
              tooltip: c.tooltip,
              link: c.link,
            }))
          }))
        });
      } else {
        res.sendStatus(404);
      }
    })
    .catch(err => ErrorHandler(req, res, err));
}