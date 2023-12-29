/**
 * Controller for reading and modifying menus
 */

import { NextFunction, Request, Response } from 'express';

import { ErrorHandler } from '@/controller';
import { MenuModel } from '@/models';

/**
 * Get a list of all menus available on the system
 * @param req 
 * @param res 
 */
export function GetMenuList(req: Request, res: Response) {
  MenuModel.find()
    .then((menus) => menus.map(m => m.name))
    .then((menus) => res.json(menus))
    .catch(err => ErrorHandler(req, res, err));
}

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
            children: m.children.map(c => ({
              title: m.title,
              tooltip: m.tooltip,
              link: m.link,
            }))
          }))
        });
      } else {
        res.sendStatus(404);
      }
    })
    .catch(err => ErrorHandler(req, res, err));
}