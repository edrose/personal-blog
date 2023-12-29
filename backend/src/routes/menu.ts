/**
 * Router for /menu
 * 
 * Configures the routes for all paths at /menu and exports a router to
 * handle them.
 */

import { Router } from 'express';
import { NotImplemented, MethodNotAllowed, HttpMethods } from '@/controller';
import * as MenuController from '@/controller/menu';
import * as AuthController from '@/controller/auth';

// Create the new router
const router = Router();

// Get the details of a specific menu
router.get('/:name', MenuController.GetMenu);

// Edit or create a menu
router.put(
  '/:name',
  AuthController.AuthenticateRequest,
  AuthController.AuthoriseAdmin,
  NotImplemented
);

// Delete a menu
router.delete(
  '/:name',
  AuthController.AuthenticateRequest,
  AuthController.AuthoriseAdmin,
  NotImplemented
);

// Catch all other methods
router.all('/:name', MethodNotAllowed([HttpMethods.Get, HttpMethods.Put, HttpMethods.Delete]))

// Get all pages that are available
router.get('/', MenuController.GetMenuList);

// Catch all other methods
router.all('/', MethodNotAllowed([HttpMethods.Get]))

export default router;
