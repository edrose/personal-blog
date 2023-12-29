/**
 * Router for /auth
 * 
 * Configures the routes for all paths at /page and exports a router to
 * handle them.
 */

import { Router } from 'express';
import * as AuthController from '@/controller/auth';
import { NotImplemented } from '@/controller'

// Create the new router
const router = Router();

// Get all pages that are available
router.get('/', NotImplemented);

router.get('/login', AuthController.Login);

router.get('/access-token', AuthController.GetAccessToken);

router.get('/user', AuthController.AuthenticateRequest, AuthController.AuthoriseUser, AuthController.GetUser);

export default router;
