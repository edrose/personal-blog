/**
 * Router for /page
 * 
 * Configures the routes for all paths at /page and exports a router to
 * handle them.
 */

import { Router } from 'express';
import { NotImplemented } from '@/controller'

// Create the new router
const router = Router();

// Get all pages that are available
router.get('/', NotImplemented);

export default router;
