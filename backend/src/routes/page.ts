/**
 * Router for /page
 * 
 * Configures the routes for all paths at /page and exports a router to
 * handle them.
 */

import { Router } from 'express';
import { NotImplemented, Page as PageController } from '@/controller'

// Create the new router
const router = Router();

// Get all pages that are available
router.get('/', PageController.GetAllPages);

// Get the contents of a single page
router.get('/:slug', PageController.GetSinglePage);

// Fetch the page style as a css stylesheet
router.get('/:slug/style', PageController.GetPageStyle);

export default router;
