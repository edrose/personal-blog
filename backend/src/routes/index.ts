/**
 * Router module to define the routes that this app will use
 * 
 * The root of the router, which pulls in all of the subroutes and creates a
 * single router that is exported.
 */
import { Router } from 'express';

import PageRouter from './page';

const router = Router();

router.use('/page', PageRouter);

router.get('/hello', (req, res) => res.send("Hello, world!"));


export default router;