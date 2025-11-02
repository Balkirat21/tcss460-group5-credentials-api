import { Router } from 'express';
import { openRoutes } from './open';
import { closedRoutes } from './closed';
import { adminRoutes } from './admin';

const routes = Router();

// Mount all route groups
routes.use('', openRoutes);

routes.use('', closedRoutes);

// Admin routes (Person 3's implementation)
routes.use('/admin', adminRoutes);

export { routes };
