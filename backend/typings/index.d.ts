/**
 * Type augmentations to modify types in typescript
 */

import * as UserModel from '@/models/user';

declare global {
    namespace Express {
        // Override the User interface with our model
        export interface User extends UserModel.User {}
    }
}