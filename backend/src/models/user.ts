/**
 * Model for documents in the users collection
 */

import { Schema, model, Types } from 'mongoose';

export interface User {
  name: string,
  email: string,
  passwordHash?: string,
  canPublish: boolean,
}

const userSchema = new Schema<User>({
  name: { type: String, required: true },
  email: { type: String, required: true },
  passwordHash: { type: String, required: true },
  canPublish: { type: Boolean, required: true },
});

export default model<User>('Page', userSchema);
