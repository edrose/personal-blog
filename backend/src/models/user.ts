/**
 * Model for documents in the users collection
 */

import mongoose, { Schema, model, Types, ObjectId } from 'mongoose';

export interface User {
  _id?: Schema.Types.ObjectId,
  name: string,
  email: string,
  passwordHash?: string,
  canPublish: boolean,
}

const userSchema = new Schema<User>({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  canPublish: { type: Boolean, required: true },
});

export default model<User>('User', userSchema);
