/**
 * Model for documents in the users collection
 */

import { Schema, model, Types, Document } from 'mongoose';

/**
 * @brief Defines the authorization access that a user has
 */
export enum UserRole {
  User = "user",
  Admin = "admin",
}

/**
 * @brief SubDocument containing a refresh token for the user
 */
export interface RefreshToken extends Types.Subdocument {
  expiry: Date,
}

const refreshTokenSchema = new Schema<RefreshToken>({
  expiry: { type: Date, required: true },
});

/**
 * @brief A cut-down version of the user model, for use in tokens
 */
export interface UserToken {
  name: string,
  email: string,
  role: string,
}

/**
 * @brief Model that describes a user on the system
 */
export interface User extends UserToken, Document {
  passwordHash?: string,
  tokens: Types.DocumentArray<RefreshToken>,
}

const userSchema = new Schema<User>({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  role: { type: String, required: true },
  tokens: [refreshTokenSchema],
});

export default model<User>('User', userSchema);
