import { model } from "mongoose";
import { ObjectId, Types, Schema } from "mongoose";

export interface RefreshToken {
  _id: Schema.Types.ObjectId,
  id: String,
  user: ObjectId,
  expiry: Date,
}

const refreshTokenSchema = new Schema<RefreshToken>({
  id: { type: String, required: true, index: true },
  user: { type: Types.ObjectId, required: true, index: true },
  expiry: { type: Date, required: true },
});

export default model<RefreshToken>('refresh_token', refreshTokenSchema);
