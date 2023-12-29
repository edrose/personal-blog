/**
 * Model for documents in the posts collection
 */

import { Schema, model, Types } from 'mongoose';

export interface Comment {
  user: string,
  date: Date,
  comment: string,
}

const commentSchema = new Schema<Comment>({
  user: { type: String, required: true },
  date: { type: Date, required: true },
  comment: { type: String, required: true },
});

export interface Post {
  _id?: Schema.Types.ObjectId,
  title: string,
  slug: string,
  date: Date,
  published: boolean,
  author: Types.ObjectId,
  contents: string,
  comments: Array<Comment>,
}

const postSchema = new Schema<Post>({
  title: { type: String, required: true },
  slug: { type: String, required: true, unique: true },
  date: { type: Date, required: true },
  published: { type: Boolean, required: true },
  author: { type: Schema.Types.ObjectId, required: true },
  contents: { type: String, required: true },
  comments: [commentSchema],
});

export default model<Post>('Post', postSchema);
