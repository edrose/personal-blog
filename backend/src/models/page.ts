/**
 * Model for documents in the pages collection
 */

import { Schema, model, Types } from 'mongoose';

export interface Page {
  title: string,
  path: string,
  published: boolean,
  author: Types.ObjectId,
  contents: string,
}

const pageSchema = new Schema<Page>({
  title: { type: String, required: true },
  path: { type: String, required: true },
  published: { type: Boolean, required: true },
  author: { type: Schema.Types.ObjectId, required: true },
  contents: { type: String, required: true },
});

export default model<Page>('Page', pageSchema);
