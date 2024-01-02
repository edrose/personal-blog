/**
 * Model for documents in the pages collection
 */

import { Schema, model, Types } from 'mongoose';

/**
 * @brief Represents the metadata for a page
 */
export interface PageMetadata {
  title: string,
  path: string,
  published: boolean,
  author: Types.ObjectId,
}

/**
 * @brief A model to define a static page on the website
 * 
 * A page is like a post, but doesn't appear in searches and isn't
 * included in the post listings.
 */
export interface Page extends PageMetadata, Document {
  contents: string,
  style: string,
}

const pageSchema = new Schema<Page>({
  title: { type: String, required: true },
  path: { type: String, required: true, unique: true },
  published: { type: Boolean, required: true },
  author: { type: Schema.Types.ObjectId, required: true },
  contents: { type: String, required: true },
  style: { type: String, required: false }
});

export default model<Page>('Page', pageSchema);
