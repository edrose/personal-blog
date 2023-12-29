/**
 * Model for documents in the menu collection
 */

import { Schema, model, Types } from 'mongoose';

export interface ChildMenuItem {
  title: string,
  link?: string,
  tooltip?: string,
}

const childMenuItemSchema = new Schema<ChildMenuItem>({
  title: { type: String, required: true },
  link: { type: String, required: false },
  tooltip: { type: String, required: false },
});

export interface MenuItem extends ChildMenuItem {
  children: Array<ChildMenuItem>,
}

const menuItemSchema = new Schema<MenuItem>({
  title: { type: String, required: true },
  link: { type: String, required: false },
  tooltip: { type: String, required: false },
  children: [childMenuItemSchema],
});

export interface Menu {
  _id: Schema.Types.ObjectId,
  name: string,
  items: Array<MenuItem>,
}

const menuSchema = new Schema<Menu>({
  name: { type: String, required: true, unique: true },
  items: [menuItemSchema],
});

export default model<Menu>('Menu', menuSchema);
