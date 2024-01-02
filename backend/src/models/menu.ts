/**
 * Model for documents in the menu collection
 */

import { Schema, model, Types } from 'mongoose';

/**
 * @brief Base interface containing all common fields for menu items
 */
interface BaseMenuItem {
  title: string,
  link?: string,
  tooltip?: string,
}

/**
 * @brief A sub-menu item which sits below a menu item
 */
export interface SubMenuItem extends BaseMenuItem, Types.Subdocument {}

const childMenuItemSchema = new Schema<SubMenuItem>({
  title: { type: String, required: true },
  link: { type: String, required: false },
  tooltip: { type: String, required: false },
});

/**
 * @brief An item that can be a top-level menu item
 */
export interface MenuItem extends BaseMenuItem, Types.Subdocument {
  subItems: Types.DocumentArray<SubMenuItem>,
}

const menuItemSchema = new Schema<MenuItem>({
  title: { type: String, required: true },
  link: { type: String, required: false },
  tooltip: { type: String, required: false },
  subItems: [childMenuItemSchema],
});

/**
 * @brief A menu, which contains a nummber of top-level menu items
 * 
 * A menu contains MenuItems, which can have a number of sub-menu items. This
 * allow a top-level menu to have a dropdown with multiple sub-menu items.
 */
export interface Menu extends Document {
  name: string,
  items: Types.DocumentArray<MenuItem>,
}

const menuSchema = new Schema<Menu>({
  name: { type: String, required: true, unique: true },
  items: [menuItemSchema],
});

export default model<Menu>('Menu', menuSchema);
