/**
 * Business logic for the menu
 */
import { MenuModel } from '@/models';
import { Menu, MenuItem, SubMenuItem } from '@/models/menu';

/**
 * @brief Fetch all menus from the system
 * @returns An array of all the menus on the system
 */
export function GetMenuList(): Promise<Array<Menu>> {
  return MenuModel.find();
}

/**
 * @brief Fetch a single menu by name
 * @param name The name of the menu to fetch
 * @returns The menu object, if it exists, or null if it's not found
 */
export function GetMenu(name: String): Promise<Menu | null> {
  return MenuModel.findOne({ where: name });
}