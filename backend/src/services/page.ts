/**
 * Business logic for pages
 */

import { PageModel } from "@/models";
import { Page, PageMetadata } from "@/models/page";

/**
 * @brief Fetch all pages from the system, returning just the metadata
 * @param max Limit the size of the results to this number
 * @param page Zero indexed page number. E.g page = 2 skips 
 * @returns An array of page metadata
 */
export function GetAllPages(max?: number, page?: number): Promise<Array<PageMetadata>> {
  // Validate the max and page variables
  let limit: number | undefined = max || undefined;
  let skip: number | undefined = undefined;

  // Ensure they don't go negative
  if (!!limit && limit < 0) {
    limit = undefined;
  }
 
  // Page is only allowed if limit is also provided
  if (!!limit && !!page && page > 0) {
    skip = limit * page;
  }

  // Now perform the query
  return PageModel.find({}, null, { limit, skip })
    // Remove the content from the response and return it
    .then((pages) => pages.map(p => ({
      title: p.title,
      path: p.path,
      author: p.author,
      published: p.published,
    } as PageMetadata)));
}

/**
 * @brief Fetch a single page from the database using it's slug
 * @param slug Slug to use to query for the page
 * @returns Either a single page, or null if the page is not found
 */
export async function GetPage(slug: String): Promise<Page | null> {
  return await PageModel.findOne({ where: { slug }});
}
