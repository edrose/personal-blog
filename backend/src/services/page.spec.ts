/**
 * Unit tests for the page service
 */

import { assert } from 'chai';
import Mongoose from 'mongoose';
import Config from 'config';
import { PageModel, UserModel } from '@/models';
import { UserRole } from '@/models/user';

import * as PageService from './page';

describe('Page Service Tests', () => {
  // Before running the tests, connect to the database
  before(() => {
    return Mongoose.connect(Config.get('mongoUrl'),
      {
        user: "root",
        pass: "example",
        authSource: "admin"
      }
    )
    // Clear out the database
    .then(() => PageModel.deleteMany({}))
    .then(() => UserModel.deleteMany({}))
    // Insert a test user
    .then(() => UserModel.create({
        email: 'test@example.com',
        name: 'Test User',
        role: UserRole.Admin,
      })
      .then(user => user.save())
    )
    .then((user) => PageModel.insertMany([
      {
        title: 'Home',
        path: '/',
        published: true,
        user: user.id,
        contents: 'Hello, world',
      }
    ]))
  });


  describe('Fetch page metadata', () => {
    it('should return page metadata', async () => {
      let pages = await PageService.GetAllPages();
      assert(pages.length == 1);
      assert(pages[0].path == '/');
      assert(pages[0].title == 'Home');
    })
  })
})

