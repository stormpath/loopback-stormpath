'use strict';

var stormpathConnector = require('loopback-connector-stormpath');

/**
 * Attach our custom StormpathUser model as well as our stormpath datasource
 * into Loopback so that these utilities are available to the developers using
 * this library.
 *
 * @param {Object} loopback The Loopback require.
 *
 * Usage example:
 *
 *   var loopback = require('loopback');
 *   var stormpath = require('loopback-stormpath');
 *
 *   var app = loopback();
 *   stormpath.init(app);
 *
 *   ...
 */
module.exports.init = function(app) {

  /**
   * This helper function, createModel, is stolen from the Loopback project
   * source code.  It apparently bootstraps the models properly.  See:
   * https://github.com/strongloop/loopback/blob/master/lib/builtin-models.js
   *
   * @param {Object} definitionJson The model's JSON definition.
   * @param {Function} customizeFn The function which customizes the model,
   *    loaded from bootscripts I believe.
   *
   * @return {Object} The fully customized model object.
   */
  function createModel(definitionJson, customizeFn) {
    var Model = app.loopback.createModel(definitionJson);
    customizeFn(Model);

    return Model;
  }

  // Initialize our `stormpath` datasource.  This is what provides all of the
  // ORM functionality for working with Stormpath Account objects.
  app.loopback.Stormpath = stormpathConnector;
  app.connector('stormpath', stormpathConnector);

  // Bind our `StormpathUser` model, making it available to developers.
  app.loopback.StormpathUser = createModel(
    require('../common/models/stormpath-user.json'),
    require('../common/models/stormpath-user.js')
  );

  // Automatically attach the `StormpathUser` model to the `stormpath`
  // datasource.
  app.loopback.StormpathUser.autoAttach = 'stormpath';

};
