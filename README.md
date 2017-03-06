#Stormpath is Joining Okta
We are incredibly excited to announce that [Stormpath is joining forces with Okta](https://stormpath.com/blog/stormpaths-new-path?utm_source=github&utm_medium=readme&utm-campaign=okta-announcement). Please visit [the Migration FAQs](https://stormpath.com/oktaplusstormpath?utm_source=github&utm_medium=readme&utm-campaign=okta-announcement) for a detailed look at what this means for Stormpath users.

We're available to answer all questions at [support@stormpath.com](mailto:support@stormpath.com).

# loopback-stormpath

[![NPM Version](https://img.shields.io/npm/v/loopback-stormpath.svg?style=flat)](https://npmjs.org/package/loopback-stormpath)
[![NPM Downloads](http://img.shields.io/npm/dm/loopback-stormpath.svg?style=flat)](https://npmjs.org/package/loopback-stormpath)
[![Build Status](https://img.shields.io/travis/stormpath/loopback-stormpath.svg?style=flat)](https://travis-ci.org/stormpath/loopback-stormpath)

*Stormpath User Management for Loopback.*


## Purpose

This library is meant to provide an interface between [Loopback][] and
[Stormpath][].

The end goal is provide the best possible user management system of all time for
Loopback developers!

If you don't already have a Stormpath account, go make one!
https://stormpath.com


## Usage

To get started, you'll need to have Strongloop installed:

```console
$ npm install -g strongloop
```

Next, you need to create a Loopback project to work in:

```console
$ slc loopback
```

Go through the questions to create your project.

Next, go into your project directory and edit your `server/server.js` file.
You'll need to add the following import statement to the top of your file:

```javascript
var stormpath = require('loopback-stormpath');
```

You'll also need to add the following line of code below your app creation
stuff.  You should have something like this:

```javascript
var app = module.exports = loopback();

// Initialize Stormpath.
stormpath.init(app);
```

After that, go ahead and open up `server/model-config.json`, and do two things:

- Firstly, remove the `User` object.  This is the default Loopback User model
  which you won't be using.
- Secondly, add in a `StormpathUser` object like this:

```javascript
"StormpathUser": {
  "dataSource": "stormpath"
}
```

`StormpathUser` is the new user model you'll be using from now on.

Next, open up `server/datasources.json`.  Here you'll need to define your
Stormpath data source, and specify your Stormpath API credentials.  Use the
following JSON blob as a configuration example, but substitute in your own
credentials:

```javascript
"stormpath": {
  "name": "stormpath",
  "connector": "stormpath",
  "apiKeyId": "xxx",
  "apiKeySecret": "xxx",
  "applicationHref": "https://api.stormpath.com/v1/applications/xxx"
}
```

That's it!  You've now fully configured your Loopback project to work with
Stormpath.  If you run your project (`$ slc run`), then visit the API explorer:
http://localhost:3000/explorer -- you should see a `StormpathUser` API endpoint
that you can use to create and manage your users with Stormpath!

**NOTE**: This is a VERY early release.  We're still working hard to improve
things, and make this feature complete!  If you have feedback, please send it to
us: support@stormpath.com


## Changelog

All library changes, in descending order.


### Version 0.0.1

**Released on March 27, 2015.**

- First release ever!  Still some lacking features, but we'll ship it anyway!


  [Stormpath]: https://stormpath.com/ "Stormpath User Management"
  [Loopback]: http://loopback.io/ "Loopback Node.js Web Framework"
