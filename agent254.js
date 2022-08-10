/*! pendo-client 2020-05-18 */
(function(window, document, undefined){ // BEGIN config IIFE
    var sha1 = (function (module) { // added wrapper for "export" to pendo object
    
    /*
     * [js-sha1]{@link https://github.com/emn178/js-sha1}
     *
     * @version 0.6.0
     * @author Chen, Yi-Cyuan [emn178@gmail.com]
     * @copyright Chen, Yi-Cyuan 2014-2017
     * @license MIT
     */
    /*jslint bitwise: true */
    (function() {
      'use strict';
    
      var root = typeof window === 'object' ? window : {};
      var NODE_JS = !root.JS_SHA1_NO_NODE_JS && typeof process === 'object' && process.versions && process.versions.node;
      if (NODE_JS) {
        root = global;
      }
      var COMMON_JS = !root.JS_SHA1_NO_COMMON_JS && typeof module === 'object' && module.exports;
      var AMD = typeof define === 'function' && define.amd;
      var HEX_CHARS = '0123456789abcdef'.split('');
      var EXTRA = [-2147483648, 8388608, 32768, 128];
      var SHIFT = [24, 16, 8, 0];
      var OUTPUT_TYPES = ['hex', 'array', 'digest', 'arrayBuffer'];
    
      var blocks = [];
    
      var createOutputMethod = function (outputType) {
        return function (message) {
          return new Sha1(true).update(message)[outputType]();
        };
      };
    
      var createMethod = function () {
        var method = createOutputMethod('hex');
        if (NODE_JS) {
          method = nodeWrap(method);
        }
        method.create = function () {
          return new Sha1();
        };
        method.update = function (message) {
          return method.create().update(message);
        };
        for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
          var type = OUTPUT_TYPES[i];
          method[type] = createOutputMethod(type);
        }
        return method;
      };
    
      var nodeWrap = function (method) {
        var crypto = eval("require('crypto')");
        var Buffer = eval("require('buffer').Buffer");
        var nodeMethod = function (message) {
          if (typeof message === 'string') {
            return crypto.createHash('sha1').update(message, 'utf8').digest('hex');
          } else if (message.constructor === ArrayBuffer) {
            message = new Uint8Array(message);
          } else if (message.length === undefined) {
            return method(message);
          }
          return crypto.createHash('sha1').update(new Buffer(message)).digest('hex');
        };
        return nodeMethod;
      };
    
      function Sha1(sharedMemory) {
        if (sharedMemory) {
          blocks[0] = blocks[16] = blocks[1] = blocks[2] = blocks[3] =
          blocks[4] = blocks[5] = blocks[6] = blocks[7] =
          blocks[8] = blocks[9] = blocks[10] = blocks[11] =
          blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
          this.blocks = blocks;
        } else {
          this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        }
    
        this.h0 = 0x67452301;
        this.h1 = 0xEFCDAB89;
        this.h2 = 0x98BADCFE;
        this.h3 = 0x10325476;
        this.h4 = 0xC3D2E1F0;
    
        this.block = this.start = this.bytes = this.hBytes = 0;
        this.finalized = this.hashed = false;
        this.first = true;
      }
    
      Sha1.prototype.update = function (message) {
        if (this.finalized) {
          return;
        }
        var notString = typeof(message) !== 'string';
        if (notString && message.constructor === root.ArrayBuffer) {
          message = new Uint8Array(message);
        }
        var code, index = 0, i, length = message.length || 0, blocks = this.blocks;
    
        while (index < length) {
          if (this.hashed) {
            this.hashed = false;
            blocks[0] = this.block;
            blocks[16] = blocks[1] = blocks[2] = blocks[3] =
            blocks[4] = blocks[5] = blocks[6] = blocks[7] =
            blocks[8] = blocks[9] = blocks[10] = blocks[11] =
            blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
          }
    
          if(notString) {
            for (i = this.start; index < length && i < 64; ++index) {
              blocks[i >> 2] |= message[index] << SHIFT[i++ & 3];
            }
          } else {
            for (i = this.start; index < length && i < 64; ++index) {
              code = message.charCodeAt(index);
              if (code < 0x80) {
                blocks[i >> 2] |= code << SHIFT[i++ & 3];
              } else if (code < 0x800) {
                blocks[i >> 2] |= (0xc0 | (code >> 6)) << SHIFT[i++ & 3];
                blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
              } else if (code < 0xd800 || code >= 0xe000) {
                blocks[i >> 2] |= (0xe0 | (code >> 12)) << SHIFT[i++ & 3];
                blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
                blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
              } else {
                code = 0x10000 + (((code & 0x3ff) << 10) | (message.charCodeAt(++index) & 0x3ff));
                blocks[i >> 2] |= (0xf0 | (code >> 18)) << SHIFT[i++ & 3];
                blocks[i >> 2] |= (0x80 | ((code >> 12) & 0x3f)) << SHIFT[i++ & 3];
                blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
                blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
              }
            }
          }
    
          this.lastByteIndex = i;
          this.bytes += i - this.start;
          if (i >= 64) {
            this.block = blocks[16];
            this.start = i - 64;
            this.hash();
            this.hashed = true;
          } else {
            this.start = i;
          }
        }
        if (this.bytes > 4294967295) {
          this.hBytes += this.bytes / 4294967296 << 0;
          this.bytes = this.bytes % 4294967296;
        }
        return this;
      };
    
      Sha1.prototype.finalize = function () {
        if (this.finalized) {
          return;
        }
        this.finalized = true;
        var blocks = this.blocks, i = this.lastByteIndex;
        blocks[16] = this.block;
        blocks[i >> 2] |= EXTRA[i & 3];
        this.block = blocks[16];
        if (i >= 56) {
          if (!this.hashed) {
            this.hash();
          }
          blocks[0] = this.block;
          blocks[16] = blocks[1] = blocks[2] = blocks[3] =
          blocks[4] = blocks[5] = blocks[6] = blocks[7] =
          blocks[8] = blocks[9] = blocks[10] = blocks[11] =
          blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
        }
        blocks[14] = this.hBytes << 3 | this.bytes >>> 29;
        blocks[15] = this.bytes << 3;
        this.hash();
      };
    
      Sha1.prototype.hash = function () {
        var a = this.h0, b = this.h1, c = this.h2, d = this.h3, e = this.h4;
        var f, j, t, blocks = this.blocks;
    
        for(j = 16; j < 80; ++j) {
          t = blocks[j - 3] ^ blocks[j - 8] ^ blocks[j - 14] ^ blocks[j - 16];
          blocks[j] =  (t << 1) | (t >>> 31);
        }
    
        for(j = 0; j < 20; j += 5) {
          f = (b & c) | ((~b) & d);
          t = (a << 5) | (a >>> 27);
          e = t + f + e + 1518500249 + blocks[j] << 0;
          b = (b << 30) | (b >>> 2);
    
          f = (a & b) | ((~a) & c);
          t = (e << 5) | (e >>> 27);
          d = t + f + d + 1518500249 + blocks[j + 1] << 0;
          a = (a << 30) | (a >>> 2);
    
          f = (e & a) | ((~e) & b);
          t = (d << 5) | (d >>> 27);
          c = t + f + c + 1518500249 + blocks[j + 2] << 0;
          e = (e << 30) | (e >>> 2);
    
          f = (d & e) | ((~d) & a);
          t = (c << 5) | (c >>> 27);
          b = t + f + b + 1518500249 + blocks[j + 3] << 0;
          d = (d << 30) | (d >>> 2);
    
          f = (c & d) | ((~c) & e);
          t = (b << 5) | (b >>> 27);
          a = t + f + a + 1518500249 + blocks[j + 4] << 0;
          c = (c << 30) | (c >>> 2);
        }
    
        for(; j < 40; j += 5) {
          f = b ^ c ^ d;
          t = (a << 5) | (a >>> 27);
          e = t + f + e + 1859775393 + blocks[j] << 0;
          b = (b << 30) | (b >>> 2);
    
          f = a ^ b ^ c;
          t = (e << 5) | (e >>> 27);
          d = t + f + d + 1859775393 + blocks[j + 1] << 0;
          a = (a << 30) | (a >>> 2);
    
          f = e ^ a ^ b;
          t = (d << 5) | (d >>> 27);
          c = t + f + c + 1859775393 + blocks[j + 2] << 0;
          e = (e << 30) | (e >>> 2);
    
          f = d ^ e ^ a;
          t = (c << 5) | (c >>> 27);
          b = t + f + b + 1859775393 + blocks[j + 3] << 0;
          d = (d << 30) | (d >>> 2);
    
          f = c ^ d ^ e;
          t = (b << 5) | (b >>> 27);
          a = t + f + a + 1859775393 + blocks[j + 4] << 0;
          c = (c << 30) | (c >>> 2);
        }
    
        for(; j < 60; j += 5) {
          f = (b & c) | (b & d) | (c & d);
          t = (a << 5) | (a >>> 27);
          e = t + f + e - 1894007588 + blocks[j] << 0;
          b = (b << 30) | (b >>> 2);
    
          f = (a & b) | (a & c) | (b & c);
          t = (e << 5) | (e >>> 27);
          d = t + f + d - 1894007588 + blocks[j + 1] << 0;
          a = (a << 30) | (a >>> 2);
    
          f = (e & a) | (e & b) | (a & b);
          t = (d << 5) | (d >>> 27);
          c = t + f + c - 1894007588 + blocks[j + 2] << 0;
          e = (e << 30) | (e >>> 2);
    
          f = (d & e) | (d & a) | (e & a);
          t = (c << 5) | (c >>> 27);
          b = t + f + b - 1894007588 + blocks[j + 3] << 0;
          d = (d << 30) | (d >>> 2);
    
          f = (c & d) | (c & e) | (d & e);
          t = (b << 5) | (b >>> 27);
          a = t + f + a - 1894007588 + blocks[j + 4] << 0;
          c = (c << 30) | (c >>> 2);
        }
    
        for(; j < 80; j += 5) {
          f = b ^ c ^ d;
          t = (a << 5) | (a >>> 27);
          e = t + f + e - 899497514 + blocks[j] << 0;
          b = (b << 30) | (b >>> 2);
    
          f = a ^ b ^ c;
          t = (e << 5) | (e >>> 27);
          d = t + f + d - 899497514 + blocks[j + 1] << 0;
          a = (a << 30) | (a >>> 2);
    
          f = e ^ a ^ b;
          t = (d << 5) | (d >>> 27);
          c = t + f + c - 899497514 + blocks[j + 2] << 0;
          e = (e << 30) | (e >>> 2);
    
          f = d ^ e ^ a;
          t = (c << 5) | (c >>> 27);
          b = t + f + b - 899497514 + blocks[j + 3] << 0;
          d = (d << 30) | (d >>> 2);
    
          f = c ^ d ^ e;
          t = (b << 5) | (b >>> 27);
          a = t + f + a - 899497514 + blocks[j + 4] << 0;
          c = (c << 30) | (c >>> 2);
        }
    
        this.h0 = this.h0 + a << 0;
        this.h1 = this.h1 + b << 0;
        this.h2 = this.h2 + c << 0;
        this.h3 = this.h3 + d << 0;
        this.h4 = this.h4 + e << 0;
      };
    
      Sha1.prototype.hex = function () {
        this.finalize();
    
        var h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, h4 = this.h4;
    
        return HEX_CHARS[(h0 >> 28) & 0x0F] + HEX_CHARS[(h0 >> 24) & 0x0F] +
               HEX_CHARS[(h0 >> 20) & 0x0F] + HEX_CHARS[(h0 >> 16) & 0x0F] +
               HEX_CHARS[(h0 >> 12) & 0x0F] + HEX_CHARS[(h0 >> 8) & 0x0F] +
               HEX_CHARS[(h0 >> 4) & 0x0F] + HEX_CHARS[h0 & 0x0F] +
               HEX_CHARS[(h1 >> 28) & 0x0F] + HEX_CHARS[(h1 >> 24) & 0x0F] +
               HEX_CHARS[(h1 >> 20) & 0x0F] + HEX_CHARS[(h1 >> 16) & 0x0F] +
               HEX_CHARS[(h1 >> 12) & 0x0F] + HEX_CHARS[(h1 >> 8) & 0x0F] +
               HEX_CHARS[(h1 >> 4) & 0x0F] + HEX_CHARS[h1 & 0x0F] +
               HEX_CHARS[(h2 >> 28) & 0x0F] + HEX_CHARS[(h2 >> 24) & 0x0F] +
               HEX_CHARS[(h2 >> 20) & 0x0F] + HEX_CHARS[(h2 >> 16) & 0x0F] +
               HEX_CHARS[(h2 >> 12) & 0x0F] + HEX_CHARS[(h2 >> 8) & 0x0F] +
               HEX_CHARS[(h2 >> 4) & 0x0F] + HEX_CHARS[h2 & 0x0F] +
               HEX_CHARS[(h3 >> 28) & 0x0F] + HEX_CHARS[(h3 >> 24) & 0x0F] +
               HEX_CHARS[(h3 >> 20) & 0x0F] + HEX_CHARS[(h3 >> 16) & 0x0F] +
               HEX_CHARS[(h3 >> 12) & 0x0F] + HEX_CHARS[(h3 >> 8) & 0x0F] +
               HEX_CHARS[(h3 >> 4) & 0x0F] + HEX_CHARS[h3 & 0x0F] +
               HEX_CHARS[(h4 >> 28) & 0x0F] + HEX_CHARS[(h4 >> 24) & 0x0F] +
               HEX_CHARS[(h4 >> 20) & 0x0F] + HEX_CHARS[(h4 >> 16) & 0x0F] +
               HEX_CHARS[(h4 >> 12) & 0x0F] + HEX_CHARS[(h4 >> 8) & 0x0F] +
               HEX_CHARS[(h4 >> 4) & 0x0F] + HEX_CHARS[h4 & 0x0F];
      };
    
      Sha1.prototype.toString = Sha1.prototype.hex;
    
      Sha1.prototype.digest = function () {
        this.finalize();
    
        var h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, h4 = this.h4;
    
        return [
          (h0 >> 24) & 0xFF, (h0 >> 16) & 0xFF, (h0 >> 8) & 0xFF, h0 & 0xFF,
          (h1 >> 24) & 0xFF, (h1 >> 16) & 0xFF, (h1 >> 8) & 0xFF, h1 & 0xFF,
          (h2 >> 24) & 0xFF, (h2 >> 16) & 0xFF, (h2 >> 8) & 0xFF, h2 & 0xFF,
          (h3 >> 24) & 0xFF, (h3 >> 16) & 0xFF, (h3 >> 8) & 0xFF, h3 & 0xFF,
          (h4 >> 24) & 0xFF, (h4 >> 16) & 0xFF, (h4 >> 8) & 0xFF, h4 & 0xFF
        ];
      };
    
      Sha1.prototype.array = Sha1.prototype.digest;
    
      Sha1.prototype.arrayBuffer = function () {
        this.finalize();
    
        var buffer = new ArrayBuffer(20);
        var dataView = new DataView(buffer);
        dataView.setUint32(0, this.h0);
        dataView.setUint32(4, this.h1);
        dataView.setUint32(8, this.h2);
        dataView.setUint32(12, this.h3);
        dataView.setUint32(16, this.h4);
        return buffer;
      };
    
      var exports = createMethod();
    
      if (COMMON_JS) {
        module.exports = exports;
      } else {
        root.sha1 = exports;
        if (AMD) {
          define(function () {
            return exports;
          });
        }
      }
    })();
    
    // end wrapper for pendo export
    return module.exports;
    })({ exports: {} });
    var b64 = (function() {
        'use strict';
    
        var lookup = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.split('');
    
        return {
            'uint8ToBase64': uint8ToBase64
        };
    
        function uint8ToBase64(uint8) {
            var i,
                extraBytes = uint8.length % 3, // if we have 1 byte left, pad 2 bytes
                output = '',
                temp, length;
    
            function tripletToBase64(num) {
                return lookup[num >> 18 & 0x3F] + lookup[num >> 12 & 0x3F] + lookup[num >> 6 & 0x3F] + lookup[num & 0x3F];
            }
    
            // go through the array every three bytes, we'll deal with trailing stuff later
            for (i = 0, length = uint8.length - extraBytes; i < length; i += 3) {
                temp = (uint8[i] << 16) + (uint8[i + 1] << 8) + (uint8[i + 2]);
                output += tripletToBase64(temp);
            }
    
            // pad the end with zeros, but make sure to not forget the extra bytes
            //eslint-disable-next-line default-case
            switch (extraBytes) {
            case 1:
                temp = uint8[uint8.length - 1];
                output += lookup[temp >> 2];
                output += lookup[(temp << 4) & 0x3F];
                break;
            case 2:
                temp = (uint8[uint8.length - 2] << 8) + (uint8[uint8.length - 1]);
                output += lookup[temp >> 10];
                output += lookup[(temp >> 4) & 0x3F];
                output += lookup[(temp << 2) & 0x3F];
                break;
            }
    
            return output;
        }
    })();
    /*
     * NOTE: gulpfile.js line 296 -- actually writes the line of code that uses this
     * CODE to the agent. It's presumably done there to guarantee its early position
     * in resulting agent code.
     *
     * If you want to add any libraries for use in the preamble (we currently have
     * b64 and sha1 available here now) then you'll need to update `gulpfile.js`
     * line 35 for the `eslint` task and `karma.conf.js` line 31.
     */
    
    var STAGING_SERVER_HASHES = 'stagingServerHashes';
    
    function shouldLoadStagingAgent(config) {
        // trying to not calculate Hash if not needed.
        if (hasHashedStagingServers(config)) {
            var hostHash = getHash(location.host);
            for (var j = 0, jj = config[STAGING_SERVER_HASHES].length; j < jj; ++j) {
                var h = config[STAGING_SERVER_HASHES][j];
                if (h === hostHash) {
                    return true;
                }
            }
        }
    
        if (hasStagingServerConfig(config)) {
            for (var i = 0, ii = config.stagingServers.length; i < ii; ++i) {
                var stagingServer = config.stagingServers[i];
                if (typeof stagingServer === 'string') {
                    stagingServer = new RegExp('^' + stagingServer + '$');
                }
                if (stagingServer instanceof RegExp && stagingServer.test(location.host)) {
                    return true;
                }
            }
        }
    
        return false;
    }
    
    function getHash(str) {
        return b64.uint8ToBase64(
            sha1
                .create()
                .update(str)
                .digest()
        );
    }
    
    function hasHashedStagingServers(config) {
        return config && config.stagingAgentUrl && config[STAGING_SERVER_HASHES];
    }
    
    function hasStagingServerConfig(config) {
        return config && config.stagingAgentUrl && config.stagingServers;
    }
    
    var METHODS_TO_CAPTURE = [
        'initialize',
        'identify',
        'updateOptions',
        'pageLoad'
    ];
    
    function enqueueCall(method, args) {
        var pendo = window.pendo = window.pendo || {};
        var callQueue = pendo._q = pendo._q || [];
        var action = method === 'initialize' ? 'unshift' : 'push';
        callQueue[action](
            [].concat.apply([method], args)
        );
    }
    
    function captureCall(method, obj) {
        obj[method] = obj[method] || function() {
            enqueueCall(method, arguments);
        };
    }
    
    //eslint-disable-next-line no-unused-vars
    function loadStagingAgent(config) {
        if (shouldLoadStagingAgent(config)) {
            var pendo = window.pendo = window.pendo || {};
    
            if (!pendo._q) {
                var index, length;
    
                var methods = METHODS_TO_CAPTURE;
                for (index = 0, length = methods.length; index < length; ++index) {
                    captureCall(methods[index], pendo);
                }
            }
    
            includeScript(config.stagingAgentUrl);
            return true;
        }
        return false;
    }
    
    function includeScript(scriptUrl) {
        var scriptTagName = 'script';
        var stagingScriptTag = document.createElement(scriptTagName);
        stagingScriptTag.async = true;
        stagingScriptTag.src = scriptUrl;
        var otherScriptTag = document.getElementsByTagName(scriptTagName)[0];
        otherScriptTag.parentNode.insertBefore(stagingScriptTag, otherScriptTag);
    }
    
    function getPendoConfigValue(key) {
        if (typeof PendoConfig !== 'undefined') {
            return PendoConfig[key];
        }
    }
    if (typeof PendoConfig !== 'undefined' && loadStagingAgent(PendoConfig)) { return; }(function(){ // BEGIN agent IIFE
    'use strict';
    if(window.pendo && window.pendo.VERSION) { return; }
    
    /*!    Underscore.js 1.7.0
           http://underscorejs.org
           (c) 2009-2014 Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
           Underscore may be freely distributed under the MIT license.*/
    
    var UNDERSCORE_EXT = {};
    
    (function() {
    
      // Baseline setup
      // --------------
    
      // Establish the root object, `window` in the browser, or `exports` on the server.
      var root = UNDERSCORE_EXT;
    
      // Save the previous value of the `_` variable.
      var previousUnderscore = root._;
    
      // Save bytes in the minified (but not gzipped) version:
      var ArrayProto = Array.prototype, ObjProto = Object.prototype, FuncProto = Function.prototype;
    
      // Create quick reference variables for speed access to core prototypes.
      var
        push             = ArrayProto.push,
        slice            = ArrayProto.slice,
        concat           = ArrayProto.concat,
        toString         = ObjProto.toString,
        hasOwnProperty   = ObjProto.hasOwnProperty;
    
      // All **ECMAScript 5** native function implementations that we hope to use
      // are declared here.
      var
        nativeIsArray      = Array.isArray,
        nativeKeys         = Object.keys,
        nativeBind         = FuncProto.bind;
    
      // Create a safe reference to the Underscore object for use below.
      var _ = function(obj) {
        if (obj instanceof _) return obj;
        if (!(this instanceof _)) return new _(obj);
        this._wrapped = obj;
      };
    
      // Export the Underscore object for **Node.js**, with
      // backwards-compatibility for the old `require()` API. If we're in
      // the browser, add `_` as a global object.
    
      root._ = _;
    
      // Current version.
      _.VERSION = '1.7.0-pendo';
    
      // Internal function that returns an efficient (for current engines) version
      // of the passed-in callback, to be repeatedly applied in other Underscore
      // functions.
      var createCallback = function(func, context, argCount) {
        if (context === void 0) return func;
        switch (argCount == null ? 3 : argCount) {
          case 1: return function(value) {
            return func.call(context, value);
          };
          case 2: return function(value, other) {
            return func.call(context, value, other);
          };
          case 3: return function(value, index, collection) {
            return func.call(context, value, index, collection);
          };
          case 4: return function(accumulator, value, index, collection) {
            return func.call(context, accumulator, value, index, collection);
          };
        }
        return function() {
          return func.apply(context, arguments);
        };
      };
    
      // A mostly-internal function to generate callbacks that can be applied
      // to each element in a collection, returning the desired result â€” either
      // identity, an arbitrary callback, a property matcher, or a property accessor.
      _.iteratee = function(value, context, argCount) {
        if (value == null) return _.identity;
        if (_.isFunction(value)) return createCallback(value, context, argCount);
        if (_.isObject(value)) return _.matches(value);
        return _.property(value);
      };
    
      // Collection Functions
      // --------------------
    
      // The cornerstone, an `each` implementation, aka `forEach`.
      // Handles raw objects in addition to array-likes. Treats all
      // sparse array-likes as if they were dense.
      _.each = _.forEach = function(obj, iteratee, context) {
        if (obj == null) return obj;
        iteratee = createCallback(iteratee, context);
        var i, length = obj.length;
        if (length === +length) {
          for (i = 0; i < length; i++) {
            iteratee(obj[i], i, obj);
          }
        } else {
          var keys = _.keys(obj);
          for (i = 0, length = keys.length; i < length; i++) {
            iteratee(obj[keys[i]], keys[i], obj);
          }
        }
        return obj;
      };
    
      // Return the results of applying the iteratee to each element.
      _.map = _.collect = function(obj, iteratee, context) {
        if (obj == null) return [];
        iteratee = _.iteratee(iteratee, context);
        var keys = obj.length !== +obj.length && _.keys(obj),
            length = (keys || obj).length,
            results = Array(length),
            currentKey;
        for (var index = 0; index < length; index++) {
          currentKey = keys ? keys[index] : index;
          results[index] = iteratee(obj[currentKey], currentKey, obj);
        }
        return results;
      };
    
      var reduceError = 'Reduce of empty array with no initial value';
    
      // **Reduce** builds up a single result from a list of values, aka `inject`,
      // or `foldl`.
      _.reduce = _.foldl = _.inject = function(obj, iteratee, memo, context) {
        if (obj == null) obj = [];
        iteratee = createCallback(iteratee, context, 4);
        var keys = obj.length !== +obj.length && _.keys(obj),
            length = (keys || obj).length,
            index = 0, currentKey;
        if (arguments.length < 3) {
          if (!length) throw new TypeError(reduceError);
          memo = obj[keys ? keys[index++] : index++];
        }
        for (; index < length; index++) {
          currentKey = keys ? keys[index] : index;
          memo = iteratee(memo, obj[currentKey], currentKey, obj);
        }
        return memo;
      };
    
      // The right-associative version of reduce, also known as `foldr`.
      _.reduceRight = _.foldr = function(obj, iteratee, memo, context) {
        if (obj == null) obj = [];
        iteratee = createCallback(iteratee, context, 4);
        var keys = obj.length !== + obj.length && _.keys(obj),
            index = (keys || obj).length,
            currentKey;
        if (arguments.length < 3) {
          if (!index) throw new TypeError(reduceError);
          memo = obj[keys ? keys[--index] : --index];
        }
        while (index--) {
          currentKey = keys ? keys[index] : index;
          memo = iteratee(memo, obj[currentKey], currentKey, obj);
        }
        return memo;
      };
    
      // Return the first value which passes a truth test. Aliased as `detect`.
      _.find = _.detect = function(obj, predicate, context) {
        var result;
        predicate = _.iteratee(predicate, context);
        _.some(obj, function(value, index, list) {
          if (predicate(value, index, list)) {
            result = value;
            return true;
          }
        });
        return result;
      };
    
      // Return all the elements that pass a truth test.
      // Aliased as `select`.
      _.filter = _.select = function(obj, predicate, context) {
        var results = [];
        if (obj == null) return results;
        predicate = _.iteratee(predicate, context);
        _.each(obj, function(value, index, list) {
          if (predicate(value, index, list)) results.push(value);
        });
        return results;
      };
    
      // Return all the elements for which a truth test fails.
      _.reject = function(obj, predicate, context) {
        return _.filter(obj, _.negate(_.iteratee(predicate)), context);
      };
    
      // Determine whether all of the elements match a truth test.
      // Aliased as `all`.
      _.every = _.all = function(obj, predicate, context) {
        if (obj == null) return true;
        predicate = _.iteratee(predicate, context);
        var keys = obj.length !== +obj.length && _.keys(obj),
            length = (keys || obj).length,
            index, currentKey;
        for (index = 0; index < length; index++) {
          currentKey = keys ? keys[index] : index;
          if (!predicate(obj[currentKey], currentKey, obj)) return false;
        }
        return true;
      };
    
      // Determine if at least one element in the object matches a truth test.
      // Aliased as `any`.
      _.some = _.any = function(obj, predicate, context) {
        if (obj == null) return false;
        predicate = _.iteratee(predicate, context);
        var keys = obj.length !== +obj.length && _.keys(obj),
            length = (keys || obj).length,
            index, currentKey;
        for (index = 0; index < length; index++) {
          currentKey = keys ? keys[index] : index;
          if (predicate(obj[currentKey], currentKey, obj)) return true;
        }
        return false;
      };
    
      // Determine if the array or object contains a given value (using `===`).
      // Aliased as `include`.
      _.contains = _.include = function(obj, target) {
        if (obj == null) return false;
        if (obj.length !== +obj.length) obj = _.values(obj);
        return _.indexOf(obj, target) >= 0;
      };
    
      // Invoke a method (with arguments) on every item in a collection.
      _.invoke = function(obj, method) {
        var args = slice.call(arguments, 2);
        var isFunc = _.isFunction(method);
        return _.map(obj, function(value) {
          return (isFunc ? method : value[method]).apply(value, args);
        });
      };
    
      // Convenience version of a common use case of `map`: fetching a property.
      _.pluck = function(obj, key) {
        return _.map(obj, _.property(key));
      };
    
      // Convenience version of a common use case of `filter`: selecting only objects
      // containing specific `key:value` pairs.
      _.where = function(obj, attrs) {
        return _.filter(obj, _.matches(attrs));
      };
    
      // Convenience version of a common use case of `find`: getting the first object
      // containing specific `key:value` pairs.
      _.findWhere = function(obj, attrs) {
        return _.find(obj, _.matches(attrs));
      };
    
      // Return the maximum element (or element-based computation).
      _.max = function(obj, iteratee, context) {
        var result = -Infinity, lastComputed = -Infinity,
            value, computed;
        if (iteratee == null && obj != null) {
          obj = obj.length === +obj.length ? obj : _.values(obj);
          for (var i = 0, length = obj.length; i < length; i++) {
            value = obj[i];
            if (value > result) {
              result = value;
            }
          }
        } else {
          iteratee = _.iteratee(iteratee, context);
          _.each(obj, function(value, index, list) {
            computed = iteratee(value, index, list);
            if (computed > lastComputed || computed === -Infinity && result === -Infinity) {
              result = value;
              lastComputed = computed;
            }
          });
        }
        return result;
      };
    
      // Return the minimum element (or element-based computation).
      _.min = function(obj, iteratee, context) {
        var result = Infinity, lastComputed = Infinity,
            value, computed;
        if (iteratee == null && obj != null) {
          obj = obj.length === +obj.length ? obj : _.values(obj);
          for (var i = 0, length = obj.length; i < length; i++) {
            value = obj[i];
            if (value < result) {
              result = value;
            }
          }
        } else {
          iteratee = _.iteratee(iteratee, context);
          _.each(obj, function(value, index, list) {
            computed = iteratee(value, index, list);
            if (computed < lastComputed || computed === Infinity && result === Infinity) {
              result = value;
              lastComputed = computed;
            }
          });
        }
        return result;
      };
    
      // Shuffle a collection, using the modern version of the
      // [Fisher-Yates shuffle](http://en.wikipedia.org/wiki/Fisherâ€“Yates_shuffle).
      _.shuffle = function(obj) {
        var set = obj && obj.length === +obj.length ? obj : _.values(obj);
        var length = set.length;
        var shuffled = Array(length);
        for (var index = 0, rand; index < length; index++) {
          rand = _.random(0, index);
          if (rand !== index) shuffled[index] = shuffled[rand];
          shuffled[rand] = set[index];
        }
        return shuffled;
      };
    
      // Sample **n** random values from a collection.
      // If **n** is not specified, returns a single random element.
      // The internal `guard` argument allows it to work with `map`.
      _.sample = function(obj, n, guard) {
        if (n == null || guard) {
          if (obj.length !== +obj.length) obj = _.values(obj);
          return obj[_.random(obj.length - 1)];
        }
        return _.shuffle(obj).slice(0, Math.max(0, n));
      };
    
      // Sort the object's values by a criterion produced by an iteratee.
      _.sortBy = function(obj, iteratee, context) {
        iteratee = _.iteratee(iteratee, context);
        return _.pluck(_.map(obj, function(value, index, list) {
          return {
            value: value,
            index: index,
            criteria: iteratee(value, index, list)
          };
        }).sort(function(left, right) {
          var a = left.criteria;
          var b = right.criteria;
          if (a !== b) {
            if (a > b || a === void 0) return 1;
            if (a < b || b === void 0) return -1;
          }
          return left.index - right.index;
        }), 'value');
      };
    
      // An internal function used for aggregate "group by" operations.
      var group = function(behavior) {
        return function(obj, iteratee, context) {
          var result = {};
          iteratee = _.iteratee(iteratee, context);
          _.each(obj, function(value, index) {
            var key = iteratee(value, index, obj);
            behavior(result, value, key);
          });
          return result;
        };
      };
    
      // Groups the object's values by a criterion. Pass either a string attribute
      // to group by, or a function that returns the criterion.
      _.groupBy = group(function(result, value, key) {
        if (_.has(result, key)) result[key].push(value); else result[key] = [value];
      });
    
      // Indexes the object's values by a criterion, similar to `groupBy`, but for
      // when you know that your index values will be unique.
      _.indexBy = group(function(result, value, key) {
        result[key] = value;
      });
    
      // Counts instances of an object that group by a certain criterion. Pass
      // either a string attribute to count by, or a function that returns the
      // criterion.
      _.countBy = group(function(result, value, key) {
        if (_.has(result, key)) result[key]++; else result[key] = 1;
      });
    
      // Use a comparator function to figure out the smallest index at which
      // an object should be inserted so as to maintain order. Uses binary search.
      _.sortedIndex = function(array, obj, iteratee, context) {
        iteratee = _.iteratee(iteratee, context, 1);
        var value = iteratee(obj);
        var low = 0, high = array.length;
        while (low < high) {
          var mid = low + high >>> 1;
          if (iteratee(array[mid]) < value) low = mid + 1; else high = mid;
        }
        return low;
      };
    
      // Safely create a real, live array from anything iterable.
      _.toArray = function(obj) {
        if (!obj) return [];
        if (_.isArray(obj)) return slice.call(obj);
        if (obj.length === +obj.length) return _.map(obj, _.identity);
        return _.values(obj);
      };
    
      // Return the number of elements in an object.
      _.size = function(obj) {
        if (obj == null) return 0;
        return obj.length === +obj.length ? obj.length : _.keys(obj).length;
      };
    
      // Split a collection into two arrays: one whose elements all satisfy the given
      // predicate, and one whose elements all do not satisfy the predicate.
      _.partition = function(obj, predicate, context) {
        predicate = _.iteratee(predicate, context);
        var pass = [], fail = [];
        _.each(obj, function(value, key, obj) {
          (predicate(value, key, obj) ? pass : fail).push(value);
        });
        return [pass, fail];
      };
    
      // Array Functions
      // ---------------
    
      // Get the first element of an array. Passing **n** will return the first N
      // values in the array. Aliased as `head` and `take`. The **guard** check
      // allows it to work with `_.map`.
      _.first = _.head = _.take = function(array, n, guard) {
        if (array == null) return void 0;
        if (n == null || guard) return array[0];
        if (n < 0) return [];
        return slice.call(array, 0, n);
      };
    
      // Returns everything but the last entry of the array. Especially useful on
      // the arguments object. Passing **n** will return all the values in
      // the array, excluding the last N. The **guard** check allows it to work with
      // `_.map`.
      _.initial = function(array, n, guard) {
        return slice.call(array, 0, Math.max(0, array.length - (n == null || guard ? 1 : n)));
      };
    
      // Get the last element of an array. Passing **n** will return the last N
      // values in the array. The **guard** check allows it to work with `_.map`.
      _.last = function(array, n, guard) {
        if (array == null) return void 0;
        if (n == null || guard) return array[array.length - 1];
        return slice.call(array, Math.max(array.length - n, 0));
      };
    
      // Returns everything but the first entry of the array. Aliased as `tail` and `drop`.
      // Especially useful on the arguments object. Passing an **n** will return
      // the rest N values in the array. The **guard**
      // check allows it to work with `_.map`.
      _.rest = _.tail = _.drop = function(array, n, guard) {
        return slice.call(array, n == null || guard ? 1 : n);
      };
    
      // Trim out all falsy values from an array.
      _.compact = function(array) {
        return _.filter(array, _.identity);
      };
    
      // Internal implementation of a recursive `flatten` function.
      var flatten = function(input, shallow, strict, output) {
        if (shallow && _.every(input, _.isArray)) {
          return concat.apply(output, input);
        }
        for (var i = 0, length = input.length; i < length; i++) {
          var value = input[i];
          if (!_.isArray(value) && !_.isArguments(value)) {
            if (!strict) output.push(value);
          } else if (shallow) {
            push.apply(output, value);
          } else {
            flatten(value, shallow, strict, output);
          }
        }
        return output;
      };
    
      // Flatten out an array, either recursively (by default), or just one level.
      _.flatten = function(array, shallow) {
        return flatten(array, shallow, false, []);
      };
    
      // Return a version of the array that does not contain the specified value(s).
      _.without = function(array) {
        return _.difference(array, slice.call(arguments, 1));
      };
    
      // Produce a duplicate-free version of the array. If the array has already
      // been sorted, you have the option of using a faster algorithm.
      // Aliased as `unique`.
      _.uniq = _.unique = function(array, isSorted, iteratee, context) {
        if (array == null) return [];
        if (!_.isBoolean(isSorted)) {
          context = iteratee;
          iteratee = isSorted;
          isSorted = false;
        }
        if (iteratee != null) iteratee = _.iteratee(iteratee, context);
        var result = [];
        var seen = [];
        for (var i = 0, length = array.length; i < length; i++) {
          var value = array[i];
          if (isSorted) {
            if (!i || seen !== value) result.push(value);
            seen = value;
          } else if (iteratee) {
            var computed = iteratee(value, i, array);
            if (_.indexOf(seen, computed) < 0) {
              seen.push(computed);
              result.push(value);
            }
          } else if (_.indexOf(result, value) < 0) {
            result.push(value);
          }
        }
        return result;
      };
    
      // Produce an array that contains the union: each distinct element from all of
      // the passed-in arrays.
      _.union = function() {
        return _.uniq(flatten(arguments, true, true, []));
      };
    
      // Produce an array that contains every item shared between all the
      // passed-in arrays.
      _.intersection = function(array) {
        if (array == null) return [];
        var result = [];
        var argsLength = arguments.length;
        for (var i = 0, length = array.length; i < length; i++) {
          var item = array[i];
          if (_.contains(result, item)) continue;
          for (var j = 1; j < argsLength; j++) {
            if (!_.contains(arguments[j], item)) break;
          }
          if (j === argsLength) result.push(item);
        }
        return result;
      };
    
      // Take the difference between one array and a number of other arrays.
      // Only the elements present in just the first array will remain.
      _.difference = function(array) {
        var rest = flatten(slice.call(arguments, 1), true, true, []);
        return _.filter(array, function(value){
          return !_.contains(rest, value);
        });
      };
    
      // Zip together multiple lists into a single array -- elements that share
      // an index go together.
      _.zip = function(array) {
        if (array == null) return [];
        var length = _.max(arguments, 'length').length;
        var results = Array(length);
        for (var i = 0; i < length; i++) {
          results[i] = _.pluck(arguments, i);
        }
        return results;
      };
    
      // Converts lists into objects. Pass either a single array of `[key, value]`
      // pairs, or two parallel arrays of the same length -- one of keys, and one of
      // the corresponding values.
      _.object = function(list, values) {
        if (list == null) return {};
        var result = {};
        for (var i = 0, length = list.length; i < length; i++) {
          if (values) {
            result[list[i]] = values[i];
          } else {
            result[list[i][0]] = list[i][1];
          }
        }
        return result;
      };
    
      // Return the position of the first occurrence of an item in an array,
      // or -1 if the item is not included in the array.
      // If the array is large and already in sort order, pass `true`
      // for **isSorted** to use binary search.
      _.indexOf = function(array, item, isSorted) {
        if (array == null) return -1;
        var i = 0, length = array.length;
        if (isSorted) {
          if (typeof isSorted == 'number') {
            i = isSorted < 0 ? Math.max(0, length + isSorted) : isSorted;
          } else {
            i = _.sortedIndex(array, item);
            return array[i] === item ? i : -1;
          }
        }
        for (; i < length; i++) if (array[i] === item) return i;
        return -1;
      };
    
      _.lastIndexOf = function(array, item, from) {
        if (array == null) return -1;
        var idx = array.length;
        if (typeof from == 'number') {
          idx = from < 0 ? idx + from + 1 : Math.min(idx, from + 1);
        }
        while (--idx >= 0) if (array[idx] === item) return idx;
        return -1;
      };
    
      // Generate an integer Array containing an arithmetic progression. A port of
      // the native Python `range()` function. See
      // [the Python documentation](http://docs.python.org/library/functions.html#range).
      _.range = function(start, stop, step) {
        if (arguments.length <= 1) {
          stop = start || 0;
          start = 0;
        }
        step = step || 1;
    
        var length = Math.max(Math.ceil((stop - start) / step), 0);
        var range = Array(length);
    
        for (var idx = 0; idx < length; idx++, start += step) {
          range[idx] = start;
        }
    
        return range;
      };
    
      // Function (ahem) Functions
      // ------------------
    
      // Reusable constructor function for prototype setting.
      var Ctor = function(){};
    
      // Create a function bound to a given object (assigning `this`, and arguments,
      // optionally). Delegates to **ECMAScript 5**'s native `Function.bind` if
      // available.
      _.bind = function(func, context) {
        var args, bound;
        if (nativeBind && func.bind === nativeBind) return nativeBind.apply(func, slice.call(arguments, 1));
        if (!_.isFunction(func)) throw new TypeError('Bind must be called on a function');
        args = slice.call(arguments, 2);
        bound = function() {
          if (!(this instanceof bound)) return func.apply(context, args.concat(slice.call(arguments)));
          Ctor.prototype = func.prototype;
          var self = new Ctor;
          Ctor.prototype = null;
          var result = func.apply(self, args.concat(slice.call(arguments)));
          if (_.isObject(result)) return result;
          return self;
        };
        return bound;
      };
    
      // Partially apply a function by creating a version that has had some of its
      // arguments pre-filled, without changing its dynamic `this` context. _ acts
      // as a placeholder, allowing any combination of arguments to be pre-filled.
      _.partial = function(func) {
        var boundArgs = slice.call(arguments, 1);
        return function() {
          var position = 0;
          var args = boundArgs.slice();
          for (var i = 0, length = args.length; i < length; i++) {
            if (args[i] === _) args[i] = arguments[position++];
          }
          while (position < arguments.length) args.push(arguments[position++]);
          return func.apply(this, args);
        };
      };
    
      // Bind a number of an object's methods to that object. Remaining arguments
      // are the method names to be bound. Useful for ensuring that all callbacks
      // defined on an object belong to it.
      _.bindAll = function(obj) {
        var i, length = arguments.length, key;
        if (length <= 1) throw new Error('bindAll must be passed function names');
        for (i = 1; i < length; i++) {
          key = arguments[i];
          obj[key] = _.bind(obj[key], obj);
        }
        return obj;
      };
    
      // Memoize an expensive function by storing its results.
      _.memoize = function(func, hasher) {
        var memoize = function(key) {
          var cache = memoize.cache;
          var address = hasher ? hasher.apply(this, arguments) : key;
          if (!_.has(cache, address)) cache[address] = func.apply(this, arguments);
          return cache[address];
        };
        memoize.cache = {};
        return memoize;
      };
    
      // Delays a function for the given number of milliseconds, and then calls
      // it with the arguments supplied.
      _.delay = function(func, wait) {
        var args = slice.call(arguments, 2);
        return setTimeout(function(){
          return func.apply(null, args);
        }, wait);
      };
    
      // Defers a function, scheduling it to run after the current call stack has
      // cleared.
      _.defer = function(func) {
        return _.delay.apply(_, [func, 1].concat(slice.call(arguments, 1)));
      };
    
      // Returns a function, that, when invoked, will only be triggered at most once
      // during a given window of time. Normally, the throttled function will run
      // as much as it can, without ever going more than once per `wait` duration;
      // but if you'd like to disable the execution on the leading edge, pass
      // `{leading: false}`. To disable execution on the trailing edge, ditto.
      _.throttle = function(func, wait, options) {
        var context, args, result;
        var timeout = null;
        var previous = 0;
        if (!options) options = {};
        var later = function() {
          previous = options.leading === false ? 0 : _.now();
          timeout = null;
          result = func.apply(context, args);
          if (!timeout) context = args = null;
        };
        return function() {
          var now = _.now();
          if (!previous && options.leading === false) previous = now;
          var remaining = wait - (now - previous);
          context = this;
          args = arguments;
          if (remaining <= 0 || remaining > wait) {
            clearTimeout(timeout);
            timeout = null;
            previous = now;
            result = func.apply(context, args);
            if (!timeout) context = args = null;
          } else if (!timeout && options.trailing !== false) {
            timeout = setTimeout(later, remaining);
          }
          return result;
        };
      };
    
      // Returns a function, that, as long as it continues to be invoked, will not
      // be triggered. The function will be called after it stops being called for
      // N milliseconds. If `immediate` is passed, trigger the function on the
      // leading edge, instead of the trailing.
      _.debounce = function(func, wait, immediate) {
        var timeout, args, context, timestamp, result;
    
        var later = function() {
          var last = _.now() - timestamp;
    
          if (last < wait && last > 0) {
            timeout = setTimeout(later, wait - last);
          } else {
            timeout = null;
            if (!immediate) {
              result = func.apply(context, args);
              if (!timeout) context = args = null;
            }
          }
        };
    
        return function() {
          context = this;
          args = arguments;
          timestamp = _.now();
          var callNow = immediate && !timeout;
          if (!timeout) timeout = setTimeout(later, wait);
          if (callNow) {
            result = func.apply(context, args);
            context = args = null;
          }
    
          return result;
        };
      };
    
      // Returns the first function passed as an argument to the second,
      // allowing you to adjust arguments, run code before and after, and
      // conditionally execute the original function.
      _.wrap = function(func, wrapper) {
        return _.partial(wrapper, func);
      };
    
      // Returns a negated version of the passed-in predicate.
      _.negate = function(predicate) {
        return function() {
          return !predicate.apply(this, arguments);
        };
      };
    
      // Returns a function that is the composition of a list of functions, each
      // consuming the return value of the function that follows.
      _.compose = function() {
        var args = arguments;
        var start = args.length - 1;
        return function() {
          var i = start;
          var result = args[start].apply(this, arguments);
          while (i--) result = args[i].call(this, result);
          return result;
        };
      };
    
      // Returns a function that will only be executed after being called N times.
      _.after = function(times, func) {
        return function() {
          if (--times < 1) {
            return func.apply(this, arguments);
          }
        };
      };
    
      // Returns a function that will only be executed before being called N times.
      _.before = function(times, func) {
        var memo;
        return function() {
          if (--times > 0) {
            memo = func.apply(this, arguments);
          } else {
            func = null;
          }
          return memo;
        };
      };
    
      // Returns a function that will be executed at most one time, no matter how
      // often you call it. Useful for lazy initialization.
      _.once = _.partial(_.before, 2);
    
      // Object Functions
      // ----------------
    
      // Retrieve the names of an object's properties.
      // Delegates to **ECMAScript 5**'s native `Object.keys`
      _.keys = function(obj) {
        if (!_.isObject(obj)) return [];
        if (nativeKeys) return nativeKeys(obj);
        var keys = [];
        for (var key in obj) if (_.has(obj, key)) keys.push(key);
        return keys;
      };
    
      // Retrieve the values of an object's properties.
      _.values = function(obj) {
        var keys = _.keys(obj);
        var length = keys.length;
        var values = Array(length);
        for (var i = 0; i < length; i++) {
          values[i] = obj[keys[i]];
        }
        return values;
      };
    
      // Convert an object into a list of `[key, value]` pairs.
      _.pairs = function(obj) {
        var keys = _.keys(obj);
        var length = keys.length;
        var pairs = Array(length);
        for (var i = 0; i < length; i++) {
          pairs[i] = [keys[i], obj[keys[i]]];
        }
        return pairs;
      };
    
      // Invert the keys and values of an object. The values must be serializable.
      _.invert = function(obj) {
        var result = {};
        var keys = _.keys(obj);
        for (var i = 0, length = keys.length; i < length; i++) {
          result[obj[keys[i]]] = keys[i];
        }
        return result;
      };
    
      // Return a sorted list of the function names available on the object.
      // Aliased as `methods`
      _.functions = _.methods = function(obj) {
        var names = [];
        for (var key in obj) {
          if (_.isFunction(obj[key])) names.push(key);
        }
        return names.sort();
      };
    
      // Extend a given object with all the properties in passed-in object(s).
      _.extend = function(obj) {
        if (!_.isObject(obj)) return obj;
        var source, prop;
        for (var i = 1, length = arguments.length; i < length; i++) {
          source = arguments[i];
          for (prop in source) {
            if (hasOwnProperty.call(source, prop)) {
                obj[prop] = source[prop];
            }
          }
        }
        return obj;
      };
    
      // Return a copy of the object only containing the whitelisted properties.
      _.pick = function(obj, iteratee, context) {
        var result = {}, key;
        if (obj == null) return result;
        if (_.isFunction(iteratee)) {
          iteratee = createCallback(iteratee, context);
          for (key in obj) {
            var value = obj[key];
            if (iteratee(value, key, obj)) result[key] = value;
          }
        } else {
          var keys = concat.apply([], slice.call(arguments, 1));
          obj = new Object(obj);
          for (var i = 0, length = keys.length; i < length; i++) {
            key = keys[i];
            if (key in obj) result[key] = obj[key];
          }
        }
        return result;
      };
    
       // Return a copy of the object without the blacklisted properties.
      _.omit = function(obj, iteratee, context) {
        if (_.isFunction(iteratee)) {
          iteratee = _.negate(iteratee);
        } else {
          var keys = _.map(concat.apply([], slice.call(arguments, 1)), String);
          iteratee = function(value, key) {
            return !_.contains(keys, key);
          };
        }
        return _.pick(obj, iteratee, context);
      };
    
      // Fill in a given object with default properties.
      _.defaults = function(obj) {
        if (!_.isObject(obj)) return obj;
        for (var i = 1, length = arguments.length; i < length; i++) {
          var source = arguments[i];
          for (var prop in source) {
            if (obj[prop] === void 0) obj[prop] = source[prop];
          }
        }
        return obj;
      };
    
      // Create a (shallow-cloned) duplicate of an object.
      _.clone = function(obj) {
        if (!_.isObject(obj)) return obj;
        return _.isArray(obj) ? obj.slice() : _.extend({}, obj);
      };
    
      // Invokes interceptor with the obj, and then returns obj.
      // The primary purpose of this method is to "tap into" a method chain, in
      // order to perform operations on intermediate results within the chain.
      _.tap = function(obj, interceptor) {
        interceptor(obj);
        return obj;
      };
    
      // Internal recursive comparison function for `isEqual`.
      var eq = function(a, b, aStack, bStack) {
        // Identical objects are equal. `0 === -0`, but they aren't identical.
        // See the [Harmony `egal` proposal](http://wiki.ecmascript.org/doku.php?id=harmony:egal).
        if (a === b) return a !== 0 || 1 / a === 1 / b;
        // A strict comparison is necessary because `null == undefined`.
        if (a == null || b == null) return a === b;
        // Unwrap any wrapped objects.
        if (a instanceof _) a = a._wrapped;
        if (b instanceof _) b = b._wrapped;
        // Compare `[[Class]]` names.
        var className = toString.call(a);
        if (className !== toString.call(b)) return false;
        switch (className) {
          // Strings, numbers, regular expressions, dates, and booleans are compared by value.
          case '[object RegExp]':
          // RegExps are coerced to strings for comparison (Note: '' + /a/i === '/a/i')
          case '[object String]':
            // Primitives and their corresponding object wrappers are equivalent; thus, `"5"` is
            // equivalent to `new String("5")`.
            return '' + a === '' + b;
          case '[object Number]':
            // `NaN`s are equivalent, but non-reflexive.
            // Object(NaN) is equivalent to NaN
            if (+a !== +a) return +b !== +b;
            // An `egal` comparison is performed for other numeric values.
            return +a === 0 ? 1 / +a === 1 / b : +a === +b;
          case '[object Date]':
          case '[object Boolean]':
            // Coerce dates and booleans to numeric primitive values. Dates are compared by their
            // millisecond representations. Note that invalid dates with millisecond representations
            // of `NaN` are not equivalent.
            return +a === +b;
        }
        if (typeof a != 'object' || typeof b != 'object') return false;
        // Assume equality for cyclic structures. The algorithm for detecting cyclic
        // structures is adapted from ES 5.1 section 15.12.3, abstract operation `JO`.
        var length = aStack.length;
        while (length--) {
          // Linear search. Performance is inversely proportional to the number of
          // unique nested structures.
          if (aStack[length] === a) return bStack[length] === b;
        }
        // Objects with different constructors are not equivalent, but `Object`s
        // from different frames are.
        var aCtor = a.constructor, bCtor = b.constructor;
        if (
          aCtor !== bCtor &&
          // Handle Object.create(x) cases
          'constructor' in a && 'constructor' in b &&
          !(_.isFunction(aCtor) && aCtor instanceof aCtor &&
            _.isFunction(bCtor) && bCtor instanceof bCtor)
        ) {
          return false;
        }
        // Add the first object to the stack of traversed objects.
        aStack.push(a);
        bStack.push(b);
        var size, result;
        // Recursively compare objects and arrays.
        if (className === '[object Array]') {
          // Compare array lengths to determine if a deep comparison is necessary.
          size = a.length;
          result = size === b.length;
          if (result) {
            // Deep compare the contents, ignoring non-numeric properties.
            while (size--) {
              if (!(result = eq(a[size], b[size], aStack, bStack))) break;
            }
          }
        } else {
          // Deep compare objects.
          var keys = _.keys(a), key;
          size = keys.length;
          // Ensure that both objects contain the same number of properties before comparing deep equality.
          result = _.keys(b).length === size;
          if (result) {
            while (size--) {
              // Deep compare each member
              key = keys[size];
              if (!(result = _.has(b, key) && eq(a[key], b[key], aStack, bStack))) break;
            }
          }
        }
        // Remove the first object from the stack of traversed objects.
        aStack.pop();
        bStack.pop();
        return result;
      };
    
      // Perform a deep comparison to check if two objects are equal.
      _.isEqual = function(a, b) {
        return eq(a, b, [], []);
      };
    
      // Is a given array, string, or object empty?
      // An "empty" object has no enumerable own-properties.
      _.isEmpty = function(obj) {
        if (obj == null) return true;
        if (_.isArray(obj) || _.isString(obj) || _.isArguments(obj)) return obj.length === 0;
        for (var key in obj) if (_.has(obj, key)) return false;
        return true;
      };
    
      // Is a given value a DOM element?
      _.isElement = function(obj) {
        return !!(obj && obj.nodeType === 1);
      };
    
      // Is a given value an array?
      // Delegates to ECMA5's native Array.isArray
      _.isArray = nativeIsArray || function(obj) {
        return toString.call(obj) === '[object Array]';
      };
    
      // Is a given variable an object?
      _.isObject = function(obj) {
        var type = typeof obj;
        return type === 'function' || type === 'object' && !!obj;
      };
    
      // Add some isType methods: isArguments, isFunction, isString, isNumber, isDate, isRegExp.
      _.each(['Arguments', 'Function', 'String', 'Number', 'Date', 'RegExp'], function(name) {
        _['is' + name] = function(obj) {
          return toString.call(obj) === '[object ' + name + ']';
        };
      });
    
      // Define a fallback version of the method in browsers (ahem, IE), where
      // there isn't any inspectable "Arguments" type.
      if (!_.isArguments(arguments)) {
        _.isArguments = function(obj) {
          return _.has(obj, 'callee');
        };
      }
    
      // Optimize `isFunction` if appropriate. Work around an IE 11 bug.
      if (typeof /./ !== 'function') {
        _.isFunction = function(obj) {
          return typeof obj == 'function' || false;
        };
      }
    
      // Is a given object a finite number?
      _.isFinite = function(obj) {
        return isFinite(obj) && !isNaN(parseFloat(obj));
      };
    
      // Is the given value `NaN`? (NaN is the only number which does not equal itself).
      _.isNaN = function(obj) {
        return _.isNumber(obj) && obj !== +obj;
      };
    
      // Is a given value a boolean?
      _.isBoolean = function(obj) {
        return obj === true || obj === false || toString.call(obj) === '[object Boolean]';
      };
    
      // Is a given value equal to null?
      _.isNull = function(obj) {
        return obj === null;
      };
    
      // Is a given variable undefined?
      _.isUndefined = function(obj) {
        return obj === void 0;
      };
    
      // Shortcut function for checking if an object has a given property directly
      // on itself (in other words, not on a prototype).
      _.has = function(obj, key) {
        return obj != null && hasOwnProperty.call(obj, key);
      };
    
      // Utility Functions
      // -----------------
    
      // Run Underscore.js in *noConflict* mode, returning the `_` variable to its
      // previous owner. Returns a reference to the Underscore object.
      _.noConflict = function() {
        root._ = previousUnderscore;
        return this;
      };
    
      // Keep the identity function around for default iteratees.
      _.identity = function(value) {
        return value;
      };
    
      // Predicate-generating functions. Often useful outside of Underscore.
      _.constant = function(value) {
        return function() {
          return value;
        };
      };
    
      _.noop = function(){};
    
      _.property = function(key) {
        return function(obj) {
          return obj[key];
        };
      };
    
      // Returns a predicate for checking whether an object has a given set of `key:value` pairs.
      _.matches = function(attrs) {
        var pairs = _.pairs(attrs), length = pairs.length;
        return function(obj) {
          if (obj == null) return !length;
          obj = new Object(obj);
          for (var i = 0; i < length; i++) {
            var pair = pairs[i], key = pair[0];
            if (pair[1] !== obj[key] || !(key in obj)) return false;
          }
          return true;
        };
      };
    
      // Run a function **n** times.
      _.times = function(n, iteratee, context) {
        var accum = Array(Math.max(0, n));
        iteratee = createCallback(iteratee, context, 1);
        for (var i = 0; i < n; i++) accum[i] = iteratee(i);
        return accum;
      };
    
      // Return a random integer between min and max (inclusive).
      _.random = function(min, max) {
        if (max == null) {
          max = min;
          min = 0;
        }
        return min + Math.floor(Math.random() * (max - min + 1));
      };
    
      // A (possibly faster) way to get the current timestamp as an integer.
      _.now = Date.now || function() {
        return new Date().getTime();
      };
    
       // List of HTML entities for escaping.
      var escapeMap = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '`': '&#x60;'
      };
      var unescapeMap = _.invert(escapeMap);
    
      // Functions for escaping and unescaping strings to/from HTML interpolation.
      var createEscaper = function(map) {
        var escaper = function(match) {
          return map[match];
        };
        // Regexes for identifying a key that needs to be escaped
        var source = '(?:' + _.keys(map).join('|') + ')';
        var testRegexp = RegExp(source);
        var replaceRegexp = RegExp(source, 'g');
        return function(string) {
          string = string == null ? '' : '' + string;
          return testRegexp.test(string) ? string.replace(replaceRegexp, escaper) : string;
        };
      };
      _.escape = createEscaper(escapeMap);
      _.unescape = createEscaper(unescapeMap);
    
      // If the value of the named `property` is a function then invoke it with the
      // `object` as context; otherwise, return it.
      _.result = function(object, property) {
        if (object == null) return void 0;
        var value = object[property];
        return _.isFunction(value) ? object[property]() : value;
      };
    
      // Generate a unique integer id (unique within the entire client session).
      // Useful for temporary DOM ids.
      var idCounter = 0;
      _.uniqueId = function(prefix) {
        var id = ++idCounter + '';
        return prefix ? prefix + id : id;
      };
    
      // By default, Underscore uses ERB-style template delimiters, change the
      // following template settings to use alternative delimiters.
      _.templateSettings = {
        evaluate    : /<%([\s\S]+?)%>/g,
        interpolate : /<%=([\s\S]+?)%>/g,
        escape      : /<%-([\s\S]+?)%>/g
      };
    
      // When customizing `templateSettings`, if you don't want to define an
      // interpolation, evaluation or escaping regex, we need one that is
      // guaranteed not to match.
      var noMatch = /(.)^/;
    
      // Certain characters need to be escaped so that they can be put into a
      // string literal.
      var escapes = {
        "'":      "'",
        '\\':     '\\',
        '\r':     'r',
        '\n':     'n',
        '\u2028': 'u2028',
        '\u2029': 'u2029'
      };
    
      var escaper = /\\|'|\r|\n|\u2028|\u2029/g;
    
      var escapeChar = function(match) {
        return '\\' + escapes[match];
      };
    
      // JavaScript micro-templating, similar to John Resig's implementation.
      // Underscore templating handles arbitrary delimiters, preserves whitespace,
      // and correctly escapes quotes within interpolated code.
      // NB: `oldSettings` only exists for backwards compatibility.
      _.template = function(text, settings, oldSettings) {
        if (!settings && oldSettings) settings = oldSettings;
        settings = _.defaults({}, settings, _.templateSettings);
    
        // Combine delimiters into one regular expression via alternation.
        var matcher = RegExp([
          (settings.escape || noMatch).source,
          (settings.interpolate || noMatch).source,
          (settings.evaluate || noMatch).source
        ].join('|') + '|$', 'g');
    
        // Compile the template source, escaping string literals appropriately.
        var index = 0;
        var source = "__p+='";
        text.replace(matcher, function(match, escape, interpolate, evaluate, offset) {
          source += text.slice(index, offset).replace(escaper, escapeChar);
          index = offset + match.length;
    
          if (escape) {
            source += "'+\n((__t=(" + escape + "))==null?'':_.escape(__t))+\n'";
          } else if (interpolate) {
            source += "'+\n((__t=(" + interpolate + "))==null?'':__t)+\n'";
          } else if (evaluate) {
            source += "';\n" + evaluate + "\n__p+='";
          }
    
          // Adobe VMs need the match returned to produce the correct offest.
          return match;
        });
        source += "';\n";
    
        // If a variable is not specified, place data values in local scope.
        if (!settings.variable) source = 'with(obj||{}){\n' + source + '}\n';
    
        source = "var __t,__p='',__j=Array.prototype.join," +
          "print=function(){__p+=__j.call(arguments,'');};\n" +
          source + 'return __p;\n';
    
        try {
          var render = new Function(settings.variable || 'obj', '_', source);
        } catch (e) {
          e.source = source;
          throw e;
        }
    
        var template = function(data) {
          return render.call(this, data, _);
        };
    
        // Provide the compiled source as a convenience for precompilation.
        var argument = settings.variable || 'obj';
        template.source = 'function(' + argument + '){\n' + source + '}';
    
        return template;
      };
    
      // Add a "chain" function. Start chaining a wrapped Underscore object.
      _.chain = function(obj) {
        var instance = _(obj);
        instance._chain = true;
        return instance;
      };
    
      // OOP
      // ---------------
      // If Underscore is called as a function, it returns a wrapped object that
      // can be used OO-style. This wrapper holds altered versions of all the
      // underscore functions. Wrapped objects may be chained.
    
      // Helper function to continue chaining intermediate results.
      var result = function(obj) {
        return this._chain ? _(obj).chain() : obj;
      };
    
      // Add your own custom functions to the Underscore object.
      _.mixin = function(obj) {
        _.each(_.functions(obj), function(name) {
          var func = _[name] = obj[name];
          _.prototype[name] = function() {
            var args = [this._wrapped];
            push.apply(args, arguments);
            return result.call(this, func.apply(_, args));
          };
        });
      };
    
      // Add all of the Underscore functions to the wrapper object.
      _.mixin(_);
    
      // Add all mutator Array functions to the wrapper.
      _.each(['pop', 'push', 'reverse', 'shift', 'sort', 'splice', 'unshift'], function(name) {
        var method = ArrayProto[name];
        _.prototype[name] = function() {
          var obj = this._wrapped;
          method.apply(obj, arguments);
          if ((name === 'shift' || name === 'splice') && obj.length === 0) delete obj[0];
          return result.call(this, obj);
        };
      });
    
      // Add all accessor Array functions to the wrapper.
      _.each(['concat', 'join', 'slice'], function(name) {
        var method = ArrayProto[name];
        _.prototype[name] = function() {
          return result.call(this, method.apply(this._wrapped, arguments));
        };
      });
    
      // Extracts the result from a wrapped and chained object.
      _.prototype.value = function() {
        return this._wrapped;
      };
    
      // AMD registration happens at the end for compatibility with AMD loaders
      // that may not enforce next-turn semantics on modules. Even though general
      // practice for AMD registration is to be anonymous, underscore registers
      // as a named module because, like jQuery, it is a base library that is
      // popular enough to be bundled in a third party lib, but not be part of
      // an AMD load request. Those cases could generate an error when an
      // anonymous define() is called outside of a loader request.
      // if (typeof define === 'function' && define.amd) {
      //   define('underscore', [], function() {
      //     return _;
      //   });
      // }
    }.call({}));
    
    /*!
     * Sizzle CSS Selector Engine v2.3.5-pre
     * https://sizzlejs.com/
     *
     * Copyright JS Foundation and other contributors
     * Released under the MIT license
     * https://js.foundation/
     *
     * Date: 2019-10-21
     */
    
     var SIZZLE_EXT = {};
    
    ( function( window ) {
    var i,
        support,
        Expr,
        getText,
        isXML,
        tokenize,
        compile,
        select,
        outermostContext,
        sortInput,
        hasDuplicate,
    
        // Local document vars
        setDocument,
        document,
        docElem,
        documentIsHTML,
        rbuggyQSA,
        rbuggyMatches,
        matches,
        contains,
    
        // Instance-specific data
        expando = "sizzle" + 1 * new Date(),
        preferredDoc = window.document,
        dirruns = 0,
        done = 0,
        classCache = createCache(),
        tokenCache = createCache(),
        compilerCache = createCache(),
        nonnativeSelectorCache = createCache(),
        sortOrder = function( a, b ) {
            if ( a === b ) {
                hasDuplicate = true;
            }
            return 0;
        },
    
        // Instance methods
        hasOwn = ( {} ).hasOwnProperty,
        arr = [],
        pop = arr.pop,
        pushNative = arr.push,
        push = arr.push,
        slice = arr.slice,
    
        // Use a stripped-down indexOf as it's faster than native
        // https://jsperf.com/thor-indexof-vs-for/5
        indexOf = function( list, elem ) {
            var i = 0,
                len = list.length;
            for ( ; i < len; i++ ) {
                if ( list[ i ] === elem ) {
                    return i;
                }
            }
            return -1;
        },
    
        booleans = "checked|selected|async|autofocus|autoplay|controls|defer|disabled|hidden|" +
            "ismap|loop|multiple|open|readonly|required|scoped",
    
        // Regular expressions
    
        // http://www.w3.org/TR/css3-selectors/#whitespace
        whitespace = "[\\x20\\t\\r\\n\\f]",
    
        // https://www.w3.org/TR/css-syntax-3/#ident-token-diagram
        identifier = "(?:\\\\[\\da-fA-F]{1,6}" + whitespace +
            "?|\\\\[^\\r\\n\\f]|[\\w-]|[^\0-\\x7f])+",
    
        // Attribute selectors: http://www.w3.org/TR/selectors/#attribute-selectors
        attributes = "\\[" + whitespace + "*(" + identifier + ")(?:" + whitespace +
    
            // Operator (capture 2)
            "*([*^$|!~]?=)" + whitespace +
    
            // "Attribute values must be CSS identifiers [capture 5]
            // or strings [capture 3 or capture 4]"
            "*(?:'((?:\\\\.|[^\\\\'])*)'|\"((?:\\\\.|[^\\\\\"])*)\"|(" + identifier + "))|)" +
            whitespace + "*\\]",
    
        pseudos = ":(" + identifier + ")(?:\\((" +
    
            // To reduce the number of selectors needing tokenize in the preFilter, prefer arguments:
            // 1. quoted (capture 3; capture 4 or capture 5)
            "('((?:\\\\.|[^\\\\'])*)'|\"((?:\\\\.|[^\\\\\"])*)\")|" +
    
            // 2. simple (capture 6)
            "((?:\\\\.|[^\\\\()[\\]]|" + attributes + ")*)|" +
    
            // 3. anything else (capture 2)
            ".*" +
            ")\\)|)",
    
        // Leading and non-escaped trailing whitespace, capturing some non-whitespace characters preceding the latter
        rwhitespace = new RegExp( whitespace + "+", "g" ),
        rtrim = new RegExp( "^" + whitespace + "+|((?:^|[^\\\\])(?:\\\\.)*)" +
            whitespace + "+$", "g" ),
    
        rcomma = new RegExp( "^" + whitespace + "*," + whitespace + "*" ),
        rcombinators = new RegExp( "^" + whitespace + "*([>+~]|" + whitespace + ")" + whitespace +
            "*" ),
        rdescend = new RegExp( whitespace + "|>" ),
    
        rpseudo = new RegExp( pseudos ),
        ridentifier = new RegExp( "^" + identifier + "$" ),
    
        matchExpr = {
            "ID": new RegExp( "^#(" + identifier + ")" ),
            "CLASS": new RegExp( "^\\.(" + identifier + ")" ),
            "TAG": new RegExp( "^(" + identifier + "|[*])" ),
            "ATTR": new RegExp( "^" + attributes ),
            "PSEUDO": new RegExp( "^" + pseudos ),
            "CHILD": new RegExp( "^:(only|first|last|nth|nth-last)-(child|of-type)(?:\\(" +
                whitespace + "*(even|odd|(([+-]|)(\\d*)n|)" + whitespace + "*(?:([+-]|)" +
                whitespace + "*(\\d+)|))" + whitespace + "*\\)|)", "i" ),
            "bool": new RegExp( "^(?:" + booleans + ")$", "i" ),
    
            // For use in libraries implementing .is()
            // We use this for POS matching in `select`
            "needsContext": new RegExp( "^" + whitespace +
                "*[>+~]|:(even|odd|eq|gt|lt|nth|first|last)(?:\\(" + whitespace +
                "*((?:-\\d)?\\d*)" + whitespace + "*\\)|)(?=[^-]|$)", "i" )
        },
    
        rhtml = /HTML$/i,
        rinputs = /^(?:input|select|textarea|button)$/i,
        rheader = /^h\d$/i,
    
        rnative = {
            test: function (fn) {
                if (typeof ShadyDOM !== 'undefined' && typeof fn === 'function') {
                    return true;
                }
                return /^[^{]+\{\s*\[native \w/.test(fn);
            }
        },
    
        // Easily-parseable/retrievable ID or TAG or CLASS selectors
        rquickExpr = /^(?:#([\w-]+)|(\w+)|\.([\w-]+))$/,
    
        rsibling = /[+~]/,
    
        // CSS escapes
        // http://www.w3.org/TR/CSS21/syndata.html#escaped-characters
        runescape = new RegExp( "\\\\[\\da-fA-F]{1,6}" + whitespace + "?|\\\\([^\\r\\n\\f])", "g" ),
        funescape = function( escape, nonHex ) {
            var high = "0x" + escape.slice( 1 ) - 0x10000;
    
            return nonHex ?
    
                // Strip the backslash prefix from a non-hex escape sequence
                nonHex :
    
                // Replace a hexadecimal escape sequence with the encoded Unicode code point
                // Support: IE <=11+
                // For values outside the Basic Multilingual Plane (BMP), manually construct a
                // surrogate pair
                high < 0 ?
                    String.fromCharCode( high + 0x10000 ) :
                    String.fromCharCode( high >> 10 | 0xD800, high & 0x3FF | 0xDC00 );
        },
    
        // CSS string/identifier serialization
        // https://drafts.csswg.org/cssom/#common-serializing-idioms
        rcssescape = /([\0-\x1f\x7f]|^-?\d)|^-$|[^\0-\x1f\x7f-\uFFFF\w-]/g,
        fcssescape = function( ch, asCodePoint ) {
            if ( asCodePoint ) {
    
                // U+0000 NULL becomes U+FFFD REPLACEMENT CHARACTER
                if ( ch === "\0" ) {
                    return "\uFFFD";
                }
    
                // Control characters and (dependent upon position) numbers get escaped as code points
                return ch.slice( 0, -1 ) + "\\" +
                    ch.charCodeAt( ch.length - 1 ).toString( 16 ) + " ";
            }
    
            // Other potentially-special ASCII characters get backslash-escaped
            return "\\" + ch;
        },
    
        // Used for iframes
        // See setDocument()
        // Removing the function wrapper causes a "Permission Denied"
        // error in IE
        unloadHandler = function() {
            setDocument();
        },
    
        inDisabledFieldset = addCombinator(
            function( elem ) {
                return elem.disabled === true && elem.nodeName.toLowerCase() === "fieldset";
            },
            { dir: "parentNode", next: "legend" }
        );
    
    // Optimize for push.apply( _, NodeList )
    try {
        push.apply(
            ( arr = slice.call( preferredDoc.childNodes ) ),
            preferredDoc.childNodes
        );
    
        // Support: Android<4.0
        // Detect silently failing push.apply
        // eslint-disable-next-line no-unused-expressions
        arr[ preferredDoc.childNodes.length ].nodeType;
    } catch ( e ) {
        push = { apply: arr.length ?
    
            // Leverage slice if possible
            function( target, els ) {
                pushNative.apply( target, slice.call( els ) );
            } :
    
            // Support: IE<9
            // Otherwise append directly
            function( target, els ) {
                var j = target.length,
                    i = 0;
    
                // Can't trust NodeList.length
                while ( ( target[ j++ ] = els[ i++ ] ) ) {}
                target.length = j - 1;
            }
        };
    }
    
    function Sizzle( selector, context, results, seed ) {
        var m, i, elem, nid, match, groups, newSelector,
            newContext = context && context.ownerDocument,
    
            // nodeType defaults to 9, since context defaults to document
            nodeType = context ? context.nodeType : 9;
    
        results = results || [];
    
        // Return early from calls with invalid selector or context
        if ( typeof selector !== "string" || !selector ||
            nodeType !== 1 && nodeType !== 9 && nodeType !== 11 ) {
    
            return results;
        }
    
        // Try to shortcut find operations (as opposed to filters) in HTML documents
        if ( !seed ) {
            setDocument( context );
            context = context || document;
    
            if ( documentIsHTML ) {
    
                // If the selector is sufficiently simple, try using a "get*By*" DOM method
                // (excepting DocumentFragment context, where the methods don't exist)
                if ( nodeType !== 11 && ( match = rquickExpr.exec( selector ) ) ) {
    
                    // ID selector
                    if ( ( m = match[ 1 ] ) ) {
    
                        // Document context
                        if ( nodeType === 9 ) {
                            if ( ( elem = context.getElementById( m ) ) ) {
    
                                // Support: IE, Opera, Webkit
                                // TODO: identify versions
                                // getElementById can match elements by name instead of ID
                                if ( elem.id === m ) {
                                    results.push( elem );
                                    return results;
                                }
                            } else {
                                return results;
                            }
    
                        // Element context
                        } else {
    
                            // Support: IE, Opera, Webkit
                            // TODO: identify versions
                            // getElementById can match elements by name instead of ID
                            if ( newContext && ( elem = newContext.getElementById( m ) ) &&
                                contains( context, elem ) &&
                                elem.id === m ) {
    
                                results.push( elem );
                                return results;
                            }
                        }
    
                    // Type selector
                    } else if ( match[ 2 ] ) {
                        push.apply( results, context.getElementsByTagName( selector ) );
                        return results;
    
                    // Class selector
                    } else if ( ( m = match[ 3 ] ) && support.getElementsByClassName &&
                        context.getElementsByClassName ) {
    
                        push.apply( results, context.getElementsByClassName( m ) );
                        return results;
                    }
                }
    
                // Take advantage of querySelectorAll
                if ( support.qsa &&
                    !nonnativeSelectorCache[ selector + " " ] &&
                    ( !rbuggyQSA || !rbuggyQSA.test( selector ) ) &&
    
                    // Support: IE 8 only
                    // Exclude object elements
                    ( nodeType !== 1 || context.nodeName.toLowerCase() !== "object" ) ) {
    
                    newSelector = selector;
                    newContext = context;
    
                    // qSA considers elements outside a scoping root when evaluating child or
                    // descendant combinators, which is not what we want.
                    // In such cases, we work around the behavior by prefixing every selector in the
                    // list with an ID selector referencing the scope context.
                    // The technique has to be used as well when a leading combinator is used
                    // as such selectors are not recognized by querySelectorAll.
                    // Thanks to Andrew Dupont for this technique.
                    if ( nodeType === 1 &&
                        ( rdescend.test( selector ) || rcombinators.test( selector ) ) ) {
    
                        // Expand context for sibling selectors
                        newContext = rsibling.test( selector ) && testContext( context.parentNode ) ||
                            context;
    
                        // We can use :scope instead of the ID hack if the browser
                        // supports it & if we're not changing the context.
                        if ( newContext !== context || !support.scope ) {
    
                            // Capture the context ID, setting it first if necessary
                            if ( ( nid = context.getAttribute( "id" ) ) ) {
                                nid = nid.replace( rcssescape, fcssescape );
                            } else {
                                context.setAttribute( "id", ( nid = expando ) );
                            }
                        }
    
                        // Prefix every selector in the list
                        groups = tokenize( selector );
                        i = groups.length;
                        while ( i-- ) {
                            groups[ i ] = ( nid ? "#" + nid : ":scope" ) + " " +
                                toSelector( groups[ i ] );
                        }
                        newSelector = groups.join( "," );
                    }
    
                    try {
                        push.apply( results,
                            newContext.querySelectorAll( newSelector )
                        );
                        return results;
                    } catch ( qsaError ) {
                        nonnativeSelectorCache( selector, true );
                    } finally {
                        if ( nid === expando ) {
                            context.removeAttribute( "id" );
                        }
                    }
                }
            }
        }
    
        // All others
        return select( selector.replace( rtrim, "$1" ), context, results, seed );
    }
    
    /**
     * Create key-value caches of limited size
     * @returns {function(string, object)} Returns the Object data after storing it on itself with
     *	property name the (space-suffixed) string and (if the cache is larger than Expr.cacheLength)
     *	deleting the oldest entry
     */
    function createCache() {
        var keys = [];
    
        function cache( key, value ) {
    
            // Use (key + " ") to avoid collision with native prototype properties (see Issue #157)
            if ( keys.push( key + " " ) > Expr.cacheLength ) {
    
                // Only keep the most recent entries
                delete cache[ keys.shift() ];
            }
            return ( cache[ key + " " ] = value );
        }
        return cache;
    }
    
    /**
     * Mark a function for special use by Sizzle
     * @param {Function} fn The function to mark
     */
    function markFunction( fn ) {
        fn[ expando ] = true;
        return fn;
    }
    
    /**
     * Support testing using an element
     * @param {Function} fn Passed the created element and returns a boolean result
     */
    function assert( fn ) {
        var el = document.createElement( "fieldset" );
    
        try {
            return !!fn( el );
        } catch ( e ) {
            return false;
        } finally {
    
            // Remove from its parent by default
            if ( el.parentNode ) {
                el.parentNode.removeChild( el );
            }
    
            // release memory in IE
            el = null;
        }
    }
    
    /**
     * Adds the same handler for all of the specified attrs
     * @param {String} attrs Pipe-separated list of attributes
     * @param {Function} handler The method that will be applied
     */
    function addHandle( attrs, handler ) {
        var arr = attrs.split( "|" ),
            i = arr.length;
    
        while ( i-- ) {
            Expr.attrHandle[ arr[ i ] ] = handler;
        }
    }
    
    /**
     * Checks document order of two siblings
     * @param {Element} a
     * @param {Element} b
     * @returns {Number} Returns less than 0 if a precedes b, greater than 0 if a follows b
     */
    function siblingCheck( a, b ) {
        var cur = b && a,
            diff = cur && a.nodeType === 1 && b.nodeType === 1 &&
                a.sourceIndex - b.sourceIndex;
    
        // Use IE sourceIndex if available on both nodes
        if ( diff ) {
            return diff;
        }
    
        // Check if b follows a
        if ( cur ) {
            while ( ( cur = cur.nextSibling ) ) {
                if ( cur === b ) {
                    return -1;
                }
            }
        }
    
        return a ? 1 : -1;
    }
    
    /**
     * Returns a function to use in pseudos for input types
     * @param {String} type
     */
    function createInputPseudo( type ) {
        return function( elem ) {
            var name = elem.nodeName.toLowerCase();
            return name === "input" && elem.type === type;
        };
    }
    
    /**
     * Returns a function to use in pseudos for buttons
     * @param {String} type
     */
    function createButtonPseudo( type ) {
        return function( elem ) {
            var name = elem.nodeName.toLowerCase();
            return ( name === "input" || name === "button" ) && elem.type === type;
        };
    }
    
    /**
     * Returns a function to use in pseudos for :enabled/:disabled
     * @param {Boolean} disabled true for :disabled; false for :enabled
     */
    function createDisabledPseudo( disabled ) {
    
        // Known :disabled false positives: fieldset[disabled] > legend:nth-of-type(n+2) :can-disable
        return function( elem ) {
    
            // Only certain elements can match :enabled or :disabled
            // https://html.spec.whatwg.org/multipage/scripting.html#selector-enabled
            // https://html.spec.whatwg.org/multipage/scripting.html#selector-disabled
            if ( "form" in elem ) {
    
                // Check for inherited disabledness on relevant non-disabled elements:
                // * listed form-associated elements in a disabled fieldset
                //   https://html.spec.whatwg.org/multipage/forms.html#category-listed
                //   https://html.spec.whatwg.org/multipage/forms.html#concept-fe-disabled
                // * option elements in a disabled optgroup
                //   https://html.spec.whatwg.org/multipage/forms.html#concept-option-disabled
                // All such elements have a "form" property.
                if ( elem.parentNode && elem.disabled === false ) {
    
                    // Option elements defer to a parent optgroup if present
                    if ( "label" in elem ) {
                        if ( "label" in elem.parentNode ) {
                            return elem.parentNode.disabled === disabled;
                        } else {
                            return elem.disabled === disabled;
                        }
                    }
    
                    // Support: IE 6 - 11
                    // Use the isDisabled shortcut property to check for disabled fieldset ancestors
                    return elem.isDisabled === disabled ||
    
                        // Where there is no isDisabled, check manually
                        /* jshint -W018 */
                        elem.isDisabled !== !disabled &&
                        inDisabledFieldset( elem ) === disabled;
                }
    
                return elem.disabled === disabled;
    
            // Try to winnow out elements that can't be disabled before trusting the disabled property.
            // Some victims get caught in our net (label, legend, menu, track), but it shouldn't
            // even exist on them, let alone have a boolean value.
            } else if ( "label" in elem ) {
                return elem.disabled === disabled;
            }
    
            // Remaining elements are neither :enabled nor :disabled
            return false;
        };
    }
    
    /**
     * Returns a function to use in pseudos for positionals
     * @param {Function} fn
     */
    function createPositionalPseudo( fn ) {
        return markFunction( function( argument ) {
            argument = +argument;
            return markFunction( function( seed, matches ) {
                var j,
                    matchIndexes = fn( [], seed.length, argument ),
                    i = matchIndexes.length;
    
                // Match elements found at the specified indexes
                while ( i-- ) {
                    if ( seed[ ( j = matchIndexes[ i ] ) ] ) {
                        seed[ j ] = !( matches[ j ] = seed[ j ] );
                    }
                }
            } );
        } );
    }
    
    /**
     * Checks a node for validity as a Sizzle context
     * @param {Element|Object=} context
     * @returns {Element|Object|Boolean} The input node if acceptable, otherwise a falsy value
     */
    function testContext( context ) {
        return context && typeof context.getElementsByTagName !== "undefined" && context;
    }
    
    // Expose support vars for convenience
    support = Sizzle.support = {};
    
    /**
     * Detects XML nodes
     * @param {Element|Object} elem An element or a document
     * @returns {Boolean} True iff elem is a non-HTML XML node
     */
    isXML = Sizzle.isXML = function( elem ) {
        var namespace = elem.namespaceURI,
            docElem = ( elem.ownerDocument || elem ).documentElement;
    
        // Support: IE <=8
        // Assume HTML when documentElement doesn't yet exist, such as inside loading iframes
        // https://bugs.jquery.com/ticket/4833
        return !rhtml.test( namespace || docElem && docElem.nodeName || "HTML" );
    };
    
    /**
     * Sets document-related variables once based on the current document
     * @param {Element|Object} [doc] An element or document object to use to set the document
     * @returns {Object} Returns the current document
     */
    setDocument = Sizzle.setDocument = function( node ) {
        var hasCompare, subWindow,
            doc = node ? node.ownerDocument || node : preferredDoc;
    
        // Return early if doc is invalid or already selected
        // Support: IE 11+, Edge 17 - 18+
        // IE/Edge sometimes throw a "Permission denied" error when strict-comparing
        // two documents; shallow comparisons work.
        // eslint-disable-next-line eqeqeq
        if ( doc == document || doc.nodeType !== 9 || !doc.documentElement ) {
            return document;
        }
    
        // Update global variables
        document = doc;
        docElem = document.documentElement;
        documentIsHTML = !isXML( document );
    
        // Support: IE 9 - 11+, Edge 12 - 18+
        // Accessing iframe documents after unload throws "permission denied" errors (jQuery #13936)
        // Support: IE 11+, Edge 17 - 18+
        // IE/Edge sometimes throw a "Permission denied" error when strict-comparing
        // two documents; shallow comparisons work.
        // eslint-disable-next-line eqeqeq
        if ( preferredDoc != document &&
            ( subWindow = document.defaultView ) && subWindow.top !== subWindow ) {
    
            // Support: IE 11, Edge
            if ( subWindow.addEventListener ) {
                subWindow.addEventListener( "unload", unloadHandler, false );
    
            // Support: IE 9 - 10 only
            } else if ( subWindow.attachEvent ) {
                subWindow.attachEvent( "onunload", unloadHandler );
            }
        }
    
        // Support: IE 8 - 11+, Edge 12 - 18+, Chrome <=16 - 25 only, Firefox <=3.6 - 31 only,
        // Safari 4 - 5 only, Opera <=11.6 - 12.x only
        // IE/Edge & older browsers don't support the :scope pseudo-class.
        // Support: Safari 6.0 only
        // Safari 6.0 supports :scope but it's an alias of :root there.
        support.scope = assert( function( el ) {
            docElem.appendChild( el ).appendChild( document.createElement( "div" ) );
            return typeof el.querySelectorAll !== "undefined" &&
                !el.querySelectorAll( ":scope fieldset div" ).length;
        } );
    
        /* Attributes
        ---------------------------------------------------------------------- */
    
        // Support: IE<8
        // Verify that getAttribute really returns attributes and not properties
        // (excepting IE8 booleans)
        support.attributes = assert( function( el ) {
            el.className = "i";
            return !el.getAttribute( "className" );
        } );
    
        /* getElement(s)By*
        ---------------------------------------------------------------------- */
    
        // Check if getElementsByTagName("*") returns only elements
        support.getElementsByTagName = assert( function( el ) {
            el.appendChild( document.createComment( "" ) );
            return !el.getElementsByTagName( "*" ).length;
        } );
    
        // Support: IE<9
        support.getElementsByClassName = rnative.test( document.getElementsByClassName );
    
        // Support: IE<10
        // Check if getElementById returns elements by name
        // The broken getElementById methods don't pick up programmatically-set names,
        // so use a roundabout getElementsByName test
        support.getById = assert( function( el ) {
            docElem.appendChild( el ).id = expando;
            return !document.getElementsByName || !document.getElementsByName( expando ).length;
        } );
    
        // ID filter and find
        if ( support.getById ) {
            Expr.filter[ "ID" ] = function( id ) {
                var attrId = id.replace( runescape, funescape );
                return function( elem ) {
                    return elem.getAttribute( "id" ) === attrId;
                };
            };
            Expr.find[ "ID" ] = function( id, context ) {
                if ( typeof context.getElementById !== "undefined" && documentIsHTML ) {
                    var elem = context.getElementById( id );
                    return elem ? [ elem ] : [];
                }
            };
        } else {
            Expr.filter[ "ID" ] =  function( id ) {
                var attrId = id.replace( runescape, funescape );
                return function( elem ) {
                    var node = typeof elem.getAttributeNode !== "undefined" &&
                        elem.getAttributeNode( "id" );
                    return node && node.value === attrId;
                };
            };
    
            // Support: IE 6 - 7 only
            // getElementById is not reliable as a find shortcut
            Expr.find[ "ID" ] = function( id, context ) {
                if ( typeof context.getElementById !== "undefined" && documentIsHTML ) {
                    var node, i, elems,
                        elem = context.getElementById( id );
    
                    if ( elem ) {
    
                        // Verify the id attribute
                        node = elem.getAttributeNode( "id" );
                        if ( node && node.value === id ) {
                            return [ elem ];
                        }
    
                        // Fall back on getElementsByName
                        elems = context.getElementsByName( id );
                        i = 0;
                        while ( ( elem = elems[ i++ ] ) ) {
                            node = elem.getAttributeNode( "id" );
                            if ( node && node.value === id ) {
                                return [ elem ];
                            }
                        }
                    }
    
                    return [];
                }
            };
        }
    
        // Tag
        Expr.find[ "TAG" ] = support.getElementsByTagName ?
            function( tag, context ) {
                if ( typeof context.getElementsByTagName !== "undefined" ) {
                    return context.getElementsByTagName( tag );
    
                // DocumentFragment nodes don't have gEBTN
                } else if ( support.qsa ) {
                    return context.querySelectorAll( tag );
                }
            } :
    
            function( tag, context ) {
                var elem,
                    tmp = [],
                    i = 0,
    
                    // By happy coincidence, a (broken) gEBTN appears on DocumentFragment nodes too
                    results = context.getElementsByTagName( tag );
    
                // Filter out possible comments
                if ( tag === "*" ) {
                    while ( ( elem = results[ i++ ] ) ) {
                        if ( elem.nodeType === 1 ) {
                            tmp.push( elem );
                        }
                    }
    
                    return tmp;
                }
                return results;
            };
    
        // Class
        Expr.find[ "CLASS" ] = support.getElementsByClassName && function( className, context ) {
            if ( typeof context.getElementsByClassName !== "undefined" && documentIsHTML ) {
                return context.getElementsByClassName( className );
            }
        };
    
        /* QSA/matchesSelector
        ---------------------------------------------------------------------- */
    
        // QSA and matchesSelector support
    
        // matchesSelector(:active) reports false when true (IE9/Opera 11.5)
        rbuggyMatches = [];
    
        // qSa(:focus) reports false when true (Chrome 21)
        // We allow this because of a bug in IE8/9 that throws an error
        // whenever `document.activeElement` is accessed on an iframe
        // So, we allow :focus to pass through QSA all the time to avoid the IE error
        // See https://bugs.jquery.com/ticket/13378
        rbuggyQSA = [];
    
        if ( ( support.qsa = rnative.test( document.querySelectorAll ) ) ) {
    
            // Build QSA regex
            // Regex strategy adopted from Diego Perini
            assert( function( el ) {
    
                var input;
    
                // Select is set to empty string on purpose
                // This is to test IE's treatment of not explicitly
                // setting a boolean content attribute,
                // since its presence should be enough
                // https://bugs.jquery.com/ticket/12359
                docElem.appendChild( el ).innerHTML = "<a id='" + expando + "'></a>" +
                    "<select id='" + expando + "-\r\\' msallowcapture=''>" +
                    "<option selected=''></option></select>";
    
                // Support: IE8, Opera 11-12.16
                // Nothing should be selected when empty strings follow ^= or $= or *=
                // The test attribute must be unknown in Opera but "safe" for WinRT
                // https://msdn.microsoft.com/en-us/library/ie/hh465388.aspx#attribute_section
                if ( el.querySelectorAll( "[msallowcapture^='']" ).length ) {
                    rbuggyQSA.push( "[*^$]=" + whitespace + "*(?:''|\"\")" );
                }
    
                // Support: IE8
                // Boolean attributes and "value" are not treated correctly
                if ( !el.querySelectorAll( "[selected]" ).length ) {
                    rbuggyQSA.push( "\\[" + whitespace + "*(?:value|" + booleans + ")" );
                }
    
                // Support: Chrome<29, Android<4.4, Safari<7.0+, iOS<7.0+, PhantomJS<1.9.8+
                if ( !el.querySelectorAll( "[id~=" + expando + "-]" ).length ) {
                    rbuggyQSA.push( "~=" );
                }
    
                // Support: IE 11+, Edge 15 - 18+
                // IE 11/Edge don't find elements on a `[name='']` query in some cases.
                // Adding a temporary attribute to the document before the selection works
                // around the issue.
                // Interestingly, IE 10 & older don't seem to have the issue.
                input = document.createElement( "input" );
                input.setAttribute( "name", "" );
                el.appendChild( input );
                if ( !el.querySelectorAll( "[name='']" ).length ) {
                    rbuggyQSA.push( "\\[" + whitespace + "*name" + whitespace + "*=" +
                        whitespace + "*(?:''|\"\")" );
                }
    
                // Webkit/Opera - :checked should return selected option elements
                // http://www.w3.org/TR/2011/REC-css3-selectors-20110929/#checked
                // IE8 throws error here and will not see later tests
                if ( !el.querySelectorAll( ":checked" ).length ) {
                    rbuggyQSA.push( ":checked" );
                }
    
                // Support: Safari 8+, iOS 8+
                // https://bugs.webkit.org/show_bug.cgi?id=136851
                // In-page `selector#id sibling-combinator selector` fails
                if ( !el.querySelectorAll( "a#" + expando + "+*" ).length ) {
                    rbuggyQSA.push( ".#.+[+~]" );
                }
    
                // Support: Firefox <=3.6 - 5 only
                // Old Firefox doesn't throw on a badly-escaped identifier.
                el.querySelectorAll( "\\\f" );
                rbuggyQSA.push( "[\\r\\n\\f]" );
            } );
    
            assert( function( el ) {
                el.innerHTML = "<a href='' disabled='disabled'></a>" +
                    "<select disabled='disabled'><option/></select>";
    
                // Support: Windows 8 Native Apps
                // The type and name attributes are restricted during .innerHTML assignment
                var input = document.createElement( "input" );
                input.setAttribute( "type", "hidden" );
                el.appendChild( input ).setAttribute( "name", "D" );
    
                // Support: IE8
                // Enforce case-sensitivity of name attribute
                if ( el.querySelectorAll( "[name=d]" ).length ) {
                    rbuggyQSA.push( "name" + whitespace + "*[*^$|!~]?=" );
                }
    
                // FF 3.5 - :enabled/:disabled and hidden elements (hidden elements are still enabled)
                // IE8 throws error here and will not see later tests
                if ( el.querySelectorAll( ":enabled" ).length !== 2 ) {
                    rbuggyQSA.push( ":enabled", ":disabled" );
                }
    
                // Support: IE9-11+
                // IE's :disabled selector does not pick up the children of disabled fieldsets
                docElem.appendChild( el ).disabled = true;
                if ( el.querySelectorAll( ":disabled" ).length !== 2 ) {
                    rbuggyQSA.push( ":enabled", ":disabled" );
                }
    
                // Support: Opera 10 - 11 only
                // Opera 10-11 does not throw on post-comma invalid pseudos
                el.querySelectorAll( "*,:x" );
                rbuggyQSA.push( ",.*:" );
            } );
        }
    
        if ( ( support.matchesSelector = rnative.test( ( matches = docElem.matches ||
            docElem.webkitMatchesSelector ||
            docElem.mozMatchesSelector ||
            docElem.oMatchesSelector ||
            docElem.msMatchesSelector ) ) ) ) {
    
            assert( function( el ) {
    
                // Check to see if it's possible to do matchesSelector
                // on a disconnected node (IE 9)
                support.disconnectedMatch = matches.call( el, "*" );
    
                // This should fail with an exception
                // Gecko does not error, returns false instead
                matches.call( el, "[s!='']:x" );
                rbuggyMatches.push( "!=", pseudos );
            } );
        }
    
        rbuggyQSA = rbuggyQSA.length && new RegExp( rbuggyQSA.join( "|" ) );
        rbuggyMatches = rbuggyMatches.length && new RegExp( rbuggyMatches.join( "|" ) );
    
        /* Contains
        ---------------------------------------------------------------------- */
        hasCompare = rnative.test( docElem.compareDocumentPosition );
    
        // Element contains another
        // Purposefully self-exclusive
        // As in, an element does not contain itself
        contains = hasCompare || rnative.test( docElem.contains ) ?
            function( a, b ) {
                var adown = a.nodeType === 9 ? a.documentElement : a,
                    bup = b && b.parentNode;
                return a === bup || !!( bup && bup.nodeType === 1 && (
                    adown.contains ?
                        adown.contains( bup ) :
                        a.compareDocumentPosition && a.compareDocumentPosition( bup ) & 16
                ) );
            } :
            function( a, b ) {
                if ( b ) {
                    while ( ( b = b.parentNode ) ) {
                        if ( b === a ) {
                            return true;
                        }
                    }
                }
                return false;
            };
    
        /* Sorting
        ---------------------------------------------------------------------- */
    
        // Document order sorting
        sortOrder = hasCompare ?
        function( a, b ) {
    
            // Flag for duplicate removal
            if ( a === b ) {
                hasDuplicate = true;
                return 0;
            }
    
            // Sort on method existence if only one input has compareDocumentPosition
            var compare = !a.compareDocumentPosition - !b.compareDocumentPosition;
            if ( compare ) {
                return compare;
            }
    
            // Calculate position if both inputs belong to the same document
            // Support: IE 11+, Edge 17 - 18+
            // IE/Edge sometimes throw a "Permission denied" error when strict-comparing
            // two documents; shallow comparisons work.
            // eslint-disable-next-line eqeqeq
            compare = ( a.ownerDocument || a ) == ( b.ownerDocument || b ) ?
                a.compareDocumentPosition( b ) :
    
                // Otherwise we know they are disconnected
                1;
    
            // Disconnected nodes
            if ( compare & 1 ||
                ( !support.sortDetached && b.compareDocumentPosition( a ) === compare ) ) {
    
                // Choose the first element that is related to our preferred document
                // Support: IE 11+, Edge 17 - 18+
                // IE/Edge sometimes throw a "Permission denied" error when strict-comparing
                // two documents; shallow comparisons work.
                // eslint-disable-next-line eqeqeq
                if ( a == document || a.ownerDocument == preferredDoc &&
                    contains( preferredDoc, a ) ) {
                    return -1;
                }
    
                // Support: IE 11+, Edge 17 - 18+
                // IE/Edge sometimes throw a "Permission denied" error when strict-comparing
                // two documents; shallow comparisons work.
                // eslint-disable-next-line eqeqeq
                if ( b == document || b.ownerDocument == preferredDoc &&
                    contains( preferredDoc, b ) ) {
                    return 1;
                }
    
                // Maintain original order
                return sortInput ?
                    ( indexOf( sortInput, a ) - indexOf( sortInput, b ) ) :
                    0;
            }
    
            return compare & 4 ? -1 : 1;
        } :
        function( a, b ) {
    
            // Exit early if the nodes are identical
            if ( a === b ) {
                hasDuplicate = true;
                return 0;
            }
    
            var cur,
                i = 0,
                aup = a.parentNode,
                bup = b.parentNode,
                ap = [ a ],
                bp = [ b ];
    
            // Parentless nodes are either documents or disconnected
            if ( !aup || !bup ) {
    
                // Support: IE 11+, Edge 17 - 18+
                // IE/Edge sometimes throw a "Permission denied" error when strict-comparing
                // two documents; shallow comparisons work.
                /* eslint-disable eqeqeq */
                return a == document ? -1 :
                    b == document ? 1 :
                    /* eslint-enable eqeqeq */
                    aup ? -1 :
                    bup ? 1 :
                    sortInput ?
                    ( indexOf( sortInput, a ) - indexOf( sortInput, b ) ) :
                    0;
    
            // If the nodes are siblings, we can do a quick check
            } else if ( aup === bup ) {
                return siblingCheck( a, b );
            }
    
            // Otherwise we need full lists of their ancestors for comparison
            cur = a;
            while ( ( cur = cur.parentNode ) ) {
                ap.unshift( cur );
            }
            cur = b;
            while ( ( cur = cur.parentNode ) ) {
                bp.unshift( cur );
            }
    
            // Walk down the tree looking for a discrepancy
            while ( ap[ i ] === bp[ i ] ) {
                i++;
            }
    
            return i ?
    
                // Do a sibling check if the nodes have a common ancestor
                siblingCheck( ap[ i ], bp[ i ] ) :
    
                // Otherwise nodes in our document sort first
                // Support: IE 11+, Edge 17 - 18+
                // IE/Edge sometimes throw a "Permission denied" error when strict-comparing
                // two documents; shallow comparisons work.
                /* eslint-disable eqeqeq */
                ap[ i ] == preferredDoc ? -1 :
                bp[ i ] == preferredDoc ? 1 :
                /* eslint-enable eqeqeq */
                0;
        };
    
        return document;
    };
    
    Sizzle.matches = function( expr, elements ) {
        return Sizzle( expr, null, null, elements );
    };
    
    Sizzle.matchesSelector = function( elem, expr ) {
        setDocument( elem );
    
        if ( support.matchesSelector && documentIsHTML &&
            !nonnativeSelectorCache[ expr + " " ] &&
            ( !rbuggyMatches || !rbuggyMatches.test( expr ) ) &&
            ( !rbuggyQSA     || !rbuggyQSA.test( expr ) ) ) {
    
            try {
                var ret = matches.call( elem, expr );
    
                // IE 9's matchesSelector returns false on disconnected nodes
                if ( ret || support.disconnectedMatch ||
    
                    // As well, disconnected nodes are said to be in a document
                    // fragment in IE 9
                    elem.document && elem.document.nodeType !== 11 ) {
                    return ret;
                }
            } catch ( e ) {
                nonnativeSelectorCache( expr, true );
            }
        }
    
        return Sizzle( expr, document, null, [ elem ] ).length > 0;
    };
    
    Sizzle.contains = function( context, elem ) {
    
        // Set document vars if needed
        // Support: IE 11+, Edge 17 - 18+
        // IE/Edge sometimes throw a "Permission denied" error when strict-comparing
        // two documents; shallow comparisons work.
        // eslint-disable-next-line eqeqeq
        if ( ( context.ownerDocument || context ) != document ) {
            setDocument( context );
        }
        return contains( context, elem );
    };
    
    Sizzle.attr = function( elem, name ) {
    
        // Set document vars if needed
        // Support: IE 11+, Edge 17 - 18+
        // IE/Edge sometimes throw a "Permission denied" error when strict-comparing
        // two documents; shallow comparisons work.
        // eslint-disable-next-line eqeqeq
        if ( ( elem.ownerDocument || elem ) != document ) {
            setDocument( elem );
        }
    
        var fn = Expr.attrHandle[ name.toLowerCase() ],
    
            // Don't get fooled by Object.prototype properties (jQuery #13807)
            val = fn && hasOwn.call( Expr.attrHandle, name.toLowerCase() ) ?
                fn( elem, name, !documentIsHTML ) :
                undefined;
    
        return val !== undefined ?
            val :
            support.attributes || !documentIsHTML ?
                elem.getAttribute( name ) :
                ( val = elem.getAttributeNode( name ) ) && val.specified ?
                    val.value :
                    null;
    };
    
    Sizzle.escape = function( sel ) {
        return ( sel + "" ).replace( rcssescape, fcssescape );
    };
    
    Sizzle.error = function( msg ) {
        throw new Error( "Syntax error, unrecognized expression: " + msg );
    };
    
    /**
     * Document sorting and removing duplicates
     * @param {ArrayLike} results
     */
    Sizzle.uniqueSort = function( results ) {
        var elem,
            duplicates = [],
            j = 0,
            i = 0;
    
        // Unless we *know* we can detect duplicates, assume their presence
        hasDuplicate = !support.detectDuplicates;
        sortInput = !support.sortStable && results.slice( 0 );
        results.sort( sortOrder );
    
        if ( hasDuplicate ) {
            while ( ( elem = results[ i++ ] ) ) {
                if ( elem === results[ i ] ) {
                    j = duplicates.push( i );
                }
            }
            while ( j-- ) {
                results.splice( duplicates[ j ], 1 );
            }
        }
    
        // Clear input after sorting to release objects
        // See https://github.com/jquery/sizzle/pull/225
        sortInput = null;
    
        return results;
    };
    
    /**
     * Utility function for retrieving the text value of an array of DOM nodes
     * @param {Array|Element} elem
     */
    getText = Sizzle.getText = function( elem ) {
        var node,
            ret = "",
            i = 0,
            nodeType = elem.nodeType;
    
        if ( !nodeType ) {
    
            // If no nodeType, this is expected to be an array
            while ( ( node = elem[ i++ ] ) ) {
    
                // Do not traverse comment nodes
                ret += getText( node );
            }
        } else if ( nodeType === 1 || nodeType === 9 || nodeType === 11 ) {
    
            // Use textContent for elements
            // innerText usage removed for consistency of new lines (jQuery #11153)
            if ( typeof elem.textContent === "string" ) {
                return elem.textContent;
            } else {
    
                // Traverse its children
                for ( elem = elem.firstChild; elem; elem = elem.nextSibling ) {
                    ret += getText( elem );
                }
            }
        } else if ( nodeType === 3 || nodeType === 4 ) {
            return elem.nodeValue;
        }
    
        // Do not include comment or processing instruction nodes
    
        return ret;
    };
    
    Expr = Sizzle.selectors = {
    
        // Can be adjusted by the user
        cacheLength: 50,
    
        createPseudo: markFunction,
    
        match: matchExpr,
    
        attrHandle: {},
    
        find: {},
    
        relative: {
            ">": { dir: "parentNode", first: true },
            " ": { dir: "parentNode" },
            "+": { dir: "previousSibling", first: true },
            "~": { dir: "previousSibling" }
        },
    
        preFilter: {
            "ATTR": function( match ) {
                match[ 1 ] = match[ 1 ].replace( runescape, funescape );
    
                // Move the given value to match[3] whether quoted or unquoted
                match[ 3 ] = ( match[ 3 ] || match[ 4 ] ||
                    match[ 5 ] || "" ).replace( runescape, funescape );
    
                if ( match[ 2 ] === "~=" ) {
                    match[ 3 ] = " " + match[ 3 ] + " ";
                }
    
                return match.slice( 0, 4 );
            },
    
            "CHILD": function( match ) {
    
                /* matches from matchExpr["CHILD"]
                    1 type (only|nth|...)
                    2 what (child|of-type)
                    3 argument (even|odd|\d*|\d*n([+-]\d+)?|...)
                    4 xn-component of xn+y argument ([+-]?\d*n|)
                    5 sign of xn-component
                    6 x of xn-component
                    7 sign of y-component
                    8 y of y-component
                */
                match[ 1 ] = match[ 1 ].toLowerCase();
    
                if ( match[ 1 ].slice( 0, 3 ) === "nth" ) {
    
                    // nth-* requires argument
                    if ( !match[ 3 ] ) {
                        Sizzle.error( match[ 0 ] );
                    }
    
                    // numeric x and y parameters for Expr.filter.CHILD
                    // remember that false/true cast respectively to 0/1
                    match[ 4 ] = +( match[ 4 ] ?
                        match[ 5 ] + ( match[ 6 ] || 1 ) :
                        2 * ( match[ 3 ] === "even" || match[ 3 ] === "odd" ) );
                    match[ 5 ] = +( ( match[ 7 ] + match[ 8 ] ) || match[ 3 ] === "odd" );
    
                    // other types prohibit arguments
                } else if ( match[ 3 ] ) {
                    Sizzle.error( match[ 0 ] );
                }
    
                return match;
            },
    
            "PSEUDO": function( match ) {
                var excess,
                    unquoted = !match[ 6 ] && match[ 2 ];
    
                if ( matchExpr[ "CHILD" ].test( match[ 0 ] ) ) {
                    return null;
                }
    
                // Accept quoted arguments as-is
                if ( match[ 3 ] ) {
                    match[ 2 ] = match[ 4 ] || match[ 5 ] || "";
    
                // Strip excess characters from unquoted arguments
                } else if ( unquoted && rpseudo.test( unquoted ) &&
    
                    // Get excess from tokenize (recursively)
                    ( excess = tokenize( unquoted, true ) ) &&
    
                    // advance to the next closing parenthesis
                    ( excess = unquoted.indexOf( ")", unquoted.length - excess ) - unquoted.length ) ) {
    
                    // excess is a negative index
                    match[ 0 ] = match[ 0 ].slice( 0, excess );
                    match[ 2 ] = unquoted.slice( 0, excess );
                }
    
                // Return only captures needed by the pseudo filter method (type and argument)
                return match.slice( 0, 3 );
            }
        },
    
        filter: {
    
            "TAG": function( nodeNameSelector ) {
                var nodeName = nodeNameSelector.replace( runescape, funescape ).toLowerCase();
                return nodeNameSelector === "*" ?
                    function() {
                        return true;
                    } :
                    function( elem ) {
                        return elem.nodeName && elem.nodeName.toLowerCase() === nodeName;
                    };
            },
    
            "CLASS": function( className ) {
                var pattern = classCache[ className + " " ];
    
                return pattern ||
                    ( pattern = new RegExp( "(^|" + whitespace +
                        ")" + className + "(" + whitespace + "|$)" ) ) && classCache(
                            className, function( elem ) {
                                return pattern.test(
                                    typeof elem.className === "string" && elem.className ||
                                    typeof elem.getAttribute !== "undefined" &&
                                        elem.getAttribute( "class" ) ||
                                    ""
                                );
                    } );
            },
    
            "ATTR": function( name, operator, check ) {
                return function( elem ) {
                    var result = Sizzle.attr( elem, name );
    
                    if ( result == null ) {
                        return operator === "!=";
                    }
                    if ( !operator ) {
                        return true;
                    }
    
                    result += "";
    
                    /* eslint-disable max-len */
    
                    return operator === "=" ? result === check :
                        operator === "!=" ? result !== check :
                        operator === "^=" ? check && result.indexOf( check ) === 0 :
                        operator === "*=" ? check && result.indexOf( check ) > -1 :
                        operator === "$=" ? check && result.slice( -check.length ) === check :
                        operator === "~=" ? ( " " + result.replace( rwhitespace, " " ) + " " ).indexOf( check ) > -1 :
                        operator === "|=" ? result === check || result.slice( 0, check.length + 1 ) === check + "-" :
                        false;
                    /* eslint-enable max-len */
    
                };
            },
    
            "CHILD": function( type, what, _argument, first, last ) {
                var simple = type.slice( 0, 3 ) !== "nth",
                    forward = type.slice( -4 ) !== "last",
                    ofType = what === "of-type";
    
                return first === 1 && last === 0 ?
    
                    // Shortcut for :nth-*(n)
                    function( elem ) {
                        return !!elem.parentNode;
                    } :
    
                    function( elem, _context, xml ) {
                        var cache, uniqueCache, outerCache, node, nodeIndex, start,
                            dir = simple !== forward ? "nextSibling" : "previousSibling",
                            parent = elem.parentNode,
                            name = ofType && elem.nodeName.toLowerCase(),
                            useCache = !xml && !ofType,
                            diff = false;
    
                        if ( parent ) {
    
                            // :(first|last|only)-(child|of-type)
                            if ( simple ) {
                                while ( dir ) {
                                    node = elem;
                                    while ( ( node = node[ dir ] ) ) {
                                        if ( ofType ?
                                            node.nodeName.toLowerCase() === name :
                                            node.nodeType === 1 ) {
    
                                            return false;
                                        }
                                    }
    
                                    // Reverse direction for :only-* (if we haven't yet done so)
                                    start = dir = type === "only" && !start && "nextSibling";
                                }
                                return true;
                            }
    
                            start = [ forward ? parent.firstChild : parent.lastChild ];
    
                            // non-xml :nth-child(...) stores cache data on `parent`
                            if ( forward && useCache ) {
    
                                // Seek `elem` from a previously-cached index
    
                                // ...in a gzip-friendly way
                                node = parent;
                                outerCache = node[ expando ] || ( node[ expando ] = {} );
    
                                // Support: IE <9 only
                                // Defend against cloned attroperties (jQuery gh-1709)
                                uniqueCache = outerCache[ node.uniqueID ] ||
                                    ( outerCache[ node.uniqueID ] = {} );
    
                                cache = uniqueCache[ type ] || [];
                                nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ];
                                diff = nodeIndex && cache[ 2 ];
                                node = nodeIndex && parent.childNodes[ nodeIndex ];
    
                                while ( ( node = ++nodeIndex && node && node[ dir ] ||
    
                                    // Fallback to seeking `elem` from the start
                                    ( diff = nodeIndex = 0 ) || start.pop() ) ) {
    
                                    // When found, cache indexes on `parent` and break
                                    if ( node.nodeType === 1 && ++diff && node === elem ) {
                                        uniqueCache[ type ] = [ dirruns, nodeIndex, diff ];
                                        break;
                                    }
                                }
    
                            } else {
    
                                // Use previously-cached element index if available
                                if ( useCache ) {
    
                                    // ...in a gzip-friendly way
                                    node = elem;
                                    outerCache = node[ expando ] || ( node[ expando ] = {} );
    
                                    // Support: IE <9 only
                                    // Defend against cloned attroperties (jQuery gh-1709)
                                    uniqueCache = outerCache[ node.uniqueID ] ||
                                        ( outerCache[ node.uniqueID ] = {} );
    
                                    cache = uniqueCache[ type ] || [];
                                    nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ];
                                    diff = nodeIndex;
                                }
    
                                // xml :nth-child(...)
                                // or :nth-last-child(...) or :nth(-last)?-of-type(...)
                                if ( diff === false ) {
    
                                    // Use the same loop as above to seek `elem` from the start
                                    while ( ( node = ++nodeIndex && node && node[ dir ] ||
                                        ( diff = nodeIndex = 0 ) || start.pop() ) ) {
    
                                        if ( ( ofType ?
                                            node.nodeName.toLowerCase() === name :
                                            node.nodeType === 1 ) &&
                                            ++diff ) {
    
                                            // Cache the index of each encountered element
                                            if ( useCache ) {
                                                outerCache = node[ expando ] ||
                                                    ( node[ expando ] = {} );
    
                                                // Support: IE <9 only
                                                // Defend against cloned attroperties (jQuery gh-1709)
                                                uniqueCache = outerCache[ node.uniqueID ] ||
                                                    ( outerCache[ node.uniqueID ] = {} );
    
                                                uniqueCache[ type ] = [ dirruns, diff ];
                                            }
    
                                            if ( node === elem ) {
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
    
                            // Incorporate the offset, then check against cycle size
                            diff -= last;
                            return diff === first || ( diff % first === 0 && diff / first >= 0 );
                        }
                    };
            },
    
            "PSEUDO": function( pseudo, argument ) {
    
                // pseudo-class names are case-insensitive
                // http://www.w3.org/TR/selectors/#pseudo-classes
                // Prioritize by case sensitivity in case custom pseudos are added with uppercase letters
                // Remember that setFilters inherits from pseudos
                var args,
                    fn = Expr.pseudos[ pseudo ] || Expr.setFilters[ pseudo.toLowerCase() ] ||
                        Sizzle.error( "unsupported pseudo: " + pseudo );
    
                // The user may use createPseudo to indicate that
                // arguments are needed to create the filter function
                // just as Sizzle does
                if ( fn[ expando ] ) {
                    return fn( argument );
                }
    
                // But maintain support for old signatures
                if ( fn.length > 1 ) {
                    args = [ pseudo, pseudo, "", argument ];
                    return Expr.setFilters.hasOwnProperty( pseudo.toLowerCase() ) ?
                        markFunction( function( seed, matches ) {
                            var idx,
                                matched = fn( seed, argument ),
                                i = matched.length;
                            while ( i-- ) {
                                idx = indexOf( seed, matched[ i ] );
                                seed[ idx ] = !( matches[ idx ] = matched[ i ] );
                            }
                        } ) :
                        function( elem ) {
                            return fn( elem, 0, args );
                        };
                }
    
                return fn;
            }
        },
    
        pseudos: {
    
            // Potentially complex pseudos
            "not": markFunction( function( selector ) {
    
                // Trim the selector passed to compile
                // to avoid treating leading and trailing
                // spaces as combinators
                var input = [],
                    results = [],
                    matcher = compile( selector.replace( rtrim, "$1" ) );
    
                return matcher[ expando ] ?
                    markFunction( function( seed, matches, _context, xml ) {
                        var elem,
                            unmatched = matcher( seed, null, xml, [] ),
                            i = seed.length;
    
                        // Match elements unmatched by `matcher`
                        while ( i-- ) {
                            if ( ( elem = unmatched[ i ] ) ) {
                                seed[ i ] = !( matches[ i ] = elem );
                            }
                        }
                    } ) :
                    function( elem, _context, xml ) {
                        input[ 0 ] = elem;
                        matcher( input, null, xml, results );
    
                        // Don't keep the element (issue #299)
                        input[ 0 ] = null;
                        return !results.pop();
                    };
            } ),
    
            "has": markFunction( function( selector ) {
                return function( elem ) {
                    return Sizzle( selector, elem ).length > 0;
                };
            } ),
    
            "contains": markFunction( function( text ) {
                text = text.replace( runescape, funescape );
                return function( elem ) {
                    return ( elem.textContent || getText( elem ) ).indexOf( text ) > -1;
                };
            } ),
    
            // "Whether an element is represented by a :lang() selector
            // is based solely on the element's language value
            // being equal to the identifier C,
            // or beginning with the identifier C immediately followed by "-".
            // The matching of C against the element's language value is performed case-insensitively.
            // The identifier C does not have to be a valid language name."
            // http://www.w3.org/TR/selectors/#lang-pseudo
            "lang": markFunction( function( lang ) {
    
                // lang value must be a valid identifier
                if ( !ridentifier.test( lang || "" ) ) {
                    Sizzle.error( "unsupported lang: " + lang );
                }
                lang = lang.replace( runescape, funescape ).toLowerCase();
                return function( elem ) {
                    var elemLang;
                    do {
                        if ( ( elemLang = documentIsHTML ?
                            elem.lang :
                            elem.getAttribute( "xml:lang" ) || elem.getAttribute( "lang" ) ) ) {
    
                            elemLang = elemLang.toLowerCase();
                            return elemLang === lang || elemLang.indexOf( lang + "-" ) === 0;
                        }
                    } while ( ( elem = elem.parentNode ) && elem.nodeType === 1 );
                    return false;
                };
            } ),
    
            // Miscellaneous
            "target": function( elem ) {
                var hash = window.location && window.location.hash;
                return hash && hash.slice( 1 ) === elem.id;
            },
    
            "root": function( elem ) {
                return elem === docElem;
            },
    
            "focus": function( elem ) {
                return elem === document.activeElement &&
                    ( !document.hasFocus || document.hasFocus() ) &&
                    !!( elem.type || elem.href || ~elem.tabIndex );
            },
    
            // Boolean properties
            "enabled": createDisabledPseudo( false ),
            "disabled": createDisabledPseudo( true ),
    
            "checked": function( elem ) {
    
                // In CSS3, :checked should return both checked and selected elements
                // http://www.w3.org/TR/2011/REC-css3-selectors-20110929/#checked
                var nodeName = elem.nodeName.toLowerCase();
                return ( nodeName === "input" && !!elem.checked ) ||
                    ( nodeName === "option" && !!elem.selected );
            },
    
            "selected": function( elem ) {
    
                // Accessing this property makes selected-by-default
                // options in Safari work properly
                if ( elem.parentNode ) {
                    // eslint-disable-next-line no-unused-expressions
                    elem.parentNode.selectedIndex;
                }
    
                return elem.selected === true;
            },
    
            // Contents
            "empty": function( elem ) {
    
                // http://www.w3.org/TR/selectors/#empty-pseudo
                // :empty is negated by element (1) or content nodes (text: 3; cdata: 4; entity ref: 5),
                //   but not by others (comment: 8; processing instruction: 7; etc.)
                // nodeType < 6 works because attributes (2) do not appear as children
                for ( elem = elem.firstChild; elem; elem = elem.nextSibling ) {
                    if ( elem.nodeType < 6 ) {
                        return false;
                    }
                }
                return true;
            },
    
            "parent": function( elem ) {
                return !Expr.pseudos[ "empty" ]( elem );
            },
    
            // Element/input types
            "header": function( elem ) {
                return rheader.test( elem.nodeName );
            },
    
            "input": function( elem ) {
                return rinputs.test( elem.nodeName );
            },
    
            "button": function( elem ) {
                var name = elem.nodeName.toLowerCase();
                return name === "input" && elem.type === "button" || name === "button";
            },
    
            "text": function( elem ) {
                var attr;
                return elem.nodeName.toLowerCase() === "input" &&
                    elem.type === "text" &&
    
                    // Support: IE<8
                    // New HTML5 attribute values (e.g., "search") appear with elem.type === "text"
                    ( ( attr = elem.getAttribute( "type" ) ) == null ||
                        attr.toLowerCase() === "text" );
            },
    
            // Position-in-collection
            "first": createPositionalPseudo( function() {
                return [ 0 ];
            } ),
    
            "last": createPositionalPseudo( function( _matchIndexes, length ) {
                return [ length - 1 ];
            } ),
    
            "eq": createPositionalPseudo( function( _matchIndexes, length, argument ) {
                return [ argument < 0 ? argument + length : argument ];
            } ),
    
            "even": createPositionalPseudo( function( matchIndexes, length ) {
                var i = 0;
                for ( ; i < length; i += 2 ) {
                    matchIndexes.push( i );
                }
                return matchIndexes;
            } ),
    
            "odd": createPositionalPseudo( function( matchIndexes, length ) {
                var i = 1;
                for ( ; i < length; i += 2 ) {
                    matchIndexes.push( i );
                }
                return matchIndexes;
            } ),
    
            "lt": createPositionalPseudo( function( matchIndexes, length, argument ) {
                var i = argument < 0 ?
                    argument + length :
                    argument > length ?
                        length :
                        argument;
                for ( ; --i >= 0; ) {
                    matchIndexes.push( i );
                }
                return matchIndexes;
            } ),
    
            "gt": createPositionalPseudo( function( matchIndexes, length, argument ) {
                var i = argument < 0 ? argument + length : argument;
                for ( ; ++i < length; ) {
                    matchIndexes.push( i );
                }
                return matchIndexes;
            } )
        }
    };
    
    Expr.pseudos[ "nth" ] = Expr.pseudos[ "eq" ];
    
    // Add button/input type pseudos
    for ( i in { radio: true, checkbox: true, file: true, password: true, image: true } ) {
        Expr.pseudos[ i ] = createInputPseudo( i );
    }
    for ( i in { submit: true, reset: true } ) {
        Expr.pseudos[ i ] = createButtonPseudo( i );
    }
    
    // Easy API for creating new setFilters
    function setFilters() {}
    setFilters.prototype = Expr.filters = Expr.pseudos;
    Expr.setFilters = new setFilters();
    
    tokenize = Sizzle.tokenize = function( selector, parseOnly ) {
        var matched, match, tokens, type,
            soFar, groups, preFilters,
            cached = tokenCache[ selector + " " ];
    
        if ( cached ) {
            return parseOnly ? 0 : cached.slice( 0 );
        }
    
        soFar = selector;
        groups = [];
        preFilters = Expr.preFilter;
    
        while ( soFar ) {
    
            // Comma and first run
            if ( !matched || ( match = rcomma.exec( soFar ) ) ) {
                if ( match ) {
    
                    // Don't consume trailing commas as valid
                    soFar = soFar.slice( match[ 0 ].length ) || soFar;
                }
                groups.push( ( tokens = [] ) );
            }
    
            matched = false;
    
            // Combinators
            if ( ( match = rcombinators.exec( soFar ) ) ) {
                matched = match.shift();
                tokens.push( {
                    value: matched,
    
                    // Cast descendant combinators to space
                    type: match[ 0 ].replace( rtrim, " " )
                } );
                soFar = soFar.slice( matched.length );
            }
    
            // Filters
            for ( type in Expr.filter ) {
                if ( ( match = matchExpr[ type ].exec( soFar ) ) && ( !preFilters[ type ] ||
                    ( match = preFilters[ type ]( match ) ) ) ) {
                    matched = match.shift();
                    tokens.push( {
                        value: matched,
                        type: type,
                        matches: match
                    } );
                    soFar = soFar.slice( matched.length );
                }
            }
    
            if ( !matched ) {
                break;
            }
        }
    
        // Return the length of the invalid excess
        // if we're just parsing
        // Otherwise, throw an error or return tokens
        return parseOnly ?
            soFar.length :
            soFar ?
                Sizzle.error( selector ) :
    
                // Cache the tokens
                tokenCache( selector, groups ).slice( 0 );
    };
    
    function toSelector( tokens ) {
        var i = 0,
            len = tokens.length,
            selector = "";
        for ( ; i < len; i++ ) {
            selector += tokens[ i ].value;
        }
        return selector;
    }
    
    function addCombinator( matcher, combinator, base ) {
        var dir = combinator.dir,
            skip = combinator.next,
            key = skip || dir,
            checkNonElements = base && key === "parentNode",
            doneName = done++;
    
        return combinator.first ?
    
            // Check against closest ancestor/preceding element
            function( elem, context, xml ) {
                while ( ( elem = elem[ dir ] ) ) {
                    if ( elem.nodeType === 1 || checkNonElements ) {
                        return matcher( elem, context, xml );
                    }
                }
                return false;
            } :
    
            // Check against all ancestor/preceding elements
            function( elem, context, xml ) {
                var oldCache, uniqueCache, outerCache,
                    newCache = [ dirruns, doneName ];
    
                // We can't set arbitrary data on XML nodes, so they don't benefit from combinator caching
                if ( xml ) {
                    while ( ( elem = elem[ dir ] ) ) {
                        if ( elem.nodeType === 1 || checkNonElements ) {
                            if ( matcher( elem, context, xml ) ) {
                                return true;
                            }
                        }
                    }
                } else {
                    while ( ( elem = elem[ dir ] ) ) {
                        if ( elem.nodeType === 1 || checkNonElements ) {
                            outerCache = elem[ expando ] || ( elem[ expando ] = {} );
    
                            // Support: IE <9 only
                            // Defend against cloned attroperties (jQuery gh-1709)
                            uniqueCache = outerCache[ elem.uniqueID ] ||
                                ( outerCache[ elem.uniqueID ] = {} );
    
                            if ( skip && skip === elem.nodeName.toLowerCase() ) {
                                elem = elem[ dir ] || elem;
                            } else if ( ( oldCache = uniqueCache[ key ] ) &&
                                oldCache[ 0 ] === dirruns && oldCache[ 1 ] === doneName ) {
    
                                // Assign to newCache so results back-propagate to previous elements
                                return ( newCache[ 2 ] = oldCache[ 2 ] );
                            } else {
    
                                // Reuse newcache so results back-propagate to previous elements
                                uniqueCache[ key ] = newCache;
    
                                // A match means we're done; a fail means we have to keep checking
                                if ( ( newCache[ 2 ] = matcher( elem, context, xml ) ) ) {
                                    return true;
                                }
                            }
                        }
                    }
                }
                return false;
            };
    }
    
    function elementMatcher( matchers ) {
        return matchers.length > 1 ?
            function( elem, context, xml ) {
                var i = matchers.length;
                while ( i-- ) {
                    if ( !matchers[ i ]( elem, context, xml ) ) {
                        return false;
                    }
                }
                return true;
            } :
            matchers[ 0 ];
    }
    
    function multipleContexts( selector, contexts, results ) {
        var i = 0,
            len = contexts.length;
        for ( ; i < len; i++ ) {
            Sizzle( selector, contexts[ i ], results );
        }
        return results;
    }
    
    function condense( unmatched, map, filter, context, xml ) {
        var elem,
            newUnmatched = [],
            i = 0,
            len = unmatched.length,
            mapped = map != null;
    
        for ( ; i < len; i++ ) {
            if ( ( elem = unmatched[ i ] ) ) {
                if ( !filter || filter( elem, context, xml ) ) {
                    newUnmatched.push( elem );
                    if ( mapped ) {
                        map.push( i );
                    }
                }
            }
        }
    
        return newUnmatched;
    }
    
    function setMatcher( preFilter, selector, matcher, postFilter, postFinder, postSelector ) {
        if ( postFilter && !postFilter[ expando ] ) {
            postFilter = setMatcher( postFilter );
        }
        if ( postFinder && !postFinder[ expando ] ) {
            postFinder = setMatcher( postFinder, postSelector );
        }
        return markFunction( function( seed, results, context, xml ) {
            var temp, i, elem,
                preMap = [],
                postMap = [],
                preexisting = results.length,
    
                // Get initial elements from seed or context
                elems = seed || multipleContexts(
                    selector || "*",
                    context.nodeType ? [ context ] : context,
                    []
                ),
    
                // Prefilter to get matcher input, preserving a map for seed-results synchronization
                matcherIn = preFilter && ( seed || !selector ) ?
                    condense( elems, preMap, preFilter, context, xml ) :
                    elems,
    
                matcherOut = matcher ?
    
                    // If we have a postFinder, or filtered seed, or non-seed postFilter or preexisting results,
                    postFinder || ( seed ? preFilter : preexisting || postFilter ) ?
    
                        // ...intermediate processing is necessary
                        [] :
    
                        // ...otherwise use results directly
                        results :
                    matcherIn;
    
            // Find primary matches
            if ( matcher ) {
                matcher( matcherIn, matcherOut, context, xml );
            }
    
            // Apply postFilter
            if ( postFilter ) {
                temp = condense( matcherOut, postMap );
                postFilter( temp, [], context, xml );
    
                // Un-match failing elements by moving them back to matcherIn
                i = temp.length;
                while ( i-- ) {
                    if ( ( elem = temp[ i ] ) ) {
                        matcherOut[ postMap[ i ] ] = !( matcherIn[ postMap[ i ] ] = elem );
                    }
                }
            }
    
            if ( seed ) {
                if ( postFinder || preFilter ) {
                    if ( postFinder ) {
    
                        // Get the final matcherOut by condensing this intermediate into postFinder contexts
                        temp = [];
                        i = matcherOut.length;
                        while ( i-- ) {
                            if ( ( elem = matcherOut[ i ] ) ) {
    
                                // Restore matcherIn since elem is not yet a final match
                                temp.push( ( matcherIn[ i ] = elem ) );
                            }
                        }
                        postFinder( null, ( matcherOut = [] ), temp, xml );
                    }
    
                    // Move matched elements from seed to results to keep them synchronized
                    i = matcherOut.length;
                    while ( i-- ) {
                        if ( ( elem = matcherOut[ i ] ) &&
                            ( temp = postFinder ? indexOf( seed, elem ) : preMap[ i ] ) > -1 ) {
    
                            seed[ temp ] = !( results[ temp ] = elem );
                        }
                    }
                }
    
            // Add elements to results, through postFinder if defined
            } else {
                matcherOut = condense(
                    matcherOut === results ?
                        matcherOut.splice( preexisting, matcherOut.length ) :
                        matcherOut
                );
                if ( postFinder ) {
                    postFinder( null, results, matcherOut, xml );
                } else {
                    push.apply( results, matcherOut );
                }
            }
        } );
    }
    
    function matcherFromTokens( tokens ) {
        var checkContext, matcher, j,
            len = tokens.length,
            leadingRelative = Expr.relative[ tokens[ 0 ].type ],
            implicitRelative = leadingRelative || Expr.relative[ " " ],
            i = leadingRelative ? 1 : 0,
    
            // The foundational matcher ensures that elements are reachable from top-level context(s)
            matchContext = addCombinator( function( elem ) {
                return elem === checkContext;
            }, implicitRelative, true ),
            matchAnyContext = addCombinator( function( elem ) {
                return indexOf( checkContext, elem ) > -1;
            }, implicitRelative, true ),
            matchers = [ function( elem, context, xml ) {
                var ret = ( !leadingRelative && ( xml || context !== outermostContext ) ) || (
                    ( checkContext = context ).nodeType ?
                        matchContext( elem, context, xml ) :
                        matchAnyContext( elem, context, xml ) );
    
                // Avoid hanging onto element (issue #299)
                checkContext = null;
                return ret;
            } ];
    
        for ( ; i < len; i++ ) {
            if ( ( matcher = Expr.relative[ tokens[ i ].type ] ) ) {
                matchers = [ addCombinator( elementMatcher( matchers ), matcher ) ];
            } else {
                matcher = Expr.filter[ tokens[ i ].type ].apply( null, tokens[ i ].matches );
    
                // Return special upon seeing a positional matcher
                if ( matcher[ expando ] ) {
    
                    // Find the next relative operator (if any) for proper handling
                    j = ++i;
                    for ( ; j < len; j++ ) {
                        if ( Expr.relative[ tokens[ j ].type ] ) {
                            break;
                        }
                    }
                    return setMatcher(
                        i > 1 && elementMatcher( matchers ),
                        i > 1 && toSelector(
    
                        // If the preceding token was a descendant combinator, insert an implicit any-element `*`
                        tokens
                            .slice( 0, i - 1 )
                            .concat( { value: tokens[ i - 2 ].type === " " ? "*" : "" } )
                        ).replace( rtrim, "$1" ),
                        matcher,
                        i < j && matcherFromTokens( tokens.slice( i, j ) ),
                        j < len && matcherFromTokens( ( tokens = tokens.slice( j ) ) ),
                        j < len && toSelector( tokens )
                    );
                }
                matchers.push( matcher );
            }
        }
    
        return elementMatcher( matchers );
    }
    
    function matcherFromGroupMatchers( elementMatchers, setMatchers ) {
        var bySet = setMatchers.length > 0,
            byElement = elementMatchers.length > 0,
            superMatcher = function( seed, context, xml, results, outermost ) {
                var elem, j, matcher,
                    matchedCount = 0,
                    i = "0",
                    unmatched = seed && [],
                    setMatched = [],
                    contextBackup = outermostContext,
    
                    // We must always have either seed elements or outermost context
                    elems = seed || byElement && Expr.find[ "TAG" ]( "*", outermost ),
    
                    // Use integer dirruns iff this is the outermost matcher
                    dirrunsUnique = ( dirruns += contextBackup == null ? 1 : Math.random() || 0.1 ),
                    len = elems.length;
    
                if ( outermost ) {
    
                    // Support: IE 11+, Edge 17 - 18+
                    // IE/Edge sometimes throw a "Permission denied" error when strict-comparing
                    // two documents; shallow comparisons work.
                    // eslint-disable-next-line eqeqeq
                    outermostContext = context == document || context || outermost;
                }
    
                // Add elements passing elementMatchers directly to results
                // Support: IE<9, Safari
                // Tolerate NodeList properties (IE: "length"; Safari: <number>) matching elements by id
                for ( ; i !== len && ( elem = elems[ i ] ) != null; i++ ) {
                    if ( byElement && elem ) {
                        j = 0;
    
                        // Support: IE 11+, Edge 17 - 18+
                        // IE/Edge sometimes throw a "Permission denied" error when strict-comparing
                        // two documents; shallow comparisons work.
                        // eslint-disable-next-line eqeqeq
                        if ( !context && elem.ownerDocument != document ) {
                            setDocument( elem );
                            xml = !documentIsHTML;
                        }
                        while ( ( matcher = elementMatchers[ j++ ] ) ) {
                            if ( matcher( elem, context || document, xml ) ) {
                                results.push( elem );
                                break;
                            }
                        }
                        if ( outermost ) {
                            dirruns = dirrunsUnique;
                        }
                    }
    
                    // Track unmatched elements for set filters
                    if ( bySet ) {
    
                        // They will have gone through all possible matchers
                        if ( ( elem = !matcher && elem ) ) {
                            matchedCount--;
                        }
    
                        // Lengthen the array for every element, matched or not
                        if ( seed ) {
                            unmatched.push( elem );
                        }
                    }
                }
    
                // `i` is now the count of elements visited above, and adding it to `matchedCount`
                // makes the latter nonnegative.
                matchedCount += i;
    
                // Apply set filters to unmatched elements
                // NOTE: This can be skipped if there are no unmatched elements (i.e., `matchedCount`
                // equals `i`), unless we didn't visit _any_ elements in the above loop because we have
                // no element matchers and no seed.
                // Incrementing an initially-string "0" `i` allows `i` to remain a string only in that
                // case, which will result in a "00" `matchedCount` that differs from `i` but is also
                // numerically zero.
                if ( bySet && i !== matchedCount ) {
                    j = 0;
                    while ( ( matcher = setMatchers[ j++ ] ) ) {
                        matcher( unmatched, setMatched, context, xml );
                    }
    
                    if ( seed ) {
    
                        // Reintegrate element matches to eliminate the need for sorting
                        if ( matchedCount > 0 ) {
                            while ( i-- ) {
                                if ( !( unmatched[ i ] || setMatched[ i ] ) ) {
                                    setMatched[ i ] = pop.call( results );
                                }
                            }
                        }
    
                        // Discard index placeholder values to get only actual matches
                        setMatched = condense( setMatched );
                    }
    
                    // Add matches to results
                    push.apply( results, setMatched );
    
                    // Seedless set matches succeeding multiple successful matchers stipulate sorting
                    if ( outermost && !seed && setMatched.length > 0 &&
                        ( matchedCount + setMatchers.length ) > 1 ) {
    
                        Sizzle.uniqueSort( results );
                    }
                }
    
                // Override manipulation of globals by nested matchers
                if ( outermost ) {
                    dirruns = dirrunsUnique;
                    outermostContext = contextBackup;
                }
    
                return unmatched;
            };
    
        return bySet ?
            markFunction( superMatcher ) :
            superMatcher;
    }
    
    compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) {
        var i,
            setMatchers = [],
            elementMatchers = [],
            cached = compilerCache[ selector + " " ];
    
        if ( !cached ) {
    
            // Generate a function of recursive functions that can be used to check each element
            if ( !match ) {
                match = tokenize( selector );
            }
            i = match.length;
            while ( i-- ) {
                cached = matcherFromTokens( match[ i ] );
                if ( cached[ expando ] ) {
                    setMatchers.push( cached );
                } else {
                    elementMatchers.push( cached );
                }
            }
    
            // Cache the compiled function
            cached = compilerCache(
                selector,
                matcherFromGroupMatchers( elementMatchers, setMatchers )
            );
    
            // Save selector and tokenization
            cached.selector = selector;
        }
        return cached;
    };
    
    /**
     * A low-level selection function that works with Sizzle's compiled
     *  selector functions
     * @param {String|Function} selector A selector or a pre-compiled
     *  selector function built with Sizzle.compile
     * @param {Element} context
     * @param {Array} [results]
     * @param {Array} [seed] A set of elements to match against
     */
    select = Sizzle.select = function( selector, context, results, seed ) {
        var i, tokens, token, type, find,
            compiled = typeof selector === "function" && selector,
            match = !seed && tokenize( ( selector = compiled.selector || selector ) );
    
        results = results || [];
    
        // Try to minimize operations if there is only one selector in the list and no seed
        // (the latter of which guarantees us context)
        if ( match.length === 1 ) {
    
            // Reduce context if the leading compound selector is an ID
            tokens = match[ 0 ] = match[ 0 ].slice( 0 );
            if ( tokens.length > 2 && ( token = tokens[ 0 ] ).type === "ID" &&
                context.nodeType === 9 && documentIsHTML && Expr.relative[ tokens[ 1 ].type ] ) {
    
                context = ( Expr.find[ "ID" ]( token.matches[ 0 ]
                    .replace( runescape, funescape ), context ) || [] )[ 0 ];
                if ( !context ) {
                    return results;
    
                // Precompiled matchers will still verify ancestry, so step up a level
                } else if ( compiled ) {
                    context = context.parentNode;
                }
    
                selector = selector.slice( tokens.shift().value.length );
            }
    
            // Fetch a seed set for right-to-left matching
            i = matchExpr[ "needsContext" ].test( selector ) ? 0 : tokens.length;
            while ( i-- ) {
                token = tokens[ i ];
    
                // Abort if we hit a combinator
                if ( Expr.relative[ ( type = token.type ) ] ) {
                    break;
                }
                if ( ( find = Expr.find[ type ] ) ) {
    
                    // Search, expanding context for leading sibling combinators
                    if ( ( seed = find(
                        token.matches[ 0 ].replace( runescape, funescape ),
                        rsibling.test( tokens[ 0 ].type ) && testContext( context.parentNode ) ||
                            context
                    ) ) ) {
    
                        // If seed is empty or no tokens remain, we can return early
                        tokens.splice( i, 1 );
                        selector = seed.length && toSelector( tokens );
                        if ( !selector ) {
                            push.apply( results, seed );
                            return results;
                        }
    
                        break;
                    }
                }
            }
        }
    
        // Compile and execute a filtering function if one is not provided
        // Provide `match` to avoid retokenization if we modified the selector above
        ( compiled || compile( selector, match ) )(
            seed,
            context,
            !documentIsHTML,
            results,
            !context || rsibling.test( selector ) && testContext( context.parentNode ) || context
        );
        return results;
    };
    
    // One-time assignments
    
    // Sort stability
    support.sortStable = expando.split( "" ).sort( sortOrder ).join( "" ) === expando;
    
    // Support: Chrome 14-35+
    // Always assume duplicates if they aren't passed to the comparison function
    support.detectDuplicates = !!hasDuplicate;
    
    // Initialize against the default document
    setDocument();
    
    // Support: Webkit<537.32 - Safari 6.0.3/Chrome 25 (fixed in Chrome 27)
    // Detached nodes confoundingly follow *each other*
    support.sortDetached = assert( function( el ) {
    
        // Should return 1, but returns 4 (following)
        return el.compareDocumentPosition( document.createElement( "fieldset" ) ) & 1;
    } );
    
    // Support: IE<8
    // Prevent attribute/property "interpolation"
    // https://msdn.microsoft.com/en-us/library/ms536429%28VS.85%29.aspx
    if ( !assert( function( el ) {
        el.innerHTML = "<a href='#'></a>";
        return el.firstChild.getAttribute( "href" ) === "#";
    } ) ) {
        addHandle( "type|href|height|width", function( elem, name, isXML ) {
            if ( !isXML ) {
                return elem.getAttribute( name, name.toLowerCase() === "type" ? 1 : 2 );
            }
        } );
    }
    
    // Support: IE<9
    // Use defaultValue in place of getAttribute("value")
    if ( !support.attributes || !assert( function( el ) {
        el.innerHTML = "<input/>";
        el.firstChild.setAttribute( "value", "" );
        return el.firstChild.getAttribute( "value" ) === "";
    } ) ) {
        addHandle( "value", function( elem, _name, isXML ) {
            if ( !isXML && elem.nodeName.toLowerCase() === "input" ) {
                return elem.defaultValue;
            }
        } );
    }
    
    // Support: IE<9
    // Use getAttributeNode to fetch booleans when getAttribute lies
    if ( !assert( function( el ) {
        return el.getAttribute( "disabled" ) == null;
    } ) ) {
        addHandle( booleans, function( elem, name, isXML ) {
            var val;
            if ( !isXML ) {
                return elem[ name ] === true ? name.toLowerCase() :
                    ( val = elem.getAttributeNode( name ) ) && val.specified ?
                        val.value :
                        null;
            }
        } );
    }
    
    // EXPOSE special for PENDO
    SIZZLE_EXT.Sizzle = Sizzle;
    // EXPOSE
    
    } )( window );
    
    var _slice = Array.prototype.slice;
    
    try {
        // Can't be used with DOM elements in IE < 9
        _slice.call(document.documentElement);
    } catch (e) { // Fails in IE < 9
        // This will work for genuine arrays, array-like objects, 
        // NamedNodeMap (attributes, entities, notations),
        // NodeList (e.g., getElementsByTagName), HTMLCollection (e.g., childNodes),
        // and will not fail on other DOM objects (as do DOM elements in IE < 9)
        Array.prototype.slice = function(begin, end) {
            // IE < 9 gets unhappy with an undefined end argument
            end = (typeof end !== 'undefined') ? end : this.length;
    
            // For native Array objects, we use the native slice function
            if (Object.prototype.toString.call(this) === '[object Array]'){
                return _slice.call(this, begin, end); 
            }
    
            // For array like object we handle it ourselves.
            var i, cloned = [],
            size, len = this.length;
    
            // Handle negative value for "begin"
            var start = begin || 0;
            start = (start >= 0) ? start: len + start;
    
            // Handle negative value for "end"
            var upTo = (end) ? end : len;
            if (end < 0) {
                upTo = len + end;
            }
    
            // Actual expected size of the slice
            size = upTo - start;
    
            if (size > 0) {
                cloned = new Array(size);
                if (this.charAt) {
                    for (i = 0; i < size; i++) {
                        cloned[i] = this.charAt(start + i);
                    }
                } else {
                    for (i = 0; i < size; i++) {
                        cloned[i] = this[start + i];
                    }
                }
            }
    
            return cloned;
        };
    }
    
    if (!String.prototype.trim) {
      String.prototype.trim = function () {
        return this.replace(/^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g, '');
      };
    }
    
    var shadowAPI = (function() {
        function isShadowSelector(selector) {
            return selector ? selector.indexOf(shadowAPI.PSEUDO_ELEMENT) > -1 : false;
        }
    
        function parseShadowSelector(selector) {
            var splitter = selector.split(shadowAPI.PSEUDO_ELEMENT);
            var css = splitter.splice(0, 1)[0];
            var shadowCss = splitter.join(shadowAPI.PSEUDO_ELEMENT);
    
            return { 'baseCss': css, 'shadowCss': shadowCss };
        }
    
        function hasComposedPath(evt) {
            return _.isFunction(evt.composedPath);
        }
    
        return {
            'PSEUDO_ELEMENT': '::shadow',
    
            'getComposedPath': function(evt) {
                if (hasComposedPath(evt)) {
                    return evt.composedPath();
                }
    
                return null;
            },
    
            'getShadowRoot': function(elem) {
                return elem.shadowRoot;
            },
    
            'isElementShadowRoot': function(elem) {
                return typeof ShadowRoot !== 'undefined' && elem instanceof ShadowRoot && elem.host;
            },
    
            'isShadowSelector': isShadowSelector,
    
            'getParent': function(elem) {
                return shadowAPI.isElementShadowRoot(elem) ? elem.host : elem.parentNode;
            },
    
            'wrapSizzle': function(Sizzle) {
                var ShadowSizzle = _.extend(function shadowSizzleWrapper(selection, context, results, seed) {
                    if (isShadowSelector(selection) && !_.isFunction(document.documentElement.attachShadow)) {
                        return Sizzle(selection.replace(new RegExp(shadowAPI.PSEUDO_ELEMENT, 'g'), ''), context, results, seed);
                    }
    
                    // We'll need to potentially be a Recursive Descent Parser if the Selector
                    // has Shadow Root piercing pseudo selector.
                    if (isShadowSelector(selection)) {
                        var shadowQuery = parseShadowSelector(selection);
                        var baseElem = shadowSizzleWrapper(shadowQuery.baseCss, context);
    
                        return _.reduce(baseElem, function(nodes, base) {
                            if (!shadowAPI.getShadowRoot(base)) return nodes;
    
                            return nodes.concat(
                                shadowSizzleWrapper(shadowQuery.shadowCss, shadowAPI.getShadowRoot(base), results, seed)
                            );
                        }, []);
                    } else {
    
                        // base case
                        return Sizzle(selection, context, results, seed);
                    }
                }, Sizzle);
    
                ShadowSizzle.matchesSelector = _.wrap(ShadowSizzle.matchesSelector, function(matchesSelector, element, selector) {
                    if (shadowAPI.isElementShadowRoot(element)) {
                        return false;
                    }
    
                    if (isShadowSelector(selector)) {
                        return ShadowSizzle(selector, document, null, [element]).length > 0;
                    }
    
                    return matchesSelector(element, selector);
                });
    
                return ShadowSizzle;
            }
        };
    })();
    
    var pendo = window.pendo = window.pendo || {};
    
    // modified export mechanism in underscore.js, sizzle, and Zlib
    var _ = pendo._ = UNDERSCORE_EXT._;
    var Sizzle = pendo.Sizzle = shadowAPI.wrapSizzle(SIZZLE_EXT.Sizzle);
    var Zlib = pendo.Zlib = {};
    
    var ENV = 'prod',
        VERSION = pendo.VERSION = '2.54.0_prod';
    
    var getUA = function() {
        return navigator.userAgent;
    };
    
    var getVersion = function() {
        if (isBrowserInQuirksmode()) {
            return VERSION + '+quirksmode';
        }
    
        return VERSION;
    };
    
    var ConfigReader = (function() {
        // imports
        var each = _.each;
        var filter = _.filter;
        var first = _.first;
        var find = _.find;
        var findWhere = _.findWhere;
        var map = _.map;
        var pluck = _.pluck;
        // get
    
        var SNIPPET_SRC = 'snippet';
        var PENDO_CONFIG_SRC = 'pendoconfig';
        var GLOBAL_SRC = 'global';
    
        /*
        * Option Schema
        *
        * name - Name of the option
        *
        * defaultValue - Value returned if nothing else is set. Also, defines the
        *  baseline value to determine if somethings is affirmatively set or not.
        *
        * supportedSources - ordered list that describes where to check first,
        *  defaults to SNIPPET_SRC, PENDO_CONFIG_SRC, GLOBAL_SRC
        *
        * useAnySource - indicates that the supportedSources list are all
        *  equal in priority. Meaning that if any are set and not matching the
        *  default value then it'll be returned.
        */
    
        var optionList = [
            {
                'name':             'preventCodeInjection',
                'defaultValue':     false,
                'supportedSources': [SNIPPET_SRC, PENDO_CONFIG_SRC, GLOBAL_SRC]
            },
            {
                'name':             'pendoCore',
                'defaultValue':     true,
                'supportedSources': [PENDO_CONFIG_SRC]
            },
            {
                'name':             'apiKey',
                'supportedSources': [SNIPPET_SRC, PENDO_CONFIG_SRC]
            },
            {
                'name':             'additionalApiKeys',
                'supportedSources': [SNIPPET_SRC, PENDO_CONFIG_SRC]
            },
            {
                'name':             'enableDesignerKeyboardShortcut',
                'supportedSources': [SNIPPET_SRC]
            },
            {
                'name':             'disableDesignerKeyboardShortcut',
                'defaultValue':     false,
                'supportedSources': [PENDO_CONFIG_SRC]
            },
            {
                'name':             'pendoFeedback',
                'defaultValue':     false,
                'supportedSources': [PENDO_CONFIG_SRC]
            },
            {
                'name':             'disableFeedbackAutoInit',
                'supportedSources': [PENDO_CONFIG_SRC]
            },
            {
                'name':             'cookieDomain',
                'supportedSources': [SNIPPET_SRC, PENDO_CONFIG_SRC]
            },
            {
                'name':             'feedbackSettings',
                'supportedSources': [PENDO_CONFIG_SRC]
            },
            {
                'name':             'htmlAttributes',
                'supportedSources': [PENDO_CONFIG_SRC]
            },
            {
                'name':             'htmlAttributeBlacklist',
                'supportedSources': [PENDO_CONFIG_SRC]
            },
            {
                'name':             'xhrTimings',
                'supportedSources': [PENDO_CONFIG_SRC]
            },
            {
                'name':             'localStorageOnly',
                'supportedSources': [SNIPPET_SRC, PENDO_CONFIG_SRC]
            },
            {
                'name':             'disableCookies',
                'supportedSources': [SNIPPET_SRC, PENDO_CONFIG_SRC]
            },
            {
                'name':             'freeNPSData',
                'supportedSources': [PENDO_CONFIG_SRC]
            },
            {
                'name':             'feedbackSettings',
                'supportedSources': [PENDO_CONFIG_SRC]
            },
            {
                'name':             'contentHost',
                'supportedSources': [SNIPPET_SRC]
            },
            {
                'name':             'guideSeenTimeoutLength',
                'supportedSources': [PENDO_CONFIG_SRC],
                'defaultValue':     10000
            },
            {
                'name':             'disableGlobalCSS',
                'supportedSources': [SNIPPET_SRC, PENDO_CONFIG_SRC],
                'defaultValue':     false
            },
            {
                'name':             'disablePersistence',
                'supportedSources': [PENDO_CONFIG_SRC, SNIPPET_SRC]
            },
            {
                'name':             'enableSignedMetadata',
                'supportedSources': [PENDO_CONFIG_SRC],
                'defaultValue':     false
            },
            {
                'name':             'requireSignedMetadata',
                'supportedSources': [PENDO_CONFIG_SRC],
                'defaultValue':     false
            },
            {
                'name':             'guideValidation',
                'supportedSources': [SNIPPET_SRC, PENDO_CONFIG_SRC],
                'defaultValue':     false
            },
            {
                'name':             'enableGuideTimeout',
                'supportedSources': [SNIPPET_SRC, PENDO_CONFIG_SRC],
                'defaultValue':     false
            },
            {
                'name':             'blockAgentMetadata',
                'supportedSources': [PENDO_CONFIG_SRC],
                'defaultValue':     false
            },
            {
                'name':             'adoptHost',
                'supportedSources': [PENDO_CONFIG_SRC]
            },
            {
                'name':             'allowedText',
                'supportedSources': [SNIPPET_SRC, PENDO_CONFIG_SRC],
                'defaultValue':     []
            },
            {
                'name':             'excludeAllText',
                'supportedSources': [PENDO_CONFIG_SRC, SNIPPET_SRC],
                'defaultValue':     false,
                'useAnySource':     true
            },
            {
                'name':             'dataHost',
                'supportedSources': [SNIPPET_SRC]
            },
            {
                'name':             'blockLogRemoteAddress',
                'supportedSources': [PENDO_CONFIG_SRC]
            },
            {
                'name':             'ignoreHashRouting',
                'supportedSources': [PENDO_CONFIG_SRC, SNIPPET_SRC]
            },
            {
                'name':             'xhrWhitelist',
                'supportedSources': [PENDO_CONFIG_SRC]
            }
            // TODO: delayGuides, guides.delay, guideTimeout, guides.timeout,
            // guides.tooltip.arrowSize, guides.disabled, disableGuides,
            // guides.attachPoint, annotateUrl, queryStringWhitelist
        ];
    
        var sourceGetters = {};
        sourceGetters[SNIPPET_SRC] = function() {
            return { 'lookup': originalOptions || window.pendo_options, 'name': SNIPPET_SRC };
        };
        sourceGetters[PENDO_CONFIG_SRC] = function() {
            var lookup = typeof PendoConfig !== 'undefined' ? PendoConfig : {};
            return { 'lookup': lookup, 'name': PENDO_CONFIG_SRC };
        };
        sourceGetters[GLOBAL_SRC] = function() {
            return { 'lookup': pendo, 'name': GLOBAL_SRC };
        };
    
        function findOption(name) {
            return findWhere(optionList, { 'name': name }) || { 'name': name };
        }
    
        function getSupportedSources(option) {
            return get(option, 'supportedSources', [SNIPPET_SRC, PENDO_CONFIG_SRC, GLOBAL_SRC]);
        }
    
        function getValueFromSource(option, sourceGetter) {
            if (!sourceGetter) return;
            var source = sourceGetter();
            var v = get(source.lookup, option.name);
            return doesExist(v) ? v : undefined;
        }
    
        function mapSourcesToValues(option) { //: <source,value>[]
            return map(getSupportedSources(option), function(src) {
                var val = getValueFromSource(option, sourceGetters[src]);
                return new ConfigValue(option.name, val, src);
            });
        }
    
        function findSourceAndValue(optionName, defaultValue) {
            var option = findOption(optionName);
            defaultValue = defaultValue || get(option, 'defaultValue', null);
            var defaultReturn = new ConfigValue(optionName, defaultValue, 'default');
    
            var validOptions = filter(mapSourcesToValues(option), function(cv) {
                return doesExist(cv.value);
            });
    
            // defaultValue must exist in order to use non-ordered sources,
            // otherwise you can't know what value to value over another.
            if (option.useAnySource && doesExist(defaultValue)) {
                return find(validOptions, function(configValue) {
                    return configValue.value != defaultValue;
                }) || defaultReturn;
            }
    
            return first(validOptions) || defaultReturn;
        }
    
        function ConfigValue(name, value, source) {
            this.name = name;
            this.value = value;
            this.source = source;
        }
    
        /*eslint-disable no-console*/
        return {
            'audit': function() {
                // for each option, look if its set in multiple sources.
                // log when snippet and pendoconfig don't match
                console.log('not implemented');
            },
    
            'get': function(optionName, defaultValue) {
                var result = findSourceAndValue(optionName, defaultValue);
                return result.value;
            },
    
            'options': pluck(optionList, 'name'),
    
            'validate': function(console) {
                console.group('Validate Config options');
                each(optionList, function(opt) {
                    var r = findSourceAndValue(opt.name);
                    console.log('Found option ' + r.name + ' with value ' + r.value + ' from source ' + r.source);
                });
                console.groupEnd();
            }
        };
        /*eslint-enable no-console*/
    })();
    
    // Handles cases where localStorage is either not defined or inaccessible
    // by providing a do-nothing implementation
    
    // NOTE: Recently added a LocalStorage preference over cookies that is implemented
    // `agentStorage` in `browserStorage.js`. These two should be reconciled but for
    // now this shim was only used from Designer related parts of the Agent so the
    // separation was an easy thing to maintain.
    
    var pendoLocalStorage = (function() {
        var noop = _.noop;
        var fake = {
            'getItem':    noop,
            'setItem':    noop,
            'removeItem': noop
        };
    
        try {
            var ls = window.localStorage;
            if (!ls) return fake;
            return ls;
        } catch (e) {
            return fake;
        }
    })();
    
    /** @license aypromise - cburgmer [ https://github.com/cburgmer/ayepromise ] The WTFPL License */
    var q = (function () {
    var ayepromise = {};
    
        /* Wrap an arbitrary number of functions and allow only one of them to be
           executed and only once */
        var once = function () {
            var wasCalled = false;
    
            return function wrapper(wrappedFunction) {
                return function () {
                    if (wasCalled) {
                        return;
                    }
                    wasCalled = true;
                    wrappedFunction.apply(null, arguments);
                };
            };
        };
    
        var getThenableIfExists = function (obj) {
            // Make sure we only access the accessor once as required by the spec
            var then = obj && obj.then;
    
            if (typeof obj === "object" && typeof then === "function") {
                // Bind function back to it's object (so lousy 'this' will work)
                return function() { return then.apply(obj, arguments); };
            }
        };
    
        var aThenHandler = function (onFulfilled, onRejected) {
            var defer = ayepromise.defer();
    
            var doHandlerCall = function (func, value) {
                setTimeout(function () {
                    var returnValue;
                    try {
                        returnValue = func(value);
                    } catch (e) {
                        defer.reject(e);
                        return;
                    }
    
                    if (returnValue === defer.promise) {
                        defer.reject(new TypeError('Cannot resolve promise with itself'));
                    } else {
                        defer.resolve(returnValue);
                    }
                }, 1);
            };
    
            var callFulfilled = function (value) {
                if (onFulfilled && onFulfilled.call) {
                    doHandlerCall(onFulfilled, value);
                } else {
                    defer.resolve(value);
                }
            };
    
            var callRejected = function (value) {
                if (onRejected && onRejected.call) {
                    doHandlerCall(onRejected, value);
                } else {
                    defer.reject(value);
                }
            };
    
            return {
                promise: defer.promise,
                handle: function (state, value) {
                    if (state === FULFILLED) {
                        callFulfilled(value);
                    } else {
                        callRejected(value);
                    }
                }
            };
        };
    
        // States
        var PENDING = 0,
            FULFILLED = 1,
            REJECTED = 2;
    
        ayepromise.defer = function () {
            var state = PENDING,
                outcome,
                thenHandlers = [];
    
            var doSettle = function (settledState, value) {
                state = settledState;
                // Persist for handlers registered after settling
                outcome = value;
    
                _.each(thenHandlers, function (then) {
                    then.handle(state, outcome);
                });
    
                // Discard all references to handlers to be garbage collected
                thenHandlers = null;
            };
    
            var doFulfill = function (value) {
                doSettle(FULFILLED, value);
            };
    
            var doReject = function (error) {
                doSettle(REJECTED, error);
            };
    
            var registerThenHandler = function (onFulfilled, onRejected) {
                var thenHandler = aThenHandler(onFulfilled, onRejected);
    
                if (state === PENDING) {
                    thenHandlers.push(thenHandler);
                } else {
                    thenHandler.handle(state, outcome);
                }
    
                // Allow chaining of calls: something().then(...).then(...)
                return thenHandler.promise;
            };
    
            var safelyResolveThenable = function (thenable) {
                // Either fulfill, reject or reject with error
                var onceWrapper = once();
                try {
                    thenable(
                        onceWrapper(transparentlyResolveThenablesAndSettle),
                        onceWrapper(doReject)
                    );
                } catch (e) {
                    onceWrapper(doReject)(e);
                }
            };
    
            var transparentlyResolveThenablesAndSettle = function (value) {
                var thenable;
    
                try {
                    thenable = getThenableIfExists(value);
                } catch (e) {
                    doReject(e);
                    return;
                }
    
                if (thenable) {
                    safelyResolveThenable(thenable);
                } else {
                    doFulfill(value);
                }
            };
    
            var onceWrapper = once();
            return {
                resolve: onceWrapper(transparentlyResolveThenablesAndSettle),
                reject: onceWrapper(doReject),
                promise: {
                    then: registerThenHandler,
                    fail: function (onRejected) {
                        return registerThenHandler(null, onRejected);
                    }
                }
            };
        };
    
        return ayepromise;
    })();
    q.all = function(promises) {
        //Wait for all promises to resolve (or for one to reject)
        var deferred = q.defer();
        var finalResult = _.isArray(promises) ? [] : {};
        var outstanding = _.size(promises);
        if (!outstanding) return q.resolve(promises);
        var rejected = false;
        _.each(promises, function(promise, key) {
            q.resolve(promise).then(function(partialResult) {
                finalResult[key] = partialResult;
                if (--outstanding === 0 && !rejected) {
                    deferred.resolve(finalResult);
                }
            }, function(e) {
                if (!rejected) {
                    rejected = true;
                    deferred.reject(e);
                }
            });
        });
        return deferred.promise;
    };
    
    q.reject = function(rejection) {
        var deferred = q.defer();
        deferred.reject(rejection);
        return deferred.promise;
    };
    
    q.resolve = function(result) {
        var deferred = q.defer();
        deferred.resolve(result);
        return deferred.promise;
    };
    
    //Wraps any function with a try/catch that reports errors back to the server
    // Optionally will log the exception. Defaults to logging enabled.
    var makeSafe = function(method, noLogging) {
        noLogging = !!noLogging;
    
        return function() {
            try {
                return method.apply(this, arguments);
            } catch (e) {
                if (!noLogging) {
                    writeException(e);
                }
            }
        };
    };
    
    function Eventable() {
        var handlers = this._handlers = {};
    
        this.on = function(type, callback) {
            if (_.isString(type) || _.isFunction(callback)) {
                var listeners = handlers[type];
                if (!listeners) {
                    listeners = handlers[type] = [];
                }
                if (_.indexOf(listeners, callback) < 0) {
                    listeners.push(callback);
                }
            }
            return this;
        };
    
        this.one = function(type, callback) {
            var self = this;
            var triggerOnce = function() {
                self.off(type, triggerOnce);
                callback.apply(this, arguments);
            };
            return this.on(type, triggerOnce);
        };
    
        this.off = function(type, callback) {
            var listeners = handlers[type];
            if (_.isFunction(callback)) {
                var i = _.indexOf(listeners, callback);
                if (listeners && i >= 0) {
                    listeners.splice(i, 1);
                }
            } else if (listeners && callback === undefined) {
                listeners.length = 0;
            }
            return this;
        };
    
        this.trigger = function(type) {
            var listeners = handlers[type],
                args = _.toArray(arguments).slice(1);
            var results = _.map(listeners, function(callback) {
                var result = callback.apply(pendo, args);
                return result === false ? q.reject() : result;
            });
            return q.all(results);
        };
    
        return this;
    }
    
    pendo.events = (function() {
    
        var events = Eventable.call({});
    
        _.each([
            //Supported events
            'ready',
            'deliverablesLoaded',
            'guidesFailed',
            'guidesLoaded',
            'validateGuide',
            'validateLauncher',
            'validateGlobalScript'
        ], function(eventName) {
            events[eventName] = function(callback) {
                if (_.isFunction(callback)) {
                    return events.on(eventName, callback);
                } else {
                    return events.trigger.apply(events, [eventName].concat(_.toArray(arguments)));
                }
            };
        });
    
        return events;
    
    })();
    
    var whenLoadedCall = function(callback) {
        if (document.readyState === 'complete')
            {callback();}
        else
            {attachEvent(window, 'load', callback);}
    };
    
    var escapeStringsInObject = function(obj, depth) {
        if (!depth) {
            depth = 0;
        }
        if (depth >= 200) {
            return obj;//Prevent recursion depth problems
        }
        if (_.isArray(obj)) {
            return _.map(obj, function(val) {
                return escapeStringsInObject(val, depth + 1);
            });
        } else if (_.isObject(obj) && !_.isDate(obj) && !_.isRegExp(obj) && !_.isElement(obj)) {
            var clone = {};
            _.each(obj, function(value, key) {
                clone[key] = escapeStringsInObject(value, depth + 1);
            });
            return clone;
        } else if (_.isString(obj)) {
            return _.escape(obj);
        } else {
            return obj;
        }
    };
    
    pendo.compress = function(json_obj) {
        /* -- This is ZLIB */
        var compressData = pendo.toUTF8Array(JSON.stringify(json_obj));
        var deflate = new Zlib.Deflate(compressData);
        var compressedBytes = deflate.compress();
        var compressedString = pendo.fromByteArray(compressedBytes);
    
        return compressedString;
    };
    
    var crc32 = function(json_obj) {
        if (typeof json_obj !== 'undefined') {
            if (!_.isString(json_obj)) {
                json_obj = JSON.stringify(json_obj);
            }
            var byteArray = pendo.toUTF8Array(json_obj);
            return Zlib.CRC32.calc(byteArray, 0, byteArray.length);
        }
    };
    
    pendo.squeezeAndCompress = function(json_obj) {
        var results = pendo.compress(json_obj);
        return results;
    };
    
    pendo.letters = 'abcdefghijklmnopqrstuvwxyz';
    pendo.charset = pendo.letters + pendo.letters.toUpperCase() + '1234567890';
    
    pendo.randomElement = function randomElement(array) {
        return array[Math.floor(Math.random() * array.length)];
    };
    
    pendo.randomString = function randomString(length) {
        var R = '';
        var charset = pendo.charset.split('');
        for(var i = 0; i < length; i++)
            {R += pendo.randomElement(charset);}
        return R;
    };
    
    pendo.toUTF8Array = function(str) {
        var utf8 = [];
        for (var i = 0; i < str.length; i++) {
            var charcode = str.charCodeAt(i);
            if (charcode < 0x80) utf8.push(charcode);
            else if (charcode < 0x800) {
                utf8.push(0xc0 | (charcode >> 6),
                          0x80 | (charcode & 0x3f));
            }
            else if (charcode < 0xd800 || charcode >= 0xe000) {
                utf8.push(0xe0 | (charcode >> 12),
                          0x80 | ((charcode >> 6) & 0x3f),
                          0x80 | (charcode & 0x3f));
            }
            // surrogate pair
            else {
                i++;
                // UTF-16 encodes 0x10000-0x10FFFF by
                // subtracting 0x10000 and splitting the
                // 20 bits of 0x0-0xFFFFF into two halves
                charcode = 0x10000 + (((charcode & 0x3ff) << 10)
                          | (str.charCodeAt(i) & 0x3ff));
                utf8.push(0xf0 | (charcode >> 18),
                          0x80 | ((charcode >> 12) & 0x3f),
                          0x80 | ((charcode >> 6) & 0x3f),
                          0x80 | (charcode & 0x3f));
            }
        }
        return utf8;
    };
    
    var strContains = function(strA, strB, ignoreCase) {
        if (!pendo.doesExist(strA) || !pendo.doesExist(strB)) return false;
    
        if (ignoreCase) {
            strA = strA.toLowerCase();
            strB = strB.toLowerCase();
        }
    
        return (strA.indexOf(strB) > -1);
    };
    
    function backupObjectState(obj, keys) {
        var backup = {};
        if (!keys) {
            keys = _.keys(obj);
        }
        _.each(keys, function(key) {
            var value = obj[key];
            if (_.isArray(value)) {
                backup[key] = value.slice();
            } else if (!_.isFunction(value)) {
                backup[key] = value;
            }
        });
        return function restoreObjectState() {
            _.each(backup, function(value, key) {
                obj[key] = value;
            });
        };
    }
    
    // Date.now() can be overridden by libraries to return a Date object instead of timestamp
    // This is our now() function
    function getNow() {
        return new Date().getTime();
    }
    
    function isSfdcLightning() {
        /*global $A*/
        return typeof $A !== 'undefined' && _.isFunction($A.get) && _.isString($A.get('$Browser.formFactor'));
    }
    
    function createStatefulIterator(keyFn) {
        if (!_.isFunction(keyFn)) {
            keyFn = function(obj, i) {
                return i;
            };
        }
    
        return {
            'lastKey':   null,
            'eachUntil': eachUntil,
            'reset':     reset
        };
    
        function skipToNextKey(array, lastKey) {
            if (!lastKey) return array;
    
            for (var i = 0, ii = array.length; i < ii; ++i) {
                if (keyFn(array[i], i) === lastKey) {
                    return array.slice(i + 1).concat(array.slice(0, i + 1));
                }
            }
    
            return array;
        }
    
        function eachUntil(array, fn) {
            if (!array || !array.length) return;
    
            array = skipToNextKey(array, this.lastKey);
    
            for (var i = 0; i < array.length; ++i) {
                if (fn(array[i], i)) {
                    this.lastKey = keyFn(array[i], i);
                    return;
                }
            }
    
            this.lastKey = null;
        }
    
        function reset() {
            this.lastKey = null;
        }
    }
    
    function throttleIterator(maxTimeMs, iterator) {
        iterator.eachUntil = _.wrap(iterator.eachUntil, function(eachUntil, array, fn) {
            var startTime = getNow();
            return eachUntil.call(this, array, function() {
                return fn.apply(this, arguments) || Math.abs(getNow() - startTime) >= maxTimeMs;
            });
        });
        return iterator;
    }
    
    function getHashFromContentUrl(url) {
        if (!_.isString(url)) return;
        var filename = _.last(url.split('/'));
        return _.first(filename.split('.'));
    }
    
    function get(obj, path, defaultValue) {
        if (_.isString(path)) {
            if (doesExist(obj) && doesExist(obj[path])) {
                return obj[path];
            }
    
            var splitPath = path.split('.');
            for (var i = 0, ii = splitPath.length; i < ii; ++i) {
                if (doesExist(obj)) {
                    obj = obj[splitPath[i]];
                } else {
                    return defaultValue;
                }
            }
            return doesExist(obj) ? obj : defaultValue;
        }
        return defaultValue;
    }
    
    function getZoneSafeMethod(method) {
        var zoneSymbol = '__symbol__';
        /* global Zone */
        if (typeof Zone !== 'undefined' && _.isFunction(Zone[zoneSymbol])) {
            var fn = window[Zone[zoneSymbol](method)];
            if (_.isFunction(fn)) {
                return fn;
            }
        }
        return window[method];
    }
    
    /*
    * EventTracer.addTracerIds - Returns a new copy of the original object with
    * additional, contextual IDs added that provide a means of tracing event output
    * when reviewed for debugging purposes.
    *
    * Glossary
    * TabId - ID that identifies the entire browser tab. it will persist across even
    *         page loads but is unique the tab.
    * FrameId - ID that identifies the Frame or (Window) and will be generated
    *           whenever a frame is created.
    * SessionId - ID that identifies the list of Guides and other deliverables
    *             loaded in the guide.js[on] call. It will change with each call.
    *             This won't exist until guides have been loaded.
    *             This should get invalidated when the load guide event fires.
    */
    
    var EventTracer = (function() {
        var randomString = pendo.randomString;
        var partial = _.partial;
        var compose = _.compose;
        var extend = _.extend;
        var omit = _.omit;
        var events = pendo.events;
    
        var SESSION_ID = 'pendo_sessionId',
            FRAME_ID = 'pendo_frameId',
            TAB_ID = 'pendo_tabId';
    
        var MemoryStorage = {
            'data':    {},
            'getItem': function(key) { return MemoryStorage.data[key]; },
            'setItem': function(key, val) { MemoryStorage.data[key] = val; },
            'clear':   function(key) {
                MemoryStorage.data[key] = null;
                delete MemoryStorage.data[key];
            }
        };
    
        var getOrCreateTabId = partial(getOrCreateKV, TAB_ID, sessionStorage);
        var getOrCreateFrameId = partial(getOrCreateKV, FRAME_ID, MemoryStorage);
        var getOrCreateSessionId = partial(getOrCreateKV, SESSION_ID, MemoryStorage);
    
        function invalidateKey(key, storage) {
            storage.clear(key);
        }
    
        function getOrCreateKV(key, storage) {
            try {
                var v = storage.getItem(key);
                if (!v) {
                    v = randomString(16);
                    storage.setItem(key, v);
                }
                return v;
            } catch (e) {
                log('Unable to access storage: ' + e);
            }
            return; // undefined
        }
    
        events.guidesLoaded(
            compose(
                getOrCreateSessionId,
                partial(invalidateKey, SESSION_ID, MemoryStorage)
            )
        );
    
        return {
            'addTracerIds': function(obj) {
                return omit(extend(obj, {
                    'tabId':     getOrCreateTabId(),
                    'frameId':   getOrCreateFrameId(),
                    'sessionId': MemoryStorage.getItem(SESSION_ID)
                }), function(v) { return v === undefined; });
            }
        };
    })();
    
    // "Borrowed" from http://www.openjs.com/scripts/dom/class_manipulation.php
    var _hasClass = function(ele, cls) {
        try {
            var pattern = new RegExp('(\\s|^)' + cls + '(\\s|$)');
            return pattern.test(_getClass(ele));
        } catch (e) {
            return false;
        }
    };
    
    var _addClass = function(ele, cls) {
        try {
            if (!_hasClass(ele, cls)) {
                var newClass = _getClass(ele).trim() + ' ' + cls;
                _setClass(ele, newClass);
            }
        } catch (e) {
        }
    };
    
    var _removeClass = function(ele, cls) {
        try {
            if (_hasClass(ele, cls)) {
                var reg = new RegExp('(\\s|^)' + cls + '(\\s|$)');
                var newClass = _getClass(ele).replace(reg, ' ');
                _setClass(ele, newClass);
            }
        } catch (e) {
        }
    };
    
    var _setClass = function(ele, cls) {
        if (_.isString(ele.className)) {
            ele.className = cls;
        } else {
            ele.setAttribute('class', cls);// SVG elements and such, does not work in older IEs
        }
    };
    
    var _getClass = function(ele) {
        try {
            var className = ele.className;
            className = _.isString(className) || !pendo.doesExist(className) ? className : ele.getAttribute('class');
            return className || '';
        } catch (e) {
            return '';
        }
    };
    
    var _getCss3Prop = function(cssprop) {
        function camelCase(str) {
            return str.replace(/-([a-z])/gi, function(match, p1) { // p1 references submatch in parentheses
                return p1.toUpperCase(); // convert first letter after "-" to uppercase
            });
        }
        var css3propcamel = camelCase(cssprop);
        var firstChar = css3propcamel.substr(0, 1);
        css3propcamel = firstChar.toLowerCase() + css3propcamel.substr(1);
        return css3propcamel;
    };
    
    var cssNumber = {// Do not auto-px these unit-less numbers
        'columnCount': true,
        'fillOpacity': true,
        'flexGrow':    true,
        'flexShrink':  true,
        'fontWeight':  true,
        'lineHeight':  true,
        'opacity':     true,
        'order':       true,
        'orphans':     true,
        'widows':      true,
        'zIndex':      true,
        'zoom':        true
    };
    
    var setStyle = function(element, style) {
        if (_.isString(style)) {
            var styleArray = style.split(';'),
                pair, key, i, j;
            style = {};
            for (i = 0; i < styleArray.length; i++) {
                pair = styleArray[i];
                j = pair.indexOf(':');
                key = pair.substring(0, j);
                style[key] = pair.substring(j + 1);
            }
        }
        _.each(style, function(value, key) {
            key = _getCss3Prop(trim.call(key));
            if (key !== '') {
                if (_.isNumber(value) && !isNaN(value) && !cssNumber[key]) {
                    value = '' + value + 'px';// Automatically add units to numbers
                } else if (!_.isString(value)) {
                    value = '' + value;
                }
    
                try {
                    element.style[key] = trim.call(value);
                } catch (e) {
                    log('failed to set style: ' + key + ' with value ' + value);
                }
            }
        });
    };
    
    var getScreenDimensions = function() {
        if (isBrowserInQuirksmode()) {
            return {
                'width':  document.documentElement.offsetWidth || 0,
                'height': document.documentElement.offsetHeight || 0
            };
        }
    
        var w = window.innerWidth || document.documentElement.clientWidth;
        var h = window.innerHeight || document.documentElement.clientHeight;
        return { 'width': w, 'height': h };
    };
    
    var _isInViewport = function(elemPos) {
        var screenDim = getScreenDimensions(),
            scrollTop = documentScrollTop(),
            scrollLeft = documentScrollLeft();
        return (
            elemPos.top >= scrollTop &&
                elemPos.left >= scrollLeft &&
                (elemPos.top + elemPos.height) <= (scrollTop + screenDim.height) &&
                (elemPos.left + elemPos.width) <= (scrollLeft + screenDim.width)
        );
    };
    
    function documentScrollTop() {
        var docElem = document.documentElement;
        return (window.pageYOffset || docElem.scrollTop || getBody().scrollTop) - (docElem.clientTop || 0);
    }
    
    function documentScrollLeft() {
        var docElem = document.documentElement;
        return (window.pageXOffset || docElem.scrollLeft || getBody().scrollLeft) - (docElem.clientLeft || 0);
    }
    
    /**
     * @typedef {Object} Position
     * @property {Number} top
     * @property {Number} left
     * @property {Boolean} fixed True if the position is relative to the viewport, false if relative to the document
     */
    
    /**
     * Doing certain things to the body element with CSS changes the body's
     * coordinate space, which affects absolute positioning of elements
     * (like, for example, guides).
     *
     * If you apply the following styles to the body element:
     *  - position:relative
     *  - position:absolute
     *  - a CSS transform
     *
     * ... then getBoundingClientRect will still give you coordinates that are
     * correct, and that's great! However, if you try to use those coordinates
     * to position a guide, you're going to have a Bad Time. This function
     * detects these conditions and figures out what the body's offset from
     * "normal" (i.e. 0,0) is.
     *
     * @return {Position} The top/left offset position of the body
     */
    function bodyOffset() {
        var body = getBody();
        if (body) {
            var bodyStyle = getComputedStyle_safe(body);
            if (bodyStyle && (bodyStyle.position === 'relative' || bodyStyle.position === 'absolute' || hasCssTransform(bodyStyle))) {
                var rect = body.getBoundingClientRect();
                return {
                    'top':  rect.top + documentScrollTop(),
                    'left': rect.left + documentScrollLeft()
                };
            }
        }
        return { 'top': 0, 'left': 0 };
    }
    
    /**
     * @see {@link bodyOffset} for explanation of why this is a thing
     * @return {Boolean}
     */
    function positionFixedActsLikePositionAbsolute() {
        return hasCssTransform(getComputedStyle_safe(getBody())) && isNaN(msie);
    }
    
    /**
     * Checks if the style declares a CSS transform
     * @see sniffer.js for vendorPrefix definition
     * @param  {CSSStyleDeclaration}  style
     * @return {Boolean}
     */
    function hasCssTransform(style) {
        if (style && _.isFunction(style.getPropertyValue)) {
            var transforms = [style.getPropertyValue('transform')];
    
            if (typeof vendorPrefix !== 'undefined' && _.isString(vendorPrefix)) {
                transforms.push(style.getPropertyValue('-' + vendorPrefix.toLowerCase() + '-transform'));
            }
    
            return _.any(transforms, function(t) {
                return t && t !== 'none';
            });
        }
        return false;
    }
    
    /**
     * @typedef {Object} Rect
     * @property {Number} top
     * @property {Number} left
     * @property {Number} bottom
     * @property {Number} right
     * @property {Number} width
     * @property {Number} height
     * @property {Boolean} fixed
     */
    
    /**
     * Offsets the position (or rect) by the body's offset.
     * @see bodyOffset
     * @param  {Position|Rect} positionOrRect
     * @return {Position|Rect}
     */
    function applyBodyOffset(positionOrRect) {
        var offset = bodyOffset();
        positionOrRect.left -= offset.left;
        positionOrRect.top -= offset.top;
        if (_.isNumber(positionOrRect.right)) {
            positionOrRect.right -= offset.left;
        }
        if (_.isNumber(positionOrRect.bottom)) {
            positionOrRect.bottom -= offset.top;
        }
        return positionOrRect;
    }
    
    function roundOffsetPosition(position) {
        _.each(['left', 'top', 'width', 'height'], function(key) {
            position[key] = Math.round(position[key]);
        });
        return position;
    }
    
    function getOffsetPosition(element) {
        var elementPosition, _x, _y;
    
        if (!element) { return {'width': 0, 'height': 0}; }
    
        elementPosition = {
            'width':  _.isNumber(element.offsetWidth) ? element.offsetWidth : 0,
            'height': _.isNumber(element.offsetHeight) ? element.offsetHeight : 0
        };
        _x = 0;
        _y = 0;
    
        if (element.getBoundingClientRect) {
            // Use getBoundingClientRect if available
            var box;
            try {
                box = element.getBoundingClientRect();
            } catch (e) {
                // "Unspecified error" in IE, element not attached to the DOM yet
                return {'width': 0, 'height': 0};
            }
    
            elementPosition.top = box.top;
            elementPosition.left = box.left;
    
            // getBoundingClientRect will return width/height when offsetWidth/Height does not
            // IE8 and earlier will return a bounding box without width/height
            elementPosition.width = Math.max(elementPosition.width, _.isNumber(box.width) ? box.width : 0);
            elementPosition.height = Math.max(elementPosition.height, _.isNumber(box.height) ? box.height : 0);
    
            if (isPositionFixed(element)) {
                elementPosition.fixed = true;
            } else {
                // Offset by the document scroll position if not in a fixed position parent
                elementPosition.top += documentScrollTop();
                elementPosition.left += documentScrollLeft();
                elementPosition = applyBodyOffset(elementPosition);
            }
    
            return roundOffsetPosition(elementPosition);
        }
    
        while (element && !isNaN(element.offsetLeft) && !isNaN(element.offsetTop)) {
            _x += element.offsetLeft;
            _y += element.offsetTop;
            element = element.offsetParent;
        }
        elementPosition.top = _y;
        elementPosition.left = _x;
        return roundOffsetPosition(elementPosition);
    }
    
    // ~SizzleJS~ domQuery enabled
    var removeClass = function(selector, classname) {
        if (typeof selector === 'string') {
            var elems = dom(selector);
            _.map(elems, function(elem) { _removeClass(elem, classname); });
        } else {
            _removeClass(selector, classname);
        }
    };
    
    var addClass = function(selector, classname) {
        if (typeof selector === 'string') {
            var elems = dom(selector);
            _.map(elems, function(elem) { _addClass(elem, classname); });
        } else {
            _addClass(selector, classname);
        }
    };
    
    var removeNode = function(domNode) {
        if (domNode && domNode.parentNode) {
            domNode.parentNode.removeChild(domNode);
        }
    };
    
    var getElements = _.compose(
        function(arrLike) {
            return Array.prototype.slice.call(arrLike);
        },
        function(tag) {
            try {
                return Sizzle(tag);
            } catch (e) {
                writeMessage('error using sizzle: ' + e);
                return document.getElementsByTagName(tag);
            }
        });
    
    var pickBestBODY = function(b1, b2) {
        try {
            // check children.length, check Height, check Width?
            var b2Num = b2.children.length + b2.offsetHeight + b2.offsetWidth;
            var b1Num = b1.children.length + b1.offsetHeight + b1.offsetWidth;
            return b2Num - b1Num;
        } catch (e) {
            log('error interrogating body elements: ' + e);
            writeMessage('error picking best body:' + e);
            return 0;
        }
    };
    
    var getBody = function() {
        try {
            var bds = getElements('body');
            if (bds && bds.length > 1) {
                bds.sort(pickBestBODY);
                return bds[0] || document.body;
            }
    
            if (document.body && document.body.tagName && document.body.tagName.toLowerCase() !== 'body') {
                // For applications that use `frameset` as their body, we'll append guides to the first child node of
                // the document (which should always be <html>)
    
                // Since we're always expecting the result in this case to be <html>, we can simply return the `document.documentElement` property
                // of document as that works in IE back 5 and all modern browsers and is defined to be the HTML element.
                return document.documentElement;
            }
    
            return document.body;
        } catch (e) {
            writeMessage('Error getting body element: ' + e);
            return document.body;
        }
    };
    
    /**
     * Checks if the element is in the document
     * @param  {HTMLElement}  element
     * @return {Boolean}
     */
    function isInDocument(element) {
        return Sizzle.contains(document, element);
    }
    
    /*
        For APP-9593, short circuiting if NodeType is DOCUMENT_NODE.
        I'm not certain though that it wouldn't be better to do this instead.
        ```
        if (element.nodeType !== Node.ELEMENT_TYPE)
             return;
        ```
    
    */
    var checkIfElementNode = function(element) {
        // IE 7/8 don't have this ENUM but do use the nodeType of Number(1) according to MDN
        // https://developer.mozilla.org/en-US/docs/Web/API/Node/nodeType
        // https://developer.mozilla.org/en-US/docs/Web/API/NonDocumentTypeChildNode/nextElementSibling
    
        var isReasonableDefnOfNode = typeof Node !== 'undefined' && typeof Node.ELEMENT_NODE !== 'undefined';
        var ELEMENT_NODE = isReasonableDefnOfNode ? Node.ELEMENT_NODE : 1;
    
        return element && element.nodeType === ELEMENT_NODE;
    };
    
    var getComputedStyle_safe = makeSafe(function(element) {
        if (!checkIfElementNode(element)) {
            return;
        }
    
        if (window.getComputedStyle) {
            return getComputedStyle(element);
        } else if (element.currentStyle) {
            return element.currentStyle;
        }
    }, true /* disable logging */);
    
    var getClientRect = function(element) {
        var pbody = getBody();
    
        if (element === null) {
            return;
        } else if (element === pbody || element === document || element === window) {
            var viewport = {
                'left':   window.pageXOffset || pbody.scrollLeft,
                'top':    window.pageYOffset || pbody.scrollTop,
                'width':  window.innerWidth,
                'height': window.innerHeight
            };
            viewport.right = viewport.left + viewport.width;
            viewport.bottom = viewport.top + viewport.height;
            return viewport;
        } else {
            var clientRect = getOffsetPosition(element);
            clientRect.right = clientRect.left + clientRect.width;
            clientRect.bottom = clientRect.top + clientRect.height;
            return clientRect;
        }
    };
    
    var intersectRect = function(rect1, rect2) {
        if (rect1.top >= rect2.bottom) {
            return false;
        }
        if (rect1.bottom <= rect2.top) {
            return false;
        }
        if (rect1.left >= rect2.right) {
            return false;
        }
        if (rect1.right <= rect2.left) {
            return false;
        }
        return true;
    };
    
    /**
     * Checks if the element has a parent that uses CSS transforms.
     * @param  {HTMLElement}  element
     * @return {Boolean}
     */
    function hasParentWithCssTransform(element) {
        var node = element && element.parentNode;
        var style;
        while (node) {
            style = getComputedStyle_safe(node);
            if (hasCssTransform(style)) {
                return true;
            }
    
            node = node.parentNode;
        }
        return false;
    }
    
    /**
     * Checks if the element, or an ancestor, uses fixed positioning.
     * @param  {HTMLElement}  element
     * @return {Boolean}
     */
    function isPositionFixed(element) {
        var node = element;
        var style;
        while (node) {
            style = getComputedStyle_safe(node);
            if (!style) {
                return false;
            }
    
            if (style.position === 'fixed') {
                /*
                If you transformed a parent element, you broke fixed positioning, and you're a bad person,
                unless you're using IE, in which case you didn't break fixed positioning, but you're
                probably still a bad person.
                More info here: http://meyerweb.com/eric/thoughts/2011/09/12/un-fixing-fixed-elements-with-css-transforms/
                */
                if (!isNaN(msie)) {
                    return true;
                }
                return !hasParentWithCssTransform(node);
            }
    
            node = node.parentNode;
        }
        return false;
    }
    
    /* jshint sub:true */
    var getScrollParent = function(element, overflowPattern) {
        overflowPattern = overflowPattern || /(auto|scroll|hidden)/;
    
        var style,
            parent,
            parentPosition;
    
        var pbody = getBody();
    
        if (element === pbody || !isInDocument(element)) {
            return null;
        }
    
        parent = element;
        while (parent && parent != pbody) {
            style = getComputedStyle_safe(parent);
            if (!style) {
                return null;
            }
    
            parentPosition = style.position;
            if (parent !== element &&
                overflowPattern.test(style.overflow + style.overflowY + style.overflowX)) {
                return parent;
            } else if (parentPosition === 'absolute' || (parentPosition === 'fixed' && hasParentWithCssTransform(parent))) {
                parent = parent.offsetParent;
            } else if (parentPosition === 'fixed') {
                return null;
            } else {
                parent = parent.parentNode;
            }
        }
    
        return pbody;
    };
    
    /**
     * Returns the direction (if any) of the element's overflow style.
     * @param  {HTMLElement} elem
     * @param  {RegExp} overflowPattern
     * @return {OverflowDirection}
     */
    function getOverflowDirection(elem, overflowPattern) {
        var style = getComputedStyle_safe(elem);
    
        overflowPattern = overflowPattern || /(auto|scroll|hidden)/;
    
        if (!style) {
            return OverflowDirection.NONE;
        }
    
        if (overflowPattern.test(style.overflowY) &&
            overflowPattern.test(style.overflowX)) {
            return OverflowDirection.BOTH;
        }
    
        if (overflowPattern.test(style.overflowY)) {
            return OverflowDirection.Y;
        }
    
        if (overflowPattern.test(style.overflowX)) {
            return OverflowDirection.X;
        }
    
        if (overflowPattern.test(style.overflow)) {
            return OverflowDirection.BOTH;
        }
    
        return OverflowDirection.NONE;
    }
    
    /**
     * Overflow direction values.
     * @readonly
     * @enum {String}
     */
    var OverflowDirection = {
        'X':    'x',
        'Y':    'y',
        'BOTH': 'both',
        'NONE': 'none'
    };
    
    /**
     * Checks if a bounding box is visible within an
     * overflowable element.
     * @param  {Object} rect An element's bounding box
     * @param  {HTMLElement} scrollParent An overflowable element.
     * @param  {RegExp}  overflowPattern [description]
     * @return {Boolean}
     */
    function isVisibleInScrollParent(rect, scrollParent, overflowPattern) {
        var scrollRect = getClientRect(scrollParent);
        var direction = getOverflowDirection(scrollParent, overflowPattern);
    
        if (direction === OverflowDirection.BOTH) {
            if (!intersectRect(rect, scrollRect)) {
                return false;
            }
        }
    
        if (direction === OverflowDirection.Y) {
            if (rect.top >= scrollRect.bottom) {
                return false;
            }
            if (rect.bottom <= scrollRect.top) {
                return false;
            }
        }
    
        if (direction === OverflowDirection.X) {
            if (rect.left >= scrollRect.right) {
                return false;
            }
            if (rect.right <= scrollRect.left) {
                return false;
            }
        }
    
        return true;
    }
    
    /**
     * Determines if the element is the boy
     * @param  {HTMLElement}  element
     * @return {Boolean}
     */
    function isBodyElement(element) {
        return element && element.nodeName && element.nodeName.toLowerCase() === 'body';
    }
    
    /**
     * Checks if an element is visible, but does not
     * check overflow-able containers.
     * @param  {HTMLElement} element
     * @return {Boolean}
     */
    function isElementVisibleInBody(element) {
        if (!element) {
            return false;
        }
    
        if (isBodyElement(element)) { return true; }
    
        var clientRect = getClientRect(element);
    
        // Check if the element has no client width/height (display: none or removed from dom)
        if (clientRect.width === 0 || clientRect.height === 0) {
            return false;
        }
    
        var style = getComputedStyle_safe(element);
    
        if (style && style.visibility === 'hidden') {
            // Visibility is inherited and 'hidden' can be overridden by 'visible' in descendants,
            // so only check if the target element is hidden (i.e. no need to check parents)
            return false;
        }
    
        // Check if the element or any parent is invisible, but still has client width/height
        var parentNode = element;
        while (parentNode) {
            if (!style) {
                break;
            }
    
            if (style.display === 'none') {
                return false;
            }
            if (Number(style.opacity) <= 0) {
                return false;
            }
            parentNode = parentNode.parentNode;
            style = getComputedStyle_safe(parentNode);
        }
    
        return true;
    }
    
    /**
     * Checks if an element is visible, including if the
     * element is outside the visible area of some
     * overflow-able container.
     * @param  {HTMLElement} element
     * @param  {RegExp} overflowPattern Types of overflows to check (auto, scroll, hidden)
     * @return {Boolean}
     */
    function isElementVisible(element, overflowPattern) {
        if (!isElementVisibleInBody(element)) {
            return false;
        }
    
        if (isBodyElement(element)) {
            return true;
        }
    
        // Check if element is visible within any overflow:hidden areas
        var clientRect = getClientRect(element);
        overflowPattern = overflowPattern || /hidden/;
        var scrollParent = getScrollParent(element, overflowPattern);
        var prevScrollParent = null;
        var pbody = getBody();
    
        while (scrollParent && scrollParent !== pbody && scrollParent !== document && scrollParent !== prevScrollParent) {
            if (!isVisibleInScrollParent(clientRect, scrollParent, overflowPattern)) {
                return false;
            }
    
            prevScrollParent = scrollParent;
            scrollParent = getScrollParent(scrollParent, overflowPattern);
        }
    
        // Check if the element is outside of the viewport in
        // a way that we can't scroll to it
        if (element.getBoundingClientRect) { // Sorry IE 7 and 8
            var rect = element.getBoundingClientRect();
            var right = rect.right;
            var bottom = rect.bottom;
            if (!clientRect.fixed) {
                right += documentScrollLeft();
                bottom += documentScrollTop();
            }
            if (right <= 0 || bottom <= 0) {
                return false;
            }
        }
    
        // *Probably* visible...
        return true;
    }
    
    function scrollIntoView(element) {
        var overflowScroll = /(auto|scroll)/,
            clientRect,
            scrollParent,
            scrollRect,
            yScrollAmount,
            xScrollAmount,
            diff,
            pbody = getBody();
        if (!isElementVisible(element, overflowScroll)) {
            scrollParent = getScrollParent(element, overflowScroll);
            while (scrollParent && scrollParent !== pbody) {
                clientRect = getClientRect(element);
                scrollRect = getClientRect(scrollParent);
                yScrollAmount = 0;
                xScrollAmount = 0;
    
                if (clientRect.bottom > scrollRect.bottom) {
                    yScrollAmount += clientRect.bottom - scrollRect.bottom;
                    clientRect.top -= yScrollAmount;
                    clientRect.bottom -= yScrollAmount;
                }
                if (clientRect.top < scrollRect.top) {
                    diff = scrollRect.top - clientRect.top;
                    yScrollAmount -= diff;
                    clientRect.top += diff;
                    clientRect.bottom += diff;
                }
    
                if (clientRect.right > scrollRect.right) {
                    xScrollAmount += clientRect.right - scrollRect.right;
                    clientRect.left -= xScrollAmount;
                    clientRect.right -= xScrollAmount;
                }
                if (clientRect.left < scrollRect.left) {
                    diff = scrollRect.left - clientRect.left;
                    xScrollAmount -= diff;
                    clientRect.left += diff;
                    clientRect.right += diff;
                }
    
                scrollParent.scrollTop += yScrollAmount;
                scrollParent.scrollLeft += xScrollAmount;
    
                scrollParent = getScrollParent(scrollParent, overflowScroll);
            }
        }
    }
    
    function evalScript(script) {
        var tempScript = document.createElement('script');
        var head = document.head || document.getElementsByTagName('head')[0] || document.body;
        tempScript.type = 'text/javascript';
        if (script.src) {
            tempScript.src = script.src;
        } else {
            tempScript.text = script.text || script.textContent || script.innerHTML || '';
        }
        head.appendChild(tempScript);
        head.removeChild(tempScript);
    }
    
    /**
     * Sort of like a diet, caffeine-free jQuery
     */
    function dom(selection, context) {
        var self = this,
            nodes,
            tag;
    
        if (selection && selection instanceof dom) {
            return selection;
        }
    
        if (!(self instanceof dom)) {
            return new dom(selection, context);
        }
    
        if (!selection) {
            nodes = [];
        } else if (selection.nodeType) {
            nodes = [selection];
        } else if ((tag = /^<(\w+)\/?>$/.exec(selection))) {
            nodes = [document.createElement(tag[1])];
        } else if (/^<[\w\W]+>$/.test(selection)) {
            var container = document.createElement('div');
            container.innerHTML = selection;
            nodes = _.toArray(container.childNodes);
        } else if (_.isString(selection)) {
            if (context instanceof dom) { context = context.length > 0 ? context[0] : null; }
    
            // CSS selector
    
            nodes = Sizzle(selection, context);
        } else {
            // handle case where selection is not sizzle-able (window, numbers, etc.)
            nodes = [selection];
        }
    
        _.each(nodes, function(node, i) {
            self[i] = node;
        });
    
        self.context = context;
        self.length = nodes.length;
    
        return self;
    }
    
    _.extend(dom.prototype, {
    
        'findOrCreate': function(html) {
            if (this.length > 0) return this;
            return dom(html);
        },
    
        'find': function(selector) {
            var newDom = dom();
            newDom.context = this.context;
            this.each(function() {
                dom(selector, this).each(function() {
                    newDom[newDom.length++] = this;
                });
            });
            return newDom;
        },
    
        'each': function(callback) {
            var self = this;
            for (var i = 0, ii = self.length; i < ii; ++i) {
                callback.call(self[i], self[i], i);
            }
            return self;
        },
    
        'html': function(content) {
            if (content === undefined) {
                return this.length ? this[0].innerHTML : this;
            } else {
                return this.each(function() {
                    this.innerHTML = content;
                });
            }
        },
    
        'text': function(content) {
            var useInnerText = 'innerText' in document.body;
    
            if (content === undefined) {
                if (useInnerText) {
                    return this.length ? this[0].innerText : this;
                } else {
                    return this.length ? this[0].textContent : this;
                }
            }
    
            return this.each(function() {
                setStyle(this, { 'white-space': 'pre-wrap' });
                if (useInnerText) {
                    this.innerText = content;
                    return;
                }
    
                this.textContent = content;
            });
        },
    
        'addClass': function(classNames) {
            classNames = classNames.split(/\s+/);
            return this.each(function(elem) {
                _.each(classNames, function(className) {
                    _addClass(elem, className);
                });
            });
        },
    
        'removeClass': function(classNames) {
            classNames = classNames.split(/\s+/);
            return this.each(function(elem) {
                _.each(classNames, function(className) {
                    _removeClass(elem, className);
                });
            });
        },
    
        'hasClass': function(classNames) {
            classNames = classNames.split(/\s+/);
            var allElemsHaveClass = true;
            if (this.length === 0) return false;
            this.each(function(elem) {
                _.each(classNames, function(className) {
                    allElemsHaveClass = allElemsHaveClass && _hasClass(elem, className);
                });
            });
            return allElemsHaveClass;
        },
    
        'toggleClass': function(classNames) {
            classNames = classNames.split(/\s+/);
            return this.each(function(elem) {
                _.each(classNames, function(className) {
                    if (_hasClass(elem, className)) {
                        _removeClass(elem, className);
                    } else {
                        _addClass(elem, className);
                    }
                });
            });
        },
    
        'css': function(styles) {
            this.each(function() {
                setStyle(this, styles);
            });
    
            return this;
        },
    
        'appendTo': function(selector) {
            dom(selector).append(this);
            return this;
        },
    
        'append': function(selector) {
            var self = this;
            dom(selector).each(function() {
                if (self.length) {
                    self[0].appendChild(this);
                }
    
                // Execute scripts (if any) when the fragment enters the document
                if (isInDocument(this)) {
                    _.each(Sizzle('script', this), evalScript);
                }
            });
            return self;
        },
    
        'prependTo': function(selector) {
            dom(selector).prepend(this);
            return this;
        },
    
        'prepend': function(selector) {
            var self = this;
            if (self.length) {
                var target = self[0],
                    firstChild = target.childNodes[0];
                dom(selector).each(function() {
                    if (firstChild) {
                        dom(this).insertBefore(firstChild);
                    } else {
                        dom(this).appendTo(target);
                    }
                });
            }
            return self;
        },
    
        'getParent': function() {
            var target = dom(this)[0];
            if (target && target.parentNode) {
                return dom(target.parentNode);
            }
        },
    
        'insertBefore': function(selector) {
            var target = dom(selector)[0];
            if (target && target.parentNode) {
                target.parentNode.insertBefore(this[0], target);
    
                // Execute scripts (if any) when the fragment enters the document
                if (isInDocument(document, this)) {
                    _.each(Sizzle('script', this), evalScript);
                }
            }
        },
    
        'remove': function() {
            this.each(function() {
                if (this.parentNode) {
                    this.parentNode.removeChild(this);
                }
            });
            return this;
        },
    
        'attr': function(attrName, attrValue) {
            if (attrValue === undefined) {
                if (this.length > 0) {
                    return this[0].getAttribute(attrName);
                }
            } else {
                this.each(function() {
                    this.setAttribute(attrName, attrValue);
                });
    
                return this;
            }
        },
    
        'on': function(eventNames, selector, fn, useCapture) {
            if (_.isFunction(selector)) {
                useCapture = fn;
                fn = selector;
                selector = null;
            }
            var fnWrapper = function(e) {
                if (pendo.doesExist(selector)) {
                    if (pendo.dom(getTarget(e)).closest(selector).length > 0) {
                        fn.apply(this, arguments);
                    }
                } else {
                    fn.apply(this, arguments);
                }
            };
            eventNames = eventNames.split(' ');
            this.each(function(elem) {
                _.each(eventNames, function(evtName) {
                    attachEvent(elem, evtName, fnWrapper, useCapture);
                });
            });
    
            return this;
        },
    
        'closest': function(selector) {
            var elem = this[0];
            while (elem && !Sizzle.matchesSelector(elem, selector)) {
                elem = elem.parentNode;
                if (elem === document) {
                    return dom();
                }
            }
            return dom(elem);
        },
    
        'eq': function(index) {
            return dom(this[index]);
        },
    
        'height': function(height) {
            if (this.length) {
                if (height === undefined) {
                    return this[0].offsetHeight;
                } else {
                    this[0].style.height = height + 'px';
                    return this;
                }
            }
        },
    
        'width': function(width) {
            if (this.length) {
                if (width === undefined) {
                    return this[0].offsetWidth;
                } else {
                    this[0].style.width = width + 'px';
                    return this;
                }
            }
        },
    
        'focus': function() {
            return this.each(function() {
                if (_.isFunction(this.focus)) {
                    this.focus();
                }
            });
        }
    
    });
    
    _.extend(dom, {
        'removeNode':       removeNode,
        'getClass':         _getClass,
        'hasClass':         _hasClass,
        'addClass':         addClass,
        'removeClass':      removeClass,
        'getBody':          getBody,
        'getComputedStyle': getComputedStyle_safe,
        'getClientRect':    getClientRect,
        'intersectRect':    intersectRect,
        'getScrollParent':  getScrollParent,
        'isElementVisible': isElementVisible,
        'scrollIntoView':   scrollIntoView
    });
    
    
    //
    // Identity Event Code
    //
    
    function isStringWhiteSpace(str) {
        return str && typeof str === 'string' && trim.call(str).length === 0;
    }
    
    var isValidVisitor = function(vId) {
        return pendo.doesExist(vId) && vId !== '' && typeof vId !== 'boolean' && typeof vId !== 'object' && !isStringWhiteSpace(vId);
    };
    
    var isAnonymousVisitor = function(vId) {
        if (!vId || typeof vId === 'number') return false;
    
        return vId.substring(0,pendo.TEMP_PREFIX.length) === pendo.TEMP_PREFIX;
    };
    
    var shouldPersist = function() {
        var options = originalOptions || window.pendo_options || {};
        return !(getPendoConfigValue('disablePersistence') || options.disablePersistence);
    };
    
    var removeIdentificationCookies = function(apiKey) {
        apiKey = apiKey || pendo.apiKey;
    
        document.cookie = '_pendo_visitorId.' + apiKey + '=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
        document.cookie = '_pendo_accountId.' + apiKey + '=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
    
        agentStorage.clear('visitorId');
        agentStorage.clear('accountId');
    };
    
    var DEFAULT_VISITOR_ID = 'VISITOR-UNIQUE-ID';
    var isDefaultVisitor = function(vId) {
        return DEFAULT_VISITOR_ID === vId;
    };
    
    var SUBACCOUNT_DELIMITER = '::';
    var isSubaccount = function(aId) {
        return new RegExp(SUBACCOUNT_DELIMITER).test(aId);
    };
    
    var shouldIdentityChange = function(old_vId, visitor_id) {
        if (!isAnonymousVisitor(old_vId)) {
            pendo.log('Not change an old, non-anonymous visitor id: ' + old_vId);
            return false;
        }
    
        if (!isValidVisitor(visitor_id)) {
            pendo.log('Not valid visitor id: ' + visitor_id);
            return false;
        }
    
        if (isAnonymousVisitor(visitor_id)) {
            pendo.log('visitor is anonymous: ' + visitor_id);
            return false;
        }
    
        if (isDefaultVisitor(visitor_id)) {
            pendo.log('visitor id is the default: ' + visitor_id);
            return false;
        }
    
        pendo.log('Re-mapping identity from ' + old_vId + ' to ' + visitor_id);
    
        return true;
    };
    
    /*
     * NOTE:
     *
     * Identity actaully means re-map all data from the old
     * visitor id and apply it all to the new visitor id.
     *
     *
     * identify(visitor_id [, account_id ])
     * or
     * identify(obj) where obj contains visitor and account sub objects
     * w/ ids in both.
     *
    **/
    pendo.identify = makeSafe(function(visitor_id, account_id) {
        var includesOptions = (typeof visitor_id === 'object');
        var options = null;
    
        var props = {};
        props.old_visitor_id = pendo.get_visitor_id();
    
        if (includesOptions) {
            options = visitor_id;
    
            options.visitor = options.visitor || {};
            options.account = options.account || {};
            options.parentAccount = options.parentAccount || {};
    
            visitor_id = options.visitor.id;
            account_id = options.account.id;
    
            if (account_id && !isSubaccount(account_id) && options.parentAccount.id) {
                account_id = '' + options.parentAccount.id + SUBACCOUNT_DELIMITER + account_id;
            }
            updateOptions(options);
        }
    
        if (!isValidVisitor(visitor_id)) {
            pendo.log('Invalid visitor id ' + visitor_id);
            return;
        }
    
        pendo.set_visitor_id(visitor_id);
    
        if (pendo.doesExist(account_id)) {
            pendo.set_account_id(account_id);
        } else {
            account_id = pendo.get_account_id();
        }
    
        if (shouldIdentityChange(props.old_visitor_id, visitor_id)) {
    
            if(shouldInitializeFeedback(visitor_id)) {
                var feedbackSettings = getPendoConfigValue('feedbackSettings');
                var copyOfOptionsForFeedback = JSON.parse(JSON.stringify(options));
                pendo.feedback.init(copyOfOptionsForFeedback, feedbackSettings);
            }
    
            props.visitor_id = visitor_id;
            props.account_id = account_id;
    
            collectEvent('identify', props);
    
            flushLater(); // unconditionally on next tick
        }
    
        if (props.old_visitor_id !== visitor_id) {
            queueGuideReload();
        }
    });
    
    pendo.get_visitor_id = function() {
        var vId = pendo.visitorId,
            v;
    
        if (!pendo.doesExist(vId) || !isValidVisitor(vId)) {
            if (shouldPersist()) {
                v = agentStorage.read('visitorId');
                if(!isValidVisitor(v)) {
                    v = pendo.generate_unique_id(pendo.TEMP_PREFIX);
                    agentStorage.write('visitorId', v);
                }
            } else {
                v = pendo.generate_unique_id(pendo.TEMP_PREFIX);
            }
            pendo.visitorId = v;
        }
        return pendo.visitorId;
    };
    
    pendo.set_visitor_id = function(new_visitor_id) {
        pendo.visitorId = '' + new_visitor_id;
        if (shouldPersist()) {
            agentStorage.write('visitorId', pendo.visitorId, pendo.DEFAULT_EXPIRE_LEN, false, true);
        }
    };
    
    pendo.get_account_id = function() {
        if(!pendo.doesExist(pendo.accountId) && shouldPersist()) {
            var aid = agentStorage.read('accountId');
            pendo.accountId = aid;
        }
        return pendo.accountId;
    };
    
    pendo.set_account_id = function(new_account_id) {
        pendo.accountId = '' + new_account_id;
        if (shouldPersist()) {
            agentStorage.write('accountId', pendo.accountId, null, false, true);
        }
    };
    
    var inMemoryCookies = {};
    var cookieDomain;
    
    /**
     * This config setting means persistence is ok as long as it's LocalStorage or
     * anything non cookie based.
     */
    var allowLocalStorageOnly = function() {
        return ConfigReader.get('localStorageOnly');
    };
    
    /**
     * This config setting really describes any persistence at all.
     */
    var storageIsDisabled = function() {
        var jwtOptions = getJwtInfoCopy();
        return ConfigReader.get('disableCookies') || (!!jwtOptions.jwt && !!jwtOptions.signingKeyName);
    };
    
    var getCookie = function(name) {
        var toParse;
        if (storageIsDisabled() || allowLocalStorageOnly()) {
            toParse = inMemoryCookies[name];
        } else {
            toParse = document.cookie;
        }
        var result;
        return (result = new RegExp('(^|; )' + name + '=([^;]*)').exec(toParse)) ? decodeURIComponent(result[2]) : null;
    };
    
    var setCookie = function(name, val, millisToExpire, isSecure) {
        if (isInPreviewMode()) return;
        var expireDate = new Date();
        expireDate.setTime(expireDate.getTime() + millisToExpire);
        var cookie = name + '=' + encodeURIComponent(val) + (millisToExpire ? ';expires=' + expireDate.toUTCString() : '') + '; path=/' + (document.location.protocol === 'https:' || isSecure ? ';secure' : '') + '; SameSite=Strict';
        if (cookieDomain) {
            cookie += ';domain=' + cookieDomain;
        }
        if (storageIsDisabled() || allowLocalStorageOnly()) {
            inMemoryCookies[name] = cookie;
        } else {
            document.cookie = cookie;
        }
    };
    
    function setCookieDomain(newCookieDomain, locationHost) {
        if (!newCookieDomain) {
            cookieDomain = newCookieDomain;
            return;
        }
    
        if (!_.isString(newCookieDomain)) {
            return;
        }
    
        locationHost = locationHost.replace(/:\d+$/, '');
    
        newCookieDomain = newCookieDomain.replace(/^\./, '');
        var subDomainMatchRegex = new RegExp('\\.' + newCookieDomain.replace(/\./g, '\\.') + '$');
        var domainMatchRegex = new RegExp('^' + newCookieDomain.replace(/\./g, '\\.') + '$');
        if (subDomainMatchRegex.test(locationHost) || domainMatchRegex.test(locationHost)) {
            cookieDomain = '.' + newCookieDomain;
        }
    }
    
    var getPendoCookieKey = function(name) {
        return '_pendo_' + name + '.' + pendo.apiKey;
    };
    
    pendo.get_pendo_cookie = function(name) {
        return getCookie(getPendoCookieKey(name));
    };
    
    // 100 days
    pendo.DEFAULT_EXPIRE_LEN = 100 * 24 * 60 * 60 * 1000;
    
    pendo.set_pendo_cookie = function(name, val, millisToExpire, isSecure) {
        millisToExpire = millisToExpire || pendo.DEFAULT_EXPIRE_LEN;
        setCookie(getPendoCookieKey(name), val, millisToExpire, isSecure);
    };
    
    /*
     * Moving core storage API into `agentStorage` to hopefully make the abstraction
     * around where / how the storage happens in the browser clear and consistent
     * moving forward with new Agent refactoring and modularizing the code base.
     */
    
     /*
        The majority of prior existing functionality still remains where it was. The
        core Storage api is now in `agentStorage` with the original references still in place.
     */
    
    var agentStorage = (function() {
        function canUseLocalStorage() {
            if (storageIsDisabled()) return false;
            if (hasCookieDomain()) return false;
            return storageAvailable('localStorage');
        }
    
        function hasCookieDomain() {
            return !!cookieDomain;
        }
    
        // "Borrowed" from https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API/Using_the_Web_Storage_API
        // for continued reading: https://gist.github.com/paulirish/5558557
    
        // NOTE: gonna run this again before and after any writes
        var storageAvailable = _.memoize(function(type) {
            var storage;
            try {
                storage = window[type];
                var x = '__storage_test__';
                storage.setItem(x, x);
                storage.removeItem(x);
                return true;
            }
            catch(e) {
                return e instanceof DOMException && (
                    // everything except Firefox
                    e.code === 22 ||
                    // Firefox
                    e.code === 1014 ||
                    // test name field too, because code might not be present
                    // everything except Firefox
                    e.name === 'QuotaExceededError' ||
                    // Firefox
                    e.name === 'NS_ERROR_DOM_QUOTA_REACHED') &&
                    // acknowledge QuotaExceededError only if there's something already stored
                    (storage && storage.length !== 0);
            }
        });
    
        function resetCache(mFn) {
            if (mFn.cache) {
                mFn.cache = {};
            }
        }
    
        // Will always return a string or null
        function read(name, isPlain) {
            if (canUseLocalStorage()) {
                var key = !isPlain ? getPendoCookieKey(name) : name;
                var val = ttlApply(localStorage.getItem(key));
                if (val === null) {
                    clear(name);
                }
    
                return val;
            }
    
            if (!isPlain) {
                return pendo.get_pendo_cookie(name);
            } else {
                return getCookie(name);
            }
        }
    
        function ttlApply(value) {
            if (value === null) return null;
    
            try {
                // JSON parsables: Numbers, Booleans, and Objects
                var obj = JSON.parse(value);
                if (obj.ttl && obj.ttl < new Date().getTime()) {
                    return null;
                }
                return String(obj.value || obj);
            } catch (e) {
                // Strings
                return value;
            }
        }
    
        // consider assert type of val (what do we support? string, number, boolean? )
        function write(name, val, duration, isPlain, isSecure) {
            resetCache(storageAvailable);
            if (canUseLocalStorage()) {
    
                /*
                * We'll try to write but if that fails, just fall down to cookies.
                */
                try {
                    var key = !isPlain ? getPendoCookieKey(name) : name;
                    localStorage.setItem(key, ttlWrite(val, duration));
                    resetCache(storageAvailable);
                    return;
                } catch (e) {
                    log('Error trying to write to Localstorage: ' + e);
                }
            }
    
            if (!isPlain) {
                return pendo.set_pendo_cookie(name, val, duration, isSecure);
            } else {
                setCookie(name, val, duration, isSecure);
            }
        }
    
        function ttlWrite(value, duration) {
            if (!duration) {
                return value;
            }
    
            var ttl = new Date().getTime() + duration;
            return JSON.stringify({
                'ttl':   ttl,
                'value': value
            });
        }
    
        function clear(name, isPlain) {
            var key = !isPlain ? getPendoCookieKey(name) : name;
    
            if (canUseLocalStorage()) {
                return localStorage.removeItem(key);
            }
    
            document.cookie = key + '=; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
        }
    
        return { /* API */
            'read':  read,
            'write': write,
            'clear': clear
        };
    })();
    
    /* originally from here github.com/toddmotto/atomic, then heavily modified */
    (function(root, factory) {
        root.ajax = factory();
    })(pendo, function() {
    function createResult(requestObject) {
            var result = {
                'status': requestObject.status
            };
            try {
                result.data = JSON.parse(requestObject.responseText);
            } catch (e) {
                result.data = requestObject.responseText;
            }
            return result;
        }
    
        function ajax(config) {
            var deferred = q.defer();
            /*global ActiveXObject*/
            var XHR = window.XMLHttpRequest || ActiveXObject;
            var request = new XHR('MSXML2.XMLHTTP.3.0');
    
            request.open(config.method || 'GET', config.url, !config.sync);
    
            _.each(config.headers, function(headerValue, header) {
                request.setRequestHeader(header.toLowerCase(), headerValue);
            });
    
            request.onreadystatechange = function() {
                if (request.readyState === 4) {
                    var result = createResult(request);
    
                    if (request.status >= 200 && request.status < 300) {
                        deferred.resolve(result);
                    } else {
                        deferred.reject(result);
                    }
                }
            };
    
            if (config.withCredentials) {
                request.withCredentials = true;
            }
    
            if (config.data) {
                request.send(config.data);
            } else {
                request.send();
            }
    
            return deferred.promise;
        }
    
        function get(url, headers) {
            return ajax({
                'method':  'GET',
                'url':     url,
                'headers': headers
            });
        }
    
        function post(url, data, headers) {
            return ajax({
                'method':  'POST',
                'url':     url,
                'data':    data,
                'headers': headers
            });
        }
    
        function postJSON(url, data, headers) {
            if (!headers) {
                headers = {};
            }
            headers['content-type'] = 'application/json';
            data = JSON.stringify(data);
            return post(url, data, headers);
        }
    
        /**
         * Convert {params} into a valid query-string and correctly append to
         * {base}, respecting existing params and hash fragments. Does NOT handle
         * non-scalar values or nested properties.
         *
         * @param {string} base URL
         * @param {object || array} params to encode in the query string
         * @return {string} URL with optional query string {params}
         */
        function urlFor(base, params) {
            var list;
    
            if (_.isArray(params)) {
                list = params;
            } else if (_.isObject(params)) {
                list = _.keys(params);
            } else {
                return base ? base : '';
            }
            
            var qs = _.map(list, function(key) {
                if (_.isArray(params)) {
                    return encodeURIComponent(key);
                }
                return encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
            }).join('&');
    
            var parts = base.split('#', 2);
    
            var url = parts[0], fragment = parts[1];
    
            return [
                encodeURI(url),
                (qs ?
                    (_.contains(base, '?') ? '&' : '?') + qs
                    : ''
                ),
                (fragment ? '#' + fragment : '')
            ].join('');
        }
    
        return _.extend(ajax, {
            'get':      get,
            'post':     post,
            'postJSON': postJSON,
            'urlFor':   urlFor
        });
    });
    
    
    pendo.SIZE_UNIQUE_ID = 11;
    
    function getPendoCore() {
        var pendoCoreValue = getPendoConfigValue('pendoCore');
        if (typeof pendoCoreValue === 'undefined') {
            return true;
        }
        return pendoCoreValue;
    }
    
    var pendoCore = getPendoCore();
    
    function shouldInitializeFeedback(visitorId) {
        return isFeedbackOn && !isDisableFeedbackAutoInitOn && !isAnonymousVisitor(visitorId);
    }
    
    pendo.generate_unique_id = function(prefix) {
        return prefix + pendo.randomString(pendo.SIZE_UNIQUE_ID);
    };
    
    pendo.TEMP_PREFIX = '_PENDO_T_';
    
    function doesExist(arg) {
        return !(typeof arg === 'undefined' || arg === null);
    }
    
    pendo.doesExist = doesExist;
    
    // ---------------------------------------------------------------------------
    
    var pageLoad = makeSafe(function(url) {
        url = url || pendo.url.get();
    
        // Only send load event if the URL has changed
        if (url && url !== pageLoad.lastUrl) {
            pageLoad.lastUrl = url;
            var loadTime = -1;
    
            announceAgentLoaded();
    
            debug('sending load event for url ' + url);
    
            if (typeof performance !== 'undefined' && typeof performance.timing !== 'undefined') {
                loadTime = performance.timing.loadEventStart - performance.timing.fetchStart;
            }
    
            collectEvent('load', { 'load_time': loadTime }, url);
    
            queueGuideReload(url);
    
            flushLater(); // on the next tick, unconditionally
        }
    });
    
    function shouldReloadGuides(url, visitorId) {
        if (!url || !pendo.apiKey) return false;
    
        if (areGuidesDisabled() && !(pendoLocalStorage.getItem('pendo-designer-mode') === 'true')) return false;
    
        return (url !== reloadGuides.lastUrl ||
            visitorId !== reloadGuides.lastVisitorId);
    }
    
    function reloadGuides(url) {
        var visitorId = pendo.get_visitor_id();
    
        url = url || pendo.url.get();
    
        if (!shouldReloadGuides(url, visitorId)) return;
    
        reloadGuides.lastUrl = url;
    
        reloadGuides.lastVisitorId = visitorId;
    
        pendo.loadGuides(pendo.apiKey, visitorId, url);
    }
    
    var queueGuideReload = function(url) {
        if(!pendoCore) return;
        if (queueGuideReload.pending) {
            clearTimeout(queueGuideReload.pending);
        }
        queueGuideReload.pending = setTimeout(function() {
            delete queueGuideReload.pending;
            reloadGuides(url);
        }, 0);
    };
    
    function forceGuideReload() {
        reloadGuides.lastUrl = null;
        queueGuideReload();
    }
    
    function getApiKey(options) {
        var apiKeyFromPendoConfig = getPendoConfigValue('apiKey');
    
        if (apiKeyFromPendoConfig) {
            return apiKeyFromPendoConfig;
        } else if (options.apiKey) {
            return options.apiKey;
        }
    }
    
    function getAdditionalApiKeys(options) {
        var additionalApiKeysFromPendoConfig = getPendoConfigValue('additionalApiKeys');
        var additionalApiKeys;
    
        if (additionalApiKeysFromPendoConfig) {
            additionalApiKeys = additionalApiKeysFromPendoConfig;
        } else if (options.additionalApiKeys) {
            additionalApiKeys = options.additionalApiKeys;
        } else {
            additionalApiKeys = [];
        }
    
        if (additionalApiKeys && !_.isArray(additionalApiKeys)) {
            additionalApiKeys = [additionalApiKeys];
        }
    
        return additionalApiKeys;
    }
    
    function registerEventHandlers(options) {
        _.each(options.events, function(callback, eventName) {
            if (pendo.events[eventName]) {
                pendo.events[eventName](callback);
            }
        });
    }
    
    function launchDesignerOrPreview(options) {
        // in order, try to launch:
        // 1) designer
        // 2) preview
        _.find([
            _.partial(pendo.designerv2.launchOnToken, window.location),
            _.partial(startPreviewMode, window)
        ], function(fn) {
            return fn();
        });
        if(options.enableDesignerKeyboardShortcut || !getPendoConfigValue('disableDesignerKeyboardShortcut')) {
            pendo.P2AutoLaunch.listen();
        }
    }
    
    function localStorageNavigation(options) {
        if (!options.ignoreLocalStorageNavigation) {
            var storedNavigationMode = pendoLocalStorage.getItem('pendo-navigation-state');
            if (storedNavigationMode) {
                try {
                    var message = JSON.parse(storedNavigationMode);
    
                    var launchOptions = {
                        'lookaside': message.baseUrl,
                        'preloader': true,
                        'host':      message.host
                    };
                    pendo.designerv2.launchInAppDesigner(launchOptions);
                } catch (err) {
                    // gracefully catch nav parse errors
                }
            }
        }
    }
    
    // ----------------------------------------------------------------------------------
    
    var initializeCounter = 0;
    var originalOptions = null;
    var isFeedbackOn = getPendoConfigValue('pendoFeedback');
    var isDisableFeedbackAutoInitOn = getPendoConfigValue('disableFeedbackAutoInit');
    
    var initialize = makeSafe(function(options) {
        if (document.readyState !== 'complete') {
            enqueueCall('initialize', arguments);
            return;
        }
    
        if (pendo.apiKey) {
            if (initializeCounter++ === 1) {
                log([
                    'pendo.initialize only needs to be called once',
                    isSfdcLightning() ? ' per namespace' : '',
                    '. Use pendo.updateOptions to update metadata after the agent has initialized.'
                ].join(''));
            }
            return;
        }
    
        if (!options) { options = {}; }
        if(_.isEmpty(getJwtInfoCopy())) {
            var jwtOptions = JWT.getJwtOptions(options, 'initialize');
            if(jwtOptions) {
                setJwtInfo(_.pick(options, 'jwt', 'signingKeyName'));
                return initialize(jwtOptions);
            }
        }
    
        if (_.isString(options)) { // treat as URL
            return pendo.ajax.get(options)
                .then(function(response) {
                    //eslint-disable-next-line no-global-assign
                    return initialize(PendoConfig = response.data);
                });
        }
    
        // Save the options somewhere
        originalOptions = options;
        setUpdatedOptions(options);
        pendo.HOST = HOST = getDataHost();
    
        var cookieDomain = getOption('cookieDomain') || getPendoConfigValue('cookieDomain');
        if (cookieDomain) {
            setCookieDomain(cookieDomain, location.host);
        }
    
        // Primary API key
        pendo.apiKey = getApiKey(options);
    
    
        // Additional API keys
        pendo.additionalApiKeys = getAdditionalApiKeys(options);
    
        if (!pendo.apiKey && pendo.additionalApiKeys && pendo.additionalApiKeys.length) {
            pendo.apiKey = pendo.additionalApiKeys[0];
        }
    
        if (!pendo.apiKey) {
            debug('API key is not set, Pendo will not initialize.');
            return;
        }
    
        // make sure additionalApiKeys are a string
        pendo.apiKey = '' + pendo.apiKey;
        for (var i = 0; i < pendo.additionalApiKeys.length; i++) {
            pendo.additionalApiKeys[i] = '' + pendo.additionalApiKeys[i];
        }
    
        TextCapture.initialize();
    
        if (options.logStackTraces) {
            pendo.logStackTraces = options.logStackTraces;
        }
    
        if(pendoCore) {
            // Disable content pre-fetch for guide center
            pendo.disableGuideCenterContentSearch = options.disableGuideCenterContentSearch;
    
            // Register handlers passed through pendo_options
    
            registerEventHandlers(options);
    
            listenToMaster();
    
            initGuides(); // this is safe.  loadGuides actually does the loading.
    
            wirePage();
    
            startDebuggingModuleIfEnabled();
    
            launchDesignerOrPreview(options);
        }
    
        // Remove existing visitor and account identification cookies if
        // disablePersistence is set to true via administration UI or snippet
        if (!shouldPersist()) {
            removeIdentificationCookies();
        }
    
        //
        // Flag to indicate that the app is expecting to load data async
        // and will programmatically update information at a later point
        //
        if (options.usePendoAgentAPI !== true) {
            pendo.updateOptions(options);
        }
    
        if (options.visitorId && options.visitorId != DEFAULT_VISITOR_ID) {
            pendo.identify(options.visitorId);
        } else if (options.visitor && options.visitor.id && options.visitor.id != DEFAULT_VISITOR_ID) {
            var accountId = null;
            if (options.account && options.account.id) {
                accountId = options.account.id;
            }
            pendo.identify(options.visitor.id, accountId);
        }
    
        pendo.url.watch(pendo.pageLoad);
        pageLoad(pendo.url.get());
    
        localStorageNavigation(options);
    
        if(pendoCore) {
            pendo.events.ready();
        }
    
        var visitorIdFeedback = pendo.get_visitor_id();
    
        if(shouldInitializeFeedback(visitorIdFeedback)) {
            var feedbackSettings = getPendoConfigValue('feedbackSettings');
            pendo.feedback.init(getOptionsCopy(), feedbackSettings);
        }
        initializeCounter++;
    });
    
    // @return {ayepromise.Promise|undefined}
    function flushCallQueue() {
        if (!_.isArray(pendo._q) || _.isEmpty(pendo._q)) return;
    
        /**
         * Prepends and appends to {pendo._q} could occur during iteration if
         * {pendo.apiKey} is still not set, so flush it for processing.
         */
        var flushed = pendo._q.splice(0, pendo._q.length);
    
        var promise = _.reduce(flushed, function(promise, args) {
            if (!_.isArray(args)) return promise;
    
            var method = pendo[args.shift()];
    
            if (!_.isFunction(method)) return promise;
    
            // chain {method} onto {promise} to serialize execution
            return promise.then(function() {
                // if {method} returns {ayepromise.Promise} chain that too
                return method.apply(pendo, args);
            });
        }, q.resolve());
    
        // in case {pendo._q} has grown
        return promise.then(flushCallQueue);
    }
    
    var isReady = function() {
        return pendo.doesExist(pendo.apiKey);
    };
    
    var getOption = function(key, defaultValue) {
        return get(originalOptions, key, defaultValue);
    };
    
    var updatedOptions = null;
    
    var setUpdatedOptions = function(options) {
        updatedOptions = JSON.parse(JSON.stringify(options || {})); // underscore doesn't have deep clone
    };
    
    var getOptionsCopy = function() {
        return JSON.parse(JSON.stringify(updatedOptions || originalOptions || {})); // underscore doesn't have deep clone
    };
    
    var jwtInfo = null;
    var setJwtInfo = function(originalJwtInfo) {
        jwtInfo = JSON.parse(JSON.stringify(originalJwtInfo || {}));
    };
    
    var getJwtInfoCopy = function() {
        return ((jwtInfo !== null) ? jwtInfo : {});
    };
    
    /*eslint-disable no-console*/
    pendo.validateInstall = function validateInstall() {
        if (typeof console === 'undefined' || !console.group) {
            return 'Please run this test in the latest version of Chrome, Firefox, Safari, or Internet Explorer';
        }
        console.group('Pendo Install Validation');
        if (!pendo.apiKey) {
            console.error('No Pendo API key configured.');
        }
        var visitorId = pendo.get_visitor_id();
        if (isAnonymousVisitor(visitorId)) {
            console.warn('The current visitor is not identified and will be treated as "anonymous". Is this expected? (You might have used "VISITOR-UNIQUE-ID" as the visitor ID)');
        }
        if (isDefaultVisitor(visitorId)) {
            console.error('The current visitor ID matches the example visitor ID from the Pendo installation instructions.');
        }
        var accountId = pendo.get_account_id();
        if (!accountId) {
            console.warn('The current visitor is not associated with an account. Is this expected?');
        }
        if (accountId === 'ACCOUNT-UNIQUE-ID') {
            console.error('The current account ID matches the example account ID from the Pendo installation instructions.');
        }
        if (isFeedbackOn && Feedback.isUnsupportedIE()) {
            console.warn('The current version of IE is not supported by Pendo Feedback');
        }
        var metadata = getMetadata();
        _.each(['visitor', 'account', 'parentAccount'], function(kind) {
            var metadataForKind = metadata && metadata[kind];
            var keys = _.chain(metadataForKind).keys().value();
            if (keys.length > 0) {
                console.group(kind + ' metadata (does this look right?):');
                _.each(metadataForKind, function(value, key) {
                    if (_.isObject(value) && !_.isArray(value)) {
                        console.warn(key + ' is an object and will be ignored.', value);
                    } else if (_.isArray(value) && _.any(value, _.isObject)) {
                        console.warn(key + ' contains object values. The objects will be ignored.', value);
                    } else {
                        console.log(key + ':', value);
                    }
                });
                console.groupEnd();
            } else if (kind !== 'parentAccount') {
                console.warn('No ' + kind + ' metadata found. Learn more about metadata here: http://help.pendo.io/resources/support-library/installation/metadata.html');
            }
        });
    
        console.groupEnd();
    };
    
    pendo.validateNativeMethods = function() {
        var nativeTypes = [{
            'nativeType':  Object.prototype,
            'displayName': 'Object  '
        }, {
            'nativeType':  Number.prototype,
            'displayName': 'Number  '
        }, {
            'nativeType':  String.prototype,
            'displayName': 'String  '
        }, {
            'nativeType':  Function.prototype,
            'displayName': 'Function'
        }, {
            'nativeType':  Boolean.prototype,
            'displayName': 'Boolean '
        }, {
            'nativeType':  Array.prototype,
            'displayName': 'Array   '
        }, {
            'nativeType':  Date.prototype,
            'displayName': 'Date    '
        }, {
            'nativeType':  RegExp.prototype,
            'displayName': 'RegExp  '
        }, {
            'nativeType':   JSON,
            'displayName':  'JSON    ',
            'propsToCheck': ['parse', 'stringify']
        }, {
            'nativeType':  Math,
            'displayName': 'Math    '
        }, {
            'nativeType':  Promise.prototype,
            'displayName': 'Promise '
        }, {
            'nativeType':   window,
            'displayName':  'Window ',
            'propsToCheck': [
                'alert',
                'asap',
                'atob',
                'btoa',
                'cancelAnimationFrame',
                'clearImmediate',
                'clearInterval',
                'clearTimeout',
                'close',
                'confirm',
                'getComputedStyle',
                'getSelection',
                'open',
                'postMessage',
                'prompt',
                'requestAnimationFrame',
                'scroll',
                'scrollBy',
                'scrollTo',
                'setImmediate',
                'setInterval',
                'setTimeout',
                'stop',
                'XMLHttpRequest',
                'decodeURI',
                'decodeURIComponent',
                'encodeURI',
                'encodeURIComponent'
            ]
        }];
    
        var hasNonNativeMethods;
    
        _.each(nativeTypes, function(obj) {
            var nativeType = obj.nativeType;
    
            var nonNativeImplementations = [];
    
            var keys = obj.propsToCheck || Object.getOwnPropertyNames(nativeType);
    
            _.each(keys, function(propName) {
                try {
                    if(propName && nativeType[propName] && typeof nativeType[propName] === 'function') {
                        var isNativeImplementation = nativeType[propName].toString().includes('[native code]');
                        if(!isNativeImplementation) nonNativeImplementations.push(propName);
                    }
                } catch(e) {
                    // avoid strict mode accessor errors
                }
            });
    
            if(nonNativeImplementations.length) {
                obj.nonNativeImplementations = nonNativeImplementations;
                hasNonNativeMethods = true;
            }
        });
    
        console.group('Native javascript method check:');
        if(!hasNonNativeMethods) {
            console.log('Environment uses native javascript implementations');
            return console.groupEnd();
        }
    
        console.warn('Pendo has detected that your application may be changing native javascript functionality. We suggest consulting an engineer or your CSM to better understand if these changes will negatively impact Pendo\'s ability to function properly');
    
        _.each(nativeTypes, function(obj) {
            if(!obj.nonNativeImplementations) return;
    
            var nativeTypeName = obj.displayName;
            console.warn(nativeTypeName + ' | Contains the following non-native implementations:', obj.nonNativeImplementations.sort().join(', '));
        });
        console.groupEnd();
    };
    /*eslint-enable no-console*/
    
    pendo.validateEnvironment = function() {
        pendo.validateInstall();
        pendo.validateNativeMethods();
        ConfigReader.validate(console);
    };
    
    function getDataHost() {
        var dataHost = getPendoConfigValue('dataHost');
        if (dataHost) {
            return 'https://' + dataHost;
        }
        return getOption('dataHost', 'https://app.pendo.io');
    }
    
    var HOST = getDataHost();
    
    var buildBaseDataUrl = function(target, apiKey, qsMap) {
        if (getPendoConfigValue('blockLogRemoteAddress')) {
            qsMap.log = 0;
        }
    
        var template = HOST + '/data/' + target + '/' + apiKey;
        var qsArray = _.map(qsMap, function(val, key) {
            return key + '=' + val;
        });
        if (qsArray.length > 0) {
            template += '?' + qsArray.join('&');
        }
    
        return template;
    };
    
    /**
     * Only used for the ptm endpoint for now, all others should only
     * use pendo.apiKey
     */
    function getAllApiKeys() {
        return _.compact([pendo.apiKey].concat(pendo.additionalApiKeys));
    }
    
    /**
     * @param {string} jzb
     * @param {string} beaconName
     * @return {ayepromise.Promise} via {writeBeacon}
     */
    function writeEvent(jzb, beaconName) {
        var now = new Date().getTime();
    
        return writeBeacon(beaconName, {
            'v':   VERSION,
            'ct':  now,
            'jzb': jzb
        });
    }
    
    var writeGuideEvent = function(evt) {
        var now = new Date().getTime();
        var evtStr = pendo.squeezeAndCompress([ evt ]);
    
        writeBeacon('guide', {
            'ct':  now,
            'jzb': evtStr,
            'v':   VERSION
        });
    };
    
    var writeMessage = function(msg) {
        msg += 'v' + VERSION;
    
        writeBeacon('log', {
            'msg':     msg,
            'version': VERSION
        });
    };
    
    /**
     * @param {string} beaconName e.g. 'ptm'
     * @param {object} payload to pass to {buildBaseDataUrl}
     * @return {ayepromise.Promise}
     */
    function writeBeacon(beaconName, payload) {
        var jwtOptions = getJwtInfoCopy();
        var url = buildBaseDataUrl(beaconName + '.gif', pendo.apiKey, payload);
    
        if (beaconName !== 'log' && !_.isEmpty(jwtOptions)) {
            var data = JSON.stringify({
                'events':         payload.jzb,
                'jwt':            jwtOptions.jwt,
                'signingKeyName': jwtOptions.signingKeyName
            });
            url = buildBaseDataUrl(beaconName + '.gif', pendo.apiKey, _.omit(payload, 'jzb'));
            pendo.ajax({
                'method':  'POST',
                'url':     url,
                'data':    data,
                'headers': {
                    'Content-Type': 'application/json'
                }
            });
            return;
        }
    
        return writeImgTag(url);
    }
    
    var writeException = function(errorObj, message) {
        if (!errorObj) {
            return;
        }
        if (errorObj && errorObj.logged) { // ignore errors that have already been logged
            return;
        }
        if (!message) {
            message = 'pendo.io unhandled exception';
        }
        try {
            errorObj.logged = true; // Mark the exception as already logged
        } catch (ignore) {
        }
        var msg = '[' + message + ': ' + errorObj.message + ']';
        log(msg);
        var options = window.pendo_options || {};
        if (errorObj.stack && pendo.logStackTraces !== false && options.logStackTraces !== false) {
            writeErrorPOST(msg + '\n' + errorObj.stack);
        } else {
            writeMessage(msg);
        }
    };
    
    /**
     * @param {string} msg to send
     * @return {ayepromise.Promise} via {pendo.ajax.postJSON}
     */
    function writeErrorPOST(msg) {
        try {
            // NOTE: this URL is supposed to be different than all the others
            var url = HOST + '/data/errorlog?apiKey=' + pendo.apiKey;
    
            if (getPendoConfigValue('blockLogRemoteAddress')) {
                url += '&log=0';
            }
    
            var promise = pendo.ajax.postJSON(url, {
                'error':     msg,
                'version':   'v' + VERSION,
                'visitorId': pendo.get_visitor_id()
            });
    
            return promise.then(
                function() { pendo.log('successfully wrote error'); },
                function(err) { pendo.log('error writing error:' + err); }
            );
        } catch (e) {
            log('Failed to write error to server using POST endpoint: ' + e);
    
            return writeMessage('Failed to write error to server using POST endpoint: ' + e);
        }
    }
    
    
    /**
     * @param {string} src to apply to {Image}
     * @return {ayepromise.Promise<undefined>}
     *
     * @resolves {undefined} when {Image.onload} triggers or immediately if not {isUnlocked}
     * @rejects {undefined} when {Image.onerror} triggers
     */
    function writeImgTag(src) {
        if (!isUnlocked()) return q.resolve(); // bail early
        if (isInPreviewMode()) return q.resolve(); // bail early
    
        var deferred = q.defer();
    
        var image = new Image();
    
        image.onload = function() {
            deferred.resolve();
        };
    
        image.onerror = function() {
            deferred.reject();
        };
    
        image.src = src;
    
        return deferred.promise;
    }
    
    function fetchKeepalive(url) {
        fetch(url, {
            'method':    'GET',
            'keepalive': true
        });
    }
    
    fetchKeepalive.supported = function() {
        return _.isFunction(window.fetch) && typeof Request !== 'undefined' && 'keepalive' in new Request('');
    };
    
    function sendBeacon(url, data) {
        navigator.sendBeacon(url, new Blob([JSON.stringify(data)], { 'type': 'text/plain' }));
    }
    
    sendBeacon.supported = function() {
        return typeof Blob !== 'undefined' && _.isFunction(navigator.sendBeacon);
    };
    
    var locked = false;
    var lockEvents = function() {
        locked = true;
        return 'Pendo Agent locked.  No more events will be written.';
    };
    
    var unlockEvents = function() {
        buffersClearAll();
        locked = false;
        return 'Pendo Agent unlocked.  Events will be written.';
    };
    
    var isUnlocked = function() {
        return !locked && pendoCore;
    };
    
    var eventCache = [];
    var trackEventCache = [];
    
    // Send compressed event logs at least every 2 minutes
    var SEND_INTERVAL = 2 * 60 * 1000;
    
    var MAX_NUM_EVENTS = 16;
    var URL_MAX_LENGTH = 2000;
    var ENCODED_EVENT_MAX_LENGTH = 1900;
    var ENCODED_EVENT_MAX_POST_LENGTH = 1 << 16; // 64k is all you need
    
    var limitURLSize = function(size, url) {
        url = url || getURL();
        return url.substring(0, size);
    };
    
    var isURLValid = function(url) {
        return !(!url || url === '');
    };
    
    var getURL = function() {
        return pendo.url.get();
    };
    
    pendo.buffers = {
        /*: events: Event[] */
        /*: silos: Silo[] */
        'flush':                _.noop,
        'flushBy':              _.noop,
        'flushEvents':          flushNow,
        'flushTrackEvents':     flushNow,
        'flushSilos':           flushNow,
        'flushTrackEventSilos': flushNow,
        'flushBeacons':         flushNow,
        'flushNow':             flushNow,
        'flushLater':           flushLater,
        'flushEvery':           flushEvery,
        'flushStop':            flushStop,
        'beacons':              [],
        'silos':                [],
        'trackEventSilos':      []
    };
    
    /**
     * Queue {fn} after {n} ticks of the event loop, while preventing duplicate
     * invocations on the same timing and returning a clearing function that will
     * cancel the delayed invocation.
     *
     * @see {flushLater} and {flushBeacons} for usage
     *
     * @param {Function} callback to delay invocation by {n} ticks
     * @param {number} n ticks
     * @return {Function} to clear the deferred {fn} cached at {fn[n]}
     */
    function callLater(callback, n) {
        n = parseInt(n, 10) || 0;
    
        if (callback[n]) return callback[n];
    
        var timeout = window.setTimeout(function callingLater() {
            callback();
    
            callback[n]();
        }, n);
    
        return (callback[n] = function clearCallLater() {
            window.clearTimeout(timeout);
    
            delete callback[n];
        });
    }
    
    /**
     * @param {boolean} force a "full" flush, i.e. ALL {pendo.buffers.silos}
     * @return {ayepromise.Promise} from {flushBeacons}
     */
    function flushNow(force, options) {
        try {
            eventQueue.flush(options);
            trackEventQueue.flush(options);
        } catch (e) {
            writeException(e, 'unhandled error while flushing event cache');
        }
    }
    
    /**
     * Queue a curried {flushNow} with `force:true` for {n} ticks of the event
     * loop, deferring CPU-intensive compression until the main thread is free.
     */
    function flushLater(n) {
        return callLater(_.partial(flushNow, true), n);
    }
    
    /**
     * Force a full flush, i.e. `flushNow(true)`, on {n} ticks
     *
     * @param {number} n ticks to call {flushNow} on
     * @return {Function} that clears the interval when called
     *
     * @see {autoInitialize} in `src/caboose.js` for usage with {SEND_INTERVAL}
     */
    function flushEvery(n) {
        n = parseInt(n, 10) || 0;
    
        if (!_.isObject(flushEvery.intervals)) flushEvery.intervals = { };
    
        if (flushEvery.intervals[n]) return;
    
        // @see {pendo.flushNow}
        var interval = window.setInterval(flushNow, n);
    
        return (flushEvery.intervals[n] = function() {
            clearInterval(interval);
    
            delete flushEvery.intervals[n];
        });
    }
    
    /**
     * Clear outstanding timeouts or intervals on {flushEvery.intervals},
     * {flushNow}, or {flushBeacons} by invoking their callbacks.
     */
    function flushStop() {
        var toClear = _.values(flushEvery.intervals).concat([flushNow]);
    
        _.map(toClear, function(method) {
            pendo._.isFunction(method) && method();
        });
    }
    
    /**
     * Clear all {pendo.buffers} and timeouts / intervals via {flush} and
     * {flushStop}, mostly for use in testing.
     */
    function buffersClearAll() {
        eventQueue.clear();
        trackEventQueue.clear();
        xhrEventQueue.clear();
    
        flushStop();
    }
    
    var defaultTrackName = '_PENDO_UNNAMED_';
    
    var SILO_AVG_COMPRESSION_RATIO = 5;
    
    var SILO_MAX_BYTES = (
        ENCODED_EVENT_MAX_LENGTH * SILO_AVG_COMPRESSION_RATIO
    );
    
    /**
     * @param {string} type of the event, e.g. `load`, `click`, `focus`
     * @param {object} props differ depending on the {type} (see {Event} type)
     * @param {string} url - {document.location} via {pendo.url.get}
     * @param {string} name
     * @param {object} event properties collected on feature rule match
     * @return {Event}
     */
    function eventCreate(type, props, url, name, eventProperties) {
        var eventObj = {
            'type':         type,
            'browser_time': getNow(),
            'visitor_id':   pendo.get_visitor_id(),
            'account_id':   pendo.get_account_id(),
            'url':          pendo.url.externalizeURL(url),
            'props':        props
        };
        eventObj = EventTracer.addTracerIds(eventObj);
    
        if (type === 'track') {
            eventObj.track_event_name = name || defaultTrackName;
        } else if (type === 'click' && eventProperties) {
            eventObj.eventProperties =  eventProperties;
        }
        return eventObj;
    }
    
    /**
     * @var {Event[]} event buffer
     * @alias pendo.buffers.events
     */
    var events = pendo.buffers.events = eventCache;
    var trackEvents = pendo.buffers.trackEvents = trackEventCache;
    var eventQueue = createEventQueue({
        'cache':     events,
        'silos':     pendo.buffers.silos,
        'apiKey':    getAllApiKeys,
        'beacon':    'ptm',
        'allowPost': true
    });
    var trackEventQueue = createEventQueue({
        'cache':     trackEvents,
        'silos':     pendo.buffers.trackEventSilos,
        'apiKey':    getAllApiKeys,
        'beacon':    'ptm',
        'allowPost': true,
        'params':    {
            'type': 'track'
        }
    });
    
    /**
     * @public
     *
     * @param {string} type of the event, e.g. `load`, `click`, `focus`
     * @param {object} props differ depending on the {type} (see {Event} type)
     * @param {string} url - {document.location} via {pendo.url.get}
     * @param {string} name
     * @param {object} event properties collected on feature rule match
     * @return {pendo.buffers.events} for testing
     */
    function collectEvent(type, props, url, name, eventProperties) {
        if (!pendoCore) return;
        var event = eventCreate(type, props, url, name, eventProperties);
    
        if (!isURLValid(event.url)) {
            return;
        }
    
        if (!eventIsWhitelisted(event)) {
            return;
        }
    
        if (type === 'track') {
            trackEventQueue.push(event);
            return;
        }
    
        eventQueue.push(event);
    }
    
    // @const {Event.type[]}
    var WHITELIST_FREE_NPS = [ 'load', 'meta', 'identify' ];
    
    /**
     * @param {Event} event to consider
     * @return {boolean} whether {event} is allowed
     */
    function eventIsWhitelisted(event) {
        if (getPendoConfigValue('freeNPSData')) {
            return pendo._.contains(WHITELIST_FREE_NPS, event.type);
        }
    
        return true;
    }
    
    function pipeline() {
        var args = _.toArray(arguments);
        return function generatedPipeline(obj, next) {
            var functions = args.concat([next]);
            (function pipelineCallNext(i, obj) {
                if (i < functions.length) {
                    functions[i](obj, function(obj) {
                        pipelineCallNext(i + 1, obj);
                    });
                }
            })(0, obj);
        };
    }
    
    function reducer(reduceFn, initialValue) {
        var lastValue = initialValue;
        return function generatedReducer(obj, next) {
            lastValue = reduceFn(lastValue, obj);
            next(lastValue);
        };
    }
    
    function siloReducer(initialSilo) {
        return reducer(function(silo, event) {
            silo.push(event);
            return silo;
        }, initialSilo);
    }
    
    /**
     * @idempotent
     * @param {Event} event with or without {Event.bytes}
     * @return {Event} with {Event.bytes}
     */
    function eventAddBytes(event) {
        if (event.bytes == null) {
            event.bytes = JSON.stringify(event).length;
        }
    
        return event;
    }
    
    function filterSiloCapacity(silo, next) {
        var bytes = 0;
        var sliceIndex;
        for (var i = 0; i < silo.length; ++i) {
            var bytesToAdd = eventAddBytes(silo[i]).bytes;
    
            if (bytes + bytesToAdd > SILO_MAX_BYTES) {
                sliceIndex = i;
            }
    
            bytes += bytesToAdd;
        }
    
        if (sliceIndex === 0 && silo.length === 1) {
            sliceIndex = 1;
        }
    
        if (sliceIndex) {
            var completeSilo = silo.slice(0, sliceIndex);
            var incompleteSilo = silo.slice(sliceIndex);
            silo.length = 0;
            silo.push.apply(silo, incompleteSilo);
            next(completeSilo);
        }
    }
    
    function filterSiloLength(silo, next) {
        if (silo.length > MAX_NUM_EVENTS) {
            var completeSilo = silo.slice();
            silo.length = 0;
            next(completeSilo);
        }
    }
    
    function shortenFields(options) {
        options = _.defaults(options || {}, {
            'fields':         ['url'],
            'fieldMaxLength': URL_MAX_LENGTH,
            'siloMaxLength':  ENCODED_EVENT_MAX_POST_LENGTH
        });
        return function shortener(silo, next) {
            if (silo.length === 1 && silo.JZB.length > options.siloMaxLength) {
                var event = silo[0];
    
                debug('Max length exceeded for an event');
    
                _.each(options.fields, function(field) {
                    var url = event[field];
                    if (url && url.length > options.fieldMaxLength) {
                        debug('shortening ' + field + ' and retrying');
    
                        event[field] = limitURLSize(options.fieldMaxLength, url);
    
                        // allow the silo to re-compress
                        delete silo.JZB;
                    }
                });
            }
    
            next(silo);
        };
    }
    
    function compressSilo(silo, next) {
        if (silo.length === 0) return;
        if (silo.JZB) return next(silo);
    
        silo.JZB = pendo.squeezeAndCompress(silo.slice());
    
        if (silo.JZB.length <= ENCODED_EVENT_MAX_LENGTH) {
            return next(silo);
        }
    
        if (silo.length === 1) {
            return next(silo);
        }
    
        // split the silo and try again
        var center = silo.length / 2;
        compressSilo(silo.slice(0, center), next);
        compressSilo(silo.slice(center), next);
    }
    
    function filterAnalyticsDisabled(silo, next) {
        if (!isUnlocked()) return;
        if (isInPreviewMode()) return;
        next(silo);
    }
    
    function errorLogger(silo, next) {
        if (silo.length === 1 && silo.JZB.length > ENCODED_EVENT_MAX_LENGTH) {
            debug('Couldn\'t write event');
            writeMessage('Single item is: ' + silo.JZB.length + '. Dropping.');
            writeErrorPOST(silo.JZB);
        } else {
            writeErrorPOST('Failed to write silo: ' + silo.JZB);
        }
    }
    
    function getApiKeysFromOptions(options) {
        if (_.isFunction(options.apiKey)) {
            return [].concat(options.apiKey());
        }
        return [].concat(options.apiKey);
    }
    
    function buildGetRequestUrls(options, jzb) {
        return _.map(getApiKeysFromOptions(options), function(apiKey) {
            return buildBaseDataUrl(options.beacon + '.gif', apiKey, _.extend({
                'v':   VERSION,
                'ct':  getNow(),
                'jzb': jzb
            }, options.params));
        });
    }
    
    function buildPostRequestUrls(options, jzb) {
        return _.map(getApiKeysFromOptions(options), function(apiKey) {
            return buildBaseDataUrl(options.beacon + '.gif', apiKey, _.extend({
                'v':  VERSION,
                'ct': getNow(),
                's':  jzb.length
            }, options.params));
        });
    }
    
    function defaultSendEvent(options) {
        return function imgWithXhrFallback(silo, next) {
            var jzb = silo.JZB;
    
            if (!jzb) {
                return next(silo);
            }
    
            var jwtOptions = getJwtInfoCopy();
            var eventLength = jzb.length;
    
            if (!_.isEmpty(jwtOptions)) {
                eventLength += jwtOptions.jwt.length + jwtOptions.signingKeyName.length;
            }
    
            if (eventLength > ENCODED_EVENT_MAX_POST_LENGTH) {
                return next(silo);
            }
    
            if (eventLength <= ENCODED_EVENT_MAX_LENGTH) {
                if (_.isEmpty(jwtOptions)) {
                    _.each(buildGetRequestUrls(options, jzb), writeImgTag);
                } else {
                    options.params = _.extend({}, options.params, jwtOptions);
                    _.each(buildGetRequestUrls(options, jzb), function(url) {
                        pendo.ajax({
                            'method': 'GET',
                            'url':    url
                        });
                    });
                }
                return;
            }
    
            if (options.allowPost) {
                if (sendBeacon.supported()) {
                    _.each(buildPostRequestUrls(options, jzb), function(url) {
                        var payload = _.extend({
                            'events': jzb
                        }, jwtOptions);
                        sendBeacon(url, payload);
                    });
                } else {
                    _.each(buildPostRequestUrls(options, jzb), function(url) {
                        var payload = _.extend({
                            'events': jzb
                        }, jwtOptions);
                        var headers = {
                            'Content-Type': 'application/json'
                        };
                        pendo.ajax({
                            'method':  'POST',
                            'url':     url,
                            'data':    JSON.stringify(payload),
                            'headers': headers
                        });
                    });
                }
                return;
            }
    
            next(silo);
        };
    }
    
    function reliableSendEventForUnload(options) {
        return function sendBeaconWithSyncXhrFallback(silo, next) {
            var jzb = silo.JZB;
    
            if (!jzb) {
                return next(silo);
            }
    
            var jwtOptions = getJwtInfoCopy();
            var eventLength = jzb.length;
    
            if (!_.isEmpty(jwtOptions)) {
                eventLength += jwtOptions.jwt.length + jwtOptions.signingKeyName.length;
            }
    
            if (jzb.length > ENCODED_EVENT_MAX_POST_LENGTH) {
                return next(silo);
            }
    
            if (eventLength <= ENCODED_EVENT_MAX_LENGTH) {
                if (_.isEmpty(jwtOptions)) {
                    _.each(buildGetRequestUrls(options, jzb), writeImgTag);
                } else {
                    options.params = _.extend({}, options.params, jwtOptions);
                    _.each(buildGetRequestUrls(options, jzb), function(url) {
                        pendo.ajax({
                            'method': 'GET',
                            'url':    url,
                            'sync':   true
                        });
                    });
                }
                return;
            }
    
            if (options.allowPost) {
                if (sendBeacon.supported()) {
                    _.each(buildPostRequestUrls(options, jzb), function(url) {
                        var payload = _.extend({
                            'events': jzb
                        }, jwtOptions);
                        sendBeacon(url, payload);
                    });
                } else {
                    _.each(buildPostRequestUrls(options, jzb), function(url) {
                        var payload = _.extend({
                            'events': jzb
                        }, jwtOptions);
                        var headers =  {
                            'Content-Type': 'application/json'
                        };
                        pendo.ajax({
                            'method':  'POST',
                            'url':     url,
                            'data':    JSON.stringify(payload),
                            'sync':    true,
                            'headers': headers
                        });
                    });
                }
                return;
            }
    
            next(silo);
        };
    }
    
    function createSendQueue(options, createSender) {
        return pipeline(
            filterAnalyticsDisabled,
            compressSilo,
            shortenFields(options.shorten),
            compressSilo, // re-compress only if the url was shortened
            createSender(options),
            errorLogger
        );
    }
    
    function createEventQueue(options) {
        var cache = options.cache;
        var silos = options.silos;
        var send = createSendQueue(options, defaultSendEvent);
        var guaranteedSend = createSendQueue(options, reliableSendEventForUnload);
        var enqueue = pipeline(
            siloReducer(cache),
            filterSiloCapacity,
            function siloCache(silo) {
                silos.push(silo);
            }
        );
    
        return {
            'push': function push(event) {
                enqueue(event, _.noop);
            },
            'clear': function clear() {
                cache.length = 0;
                silos.length = 0;
            },
            'flush': function flush(flushOptions) {
                if (cache.length === 0 && silos.length === 0) return;
                silos.push(cache.slice());
                cache.length = 0;
                var silosToSend = silos.slice();
                silos.length = 0;
                var sendFunction = (flushOptions || {}).guaranteed ? guaranteedSend : send;
                _.each(silosToSend, function(silo) {
                    sendFunction(silo, _.noop);
                });
            }
        };
    }
    
    var rtrim = /^\s+|\s+$/g;
    var trim = String.prototype.trim;
    if (!trim) {
        trim = function() {
            return this.replace(rtrim, '');
        };
    }
    
    /*
     * events is deprecated here. TODO: simplify this to just
     * attributes by type
     */
    var evt_map = {
        'a':                      { 'events': ['click'], 'attr': ['href'] },
        'button':                 { 'events': ['click'], 'attr': ['value', 'name'] },
        'img':                    { 'events': ['click'], 'attr': ['src','alt'] },
        'select':                 { 'events': ['mouseup'], 'attr': ['name','type','selectedIndex'] },
        'textarea':               { 'events': ['mouseup'], 'attr': ['name'] },
        'input[type="submit"]':   { 'events': ['click'], 'attr': ['name', 'type', 'value'] },
        'input[type="button"]':   { 'events': ['click'], 'attr': ['name', 'type', 'value'] },
        'input[type="radio"]':    { 'events': ['click'], 'attr': ['name', 'type'] },
        'input[type="checkbox"]': { 'events': ['click'], 'attr': ['name', 'type'] },
        'input[type="password"]': { 'events': ['click'], 'attr': ['name', 'type'] },
        'input[type="text"]':     { 'events': ['click'], 'attr': ['name', 'type'] }
    };
    
    var handleEmbeddedData = function(src) {
        if (src && src.indexOf('data:') === 0) {
            debug('Embedded data provided in URI.');
            return src.substring(0, src.indexOf(','));
        }
        return src + '';
    };
    
    var extractAttribute = function(element, attrName, type) {
        if (!element || !element.nodeName) return null;
    
        var tag = element.nodeName.toLowerCase();
        if ((tag == 'img' && attrName == 'src') ||
            (tag == 'a' && attrName == 'href')) {
            var src = element.getAttribute(attrName);
            return sanitizeUrl(handleEmbeddedData(src));
        }
    
        var attr;
        if (element.getAttribute)
        {attr = element.getAttribute(attrName);}
        else
        {attr = element[attrName];}
    
        if (type && typeof attr !== type) return null;
        if (!attr) return null;
    
        return attr;
    };
    
    var asString = function(arg) { return pendo.doesExist(arg) ? '' + arg : ''; };
    
    // other node types can be read about here:
    // https://developer.mozilla.org/en-US/docs/Web/API/Node/nodeType
    var nodeTypeEnum = {
        'TEXT_ELEMENT':           3,
        'ELEMENT_NODE':           1,
        'DOCUMENT_NODE':          9,
        'DOCUMENT_FRAGMENT_NODE': 11,
        'CDATA_SECTION_NODE':     4
    };
    
    function getHtmlAttributeTester(htmlAttributes) {
        if (_.isRegExp(htmlAttributes)) return htmlAttributes;
    
        if (_.isArray(htmlAttributes)) {
            var regexes = _.map(
                _.filter(htmlAttributes, _.isObject),
                function(attributeConfig) {
                    if (attributeConfig.regexp) {
                        var match = /\/([a-z]*)$/.exec(attributeConfig.value);
                        var regexFlags = match && match[1] || '';
                        return new RegExp(attributeConfig.value.replace(/^\//, '').replace(/\/[a-z]*$/, ''), regexFlags);
                    } else {
                        return new RegExp('^' + attributeConfig.value + '$', 'i');
                    }
                }
            );
            return {
                'test': function(str) {
                    return _.any(regexes, function(regex) {
                        return regex.test(str);
                    });
                }
            };
        }
    
        return {
            'test': function() {
                return false;
            }
        };
    }
    
    var extractElementContext = function(node) {
        var context = {};
    
        if (!node) return context;
    
        context.tag = shadowAPI.isElementShadowRoot(node) ? '#shadow-root' : (node.nodeName || '');
        context.id = asString(node.id);
        context.cls = asString(dom.getClass(node));
        context.title    = extractAttribute(node, 'title', 'string');
    
        // Look up tag in element map
        var key = (context.tag || '').toLowerCase();
        if (key === 'input') {
            key += '[type="' + node.type + '"]';
        }
    
        context.attrs = {};
    
        // Grab element-specific attributes
        if (evt_map[key]) {
            _.each(evt_map[key].attr, function(attr) {
                var attrValue = extractAttribute(node, attr);
                if (pendo.doesExist(attrValue)) {
                    context.attrs[attr] = attrValue;
                }
            });
        }
    
        // Grab any other attributes whitelisted for this client
        var htmlAttributes = getHtmlAttributeTester(getPendoConfigValue('htmlAttributes'));
        if (_.isFunction(htmlAttributes.test)) {
            _.each(node.attributes, function(attributeNode) {
                var attrName = attributeNode.nodeName;
                if (htmlAttributes.test(attrName)) {
                    context.attrs[attrName.toLowerCase()] = extractAttribute(node, attrName);
                }
            });
        }
    
        // Remove blacklisted attributes
        var htmlAttributeBlacklist = getHtmlAttributeTester(getPendoConfigValue('htmlAttributeBlacklist'));
        if (_.isFunction(htmlAttributeBlacklist.test)) {
            _.each(context.attrs, function(attrValue, attrName) {
                if (htmlAttributeBlacklist.test(attrName)) {
                    delete context.attrs[attrName];
                }
            });
            // special case for title
            if (htmlAttributeBlacklist.test('title')) {
                delete context.title;
            }
        }
    
        if (node.parentNode && node.parentNode.childNodes) {
            var nodes = _.chain(node.parentNode.childNodes);
            context.myIndex = nodes.indexOf(node).value();
            context.childIndex = nodes.filter(function(n) {
                return n.nodeType == nodeTypeEnum.ELEMENT_NODE;
            }).indexOf(node).value();
        }
    
        return context;
    };
    
    var isNodeTheRoot = function(node) {
        return node.nodeName === 'BODY' || (node.parentNode === null && !shadowAPI.isElementShadowRoot(node));
    };
    
    var extractElementTreeContext = function(leaf) {
        var origContext = {};
        var currContext = origContext;
        var node, pnode = leaf;
    
        if (!leaf) return origContext;
    
        do {
            node = pnode;
            var context = extractElementContext(node);
            currContext.parentElem = context;
            currContext = context;
            pnode = shadowAPI.getParent(node);
    
        } while (pnode && !isNodeTheRoot(node));
    
        if (TextCapture.isEnabled() || (!TextCapture.isEnabled() && TextCapture.hasWhitelist())) {
            var text = getText(leaf, 128);
            if (TextCapture.isTextCapturable(text)) {
                origContext.parentElem.txt = text;
            }
        }
    
        // I don't understand this. do we not want to clear value if there is text?
        if (!TextCapture.isEnabled() && origContext.parentElem.value) {
            origContext.parentElem.value = null;
        }
    
        return origContext.parentElem;
    };
    
    
    /*
     * Additional data we care about for click events
     */
    var buttonNumMap = ['', 'left', 'right', 'middle'];
    var buttonLookup = function(name, num) { return buttonNumMap[num]; };
    var retTrue = function() { return true; };
    var getButtonType = function(evt) { return evt.which || evt.button; };
    var identity = function(foo) { return foo; };
    var propGet  = function(obj, prop) { return obj[prop]; };
    
    var COMMON_CLICK_ATTRS = [
        ['button', getButtonType, retTrue, buttonLookup],
        ['altKey', propGet, identity, identity],
        ['ctrlKey', propGet, identity, identity],
        ['metaKey', propGet, identity, identity],
        ['shiftKey', propGet, identity, identity]
    ];
    
    /*
     * Interrogate the click event object to extract the addition
     * flags we want for the event.
     *
     * input: clickEvt (Event)
     *        data (Object)
     * output: mutated data object
     */
    var determineClickFlags = function(evt, data) {
        var flags = [];
    
        for (var i = 0; i < COMMON_CLICK_ATTRS.length; i++) {
            var attr_tup = COMMON_CLICK_ATTRS[i];
            var attr_name = attr_tup[0];
    
            var getFn  = attr_tup[1];
            var testFn = attr_tup[2];
            var flagFn = attr_tup[3];
    
            var val = getFn(evt, attr_name);
    
            if (testFn(val))
            {flags.push(flagFn(attr_name, val));}
        }
    
        data.flags = flags;
    
        return data;
    };
    
    var evtHandlerExtFn = {
        'click': determineClickFlags
    };
    
    var getTarget = function(evt) {
        var cpArr = shadowAPI.getComposedPath(evt);
        if (cpArr && cpArr.length > 0) {
            return cpArr[0];
        }
        return evt.target || evt.srcElement;
    };
    
    var isElemBlacklisted = function(elem) {
        return !elem.tagName || elem.tagName.toLowerCase() == 'textarea';
    };
    
    /**
     * Determine if the supplied {codepoint} falls within the "high surrogate" range
     * of unicode characters.
     *
     * @param {Number} codepoint
     * @return {Boolean}
     *
     * @see https://en.wikipedia.org/wiki/UTF-16#U.2BD800_to_U.2BDFFF
     */
    function isHighSurrogate(codepoint) {
        return (0xD800 <= codepoint && codepoint <= 0xDBFF);
    }
    
    /**
     * Determine if the supplied {codepoint} falls within the "low surrogate" range
     * of unicode characters.
     *
     * @param {Number} codepoint
     * @return {Boolean}
     *
     * @see https://en.wikipedia.org/wiki/UTF-16#U.2BD800_to_U.2BDFFF
     */
    function isLowSurrogate(codepoint) {
        return (0xDC00 <= codepoint && codepoint <= 0xDFFF);
    }
    
    /**
     * Remove "high surrogate" or unmatched "low surrogate" characters from the end
     * of {s}, indicating a broken unicode glyph. This happens when we truncate the
     * text of a node in {getText} that ends with a double-byte-encoded unicode glyph
     * such as emoji.
     *
     * @see https://github.com/pendo-io/pendo-client/pull/12
     *
     * @param {String} s
     * @return {String} s if no trailing surrogates, s-1 otherwise
     */
    function trimSurrogate(s) {
        // If the string is empty, it's definitely _not_ a "lonely surrogate"...
        if (s.length < 1) return s;
    
        var last = s.slice(-1).charCodeAt(0);
    
        // We're only interested in the `last` character...
        if (!isHighSurrogate(last) && !isLowSurrogate(last)) return s;
    
        // If the string is only 1 character, that surrogate is definitely "lonely"...
        if (s.length === 1) return s.slice(0, -1);
    
        // All "lonely high surrogates" shall be eradicated...
        if (isHighSurrogate(last)) return s.slice(0, -1);
    
        // Not sure how "lonely low surrogate" could happen, but let's check!
        if (isLowSurrogate(last)) {
            // Per above, the `last` character isn't the _only_ character...
            var prev = s.slice(-2).charCodeAt(0);
    
            // And if the `prev` character isn't a "high surrogate", that "low surrogate" is lonely.
            if (!isHighSurrogate(prev)) return s.slice(0, -1);
        }
    
        return s; // otherwise leave it alone
    }
    
    function getText(elem, limit) {
        var ret = '',
            nodeType = elem.nodeType,
            sub;
    
        if (nodeType === nodeTypeEnum.TEXT_ELEMENT || nodeType === nodeTypeEnum.CDATA_SECTION_NODE) {
            return elem.nodeValue;
        } else if (!isElemBlacklisted(elem) &&
            (nodeType === nodeTypeEnum.ELEMENT_NODE ||
                nodeType === nodeTypeEnum.DOCUMENT_NODE ||
                nodeType === nodeTypeEnum.DOCUMENT_FRAGMENT_NODE)) {
            // Traverse its children
            for (elem = elem.firstChild; elem; elem = elem.nextSibling) {
                sub = getText(elem, limit - ret.length);
                if ((ret + sub).length >= limit) {
                    return ret + trimSurrogate(sub.substring(0, limit - ret.length));
                }
    
                ret += sub;
            }
        }
    
        return ret;
    }
    
    var getValidTarget = function(node) {
        if (node.nodeType === nodeTypeEnum.TEXT_ELEMENT) {
            return node.parentNode;
        } else if (node.nodeType === nodeTypeEnum.CDATA_SECTION_NODE) {
            return null;
        } else if (node.correspondingUseElement) {
            //Handle SVG sprites in IE
            return node.correspondingUseElement;
        }
    
        return node;
    };
    
    /*
     * After the user causes one of the Events we care about for Pendo
     * to happen we react by collecting various data from the DOM at
     * the moment and package it up for sending to the server.
     */
    var handle_event = function(evt) {
        try {
            var target = getTarget(evt);
            var type = evt.type;
            var extraData = {};
    
            var typeFn = evtHandlerExtFn[type];
            if (typeFn) {
                extraData = typeFn(evt, extraData);
            }
    
            target = getValidTarget(target);
            if (!target) {
                log('Invalid HTML target', 'event', 'dom', 'processing');
                return;
            }
    
            var data = extractElementTreeContext(target);
            _.extend(data, extraData);
    
            pageLoad(); // Send a load event if the page changed and we missed it somehow
            if (type === 'click') {
                var eventProperties = collectEventProperties(target);
                collectEvent(
                    type,
                    { 'target': data },
                    undefined,
                    undefined,
                    eventProperties
                );
            } else {
                collectEvent(type, { 'target': data });
            }
        } catch (e) {
            writeException(e, 'pendo.io while handling event');
        }
    };
    
    function collectEventPropertiesForTarget(target) {
        if (!(pendo.eventProperties && pendo.eventProperties.length && target)) { return; }
        // Track start time for use in the shouldEject function
        var startTime = getNow();
        // how much 'lag' we can tolerate introducing in front of a user's click before we break
        var eventPropertyCollectionThreshold = 50;
    
        var result = {};
        // Check to see if the target matches any of the feature rules
        // or shortcircuit if too much time has elapsed
        var ep = undefined;
        for (
            var epIndex = 0;
            epIndex < pendo.eventProperties.length && ((getNow() - startTime) < eventPropertyCollectionThreshold);
            epIndex++
        ) {
            ep = pendo.eventProperties[epIndex];
            var match = _.any(ep.featureRules, function(rule) {
                try {
                    return pendo.Sizzle.matchesSelector(target, rule);
                } catch (err) {
                    return false;
                }
            });
            if (match) {
                // In the case that a target matches a feature, collect all Event Properties for said feature
                // or shortcircuit if too much time has elapsed
                for (
                    var collectEPIndex = 0;
                    collectEPIndex < ep.eventPropertyRules.length && ((getNow() - startTime) < eventPropertyCollectionThreshold);
                    collectEPIndex++
                ) {
                    var currentRule = ep.eventPropertyRules[collectEPIndex];
                    if(!currentRule.name) { return; }
    
                    result[currentRule.name] = collectEventProperty(currentRule, target);
                }
            }
        }
        // Naming matches event property name restrictions enforced by the backend.
        result.collection_overhead_in_ms = getNow() - startTime;
        if (result.collection_overhead_in_ms > eventPropertyCollectionThreshold) {
            pendo.log('event property collection disabled; collection took greater than ' + eventPropertyCollectionThreshold + ' milliseconds.');
            var logMessage = 'ERROR event property collection exceeded time limit.';
            if (ep) {
                logMessage += '\n For feature with id: ' + ep.featureId;
            }
    
            writeException({}, logMessage);
            // Once we fail to collect an eventProperty because of a pause we will not continue
            // to punish our customer's customer by letting it happen again
            // we have the log so we can investigate, no need to register a ton more while they
            // experience jank hell.
            pendo.eventProperties = [];
        }
        return result;
    }
    var collectEventProperties = makeSafe(collectEventPropertiesForTarget);
    
    function collectEventProperty(eventPropertyRule, clickedElement) {
        if (!eventPropertyRule.path) return;
        var target = getEventPropertyTarget(eventPropertyRule, clickedElement);
        return get(
            target,
            eventPropertyRule.path,
            undefined
        );
    }
    
    function getEventPropertyTarget(eventPropertyRule, clickedElement) {
        var elementSelector = eventPropertyRule.source || eventPropertyRule.selector;
        if (elementSelector) {
            return nearestTargeter(elementSelector, clickedElement);
        } else {
            return window;
        }
    }
    
    function nearestTargeter(elementSelector, clickedElement) {
        var currentNode = clickedElement;
        var found;
        while(!found && currentNode) {
            try {
                found = pendo.Sizzle(elementSelector, currentNode)[0];
                if (found && (found.type === 'password' || found.type === 'hidden')) { return; }
            } catch (err) {
                return;
            }
            currentNode = shadowAPI.getParent(currentNode);
        }
        return found;
    }
    
    /*
     * Adds listeners to the DOM for user events
     * like click and focus.
     *
     * input: eventList (Array<string>)
     * output: none
     * sideffect: attach event listeners to the body for each event type
     */
    var listenForEvents = function(eventList) {
        _.each(eventList, function(eventType) {
            attachEvent(document, eventType, handle_event, true);
        });
    };
    
    /**
     * Number of millis to debounce `change` events entering the event pipeline
     * via {handle_event}
     *
     * @see {wirePage}
     * @link https://pendo-io.atlassian.net/browse/APP-11412
     */
    var DEBOUNCE_INTERVAL_CHANGE = 5000;
    
    // Debounce `handle_event` for `change` events
    var handle_change_event = _.debounce(handle_event, DEBOUNCE_INTERVAL_CHANGE, true);
    
    
    /*
     * Wires up the page for all the different event driven
     * functions that the pendo agent cares about.
     *
     * input: eventlist (Array<string>) names of events
     */
    var wirePage = function(eventList) {
        eventList = eventList || ['click', 'focus', 'submit', 'change'];
    
        if (_.contains(eventList, 'change')) {
            eventList = _.reject(eventList, function(value) { return value === 'change'; });
    
            attachEvent(document, 'change', handle_change_event, true);
        }
    
        listenForEvents(eventList);
    
        if (getPendoConfigValue('xhrTimings')) {
            openXhrIntercept();
        }
    
        attachEvent(window, 'unload', function() {
            flushNow(true, { 'guaranteed': true }); // escape hatch: send everything in all buffers
        });
    
        wireTurbolinks();
    };
    
    var wireTurbolinks = function() {
        if (typeof Turbolinks !== 'undefined') {
            // Special case guide reloading for troublesome Rails component:
            // https://github.com/rails/turbolinks
            /*global Turbolinks*/
            var pageLoad = Turbolinks && Turbolinks.EVENTS && Turbolinks.EVENTS.LOAD;
            if (pageLoad) {
                attachEvent(document, pageLoad, function() {
                    if (pendo.url.get() === reloadGuides.lastUrl) {
                        //Force a reload if Turbolinks replaces the document body without changing the url
                        delete reloadGuides.lastUrl;
                        queueGuideReload();
                    }
                });
            }
        }
    };
    
    var attachEvent = function(element, evt, fn, useCapture) {
        if (!(element && evt && fn)) {
            return;
        }
    
        // special case for error on window
        if (element === window && evt === 'error') {
            // do nothing
            return;
        }
    
        if (!useCapture) useCapture = false; // !!useCapture
        if (element.addEventListener) {
            element.addEventListener(evt, fn, useCapture);
        } else {
            element.attachEvent('on' + evt, fn);
        }
    };
    
    var detachEvent = function(element, evt, fn, useCapture) {
        if (!(element && evt && fn)) {
            return;
        }
    
        if (!useCapture) useCapture = false;
        if (element.removeEventListener) {
            element.removeEventListener(evt, fn, useCapture);
        } else {
            element.detachEvent('on' + evt, fn);
        }
    };
    
    var stopEvent = function(evt) {
        if (evt.stopPropagation) {
            evt.stopPropagation();
        } else {
            evt.cancelBubble = true;
        }
        if (evt.preventDefault) {
            evt.preventDefault();
        } else {
            evt.returnValue = false;
        }
    };
    
    var getDefaultLogOverride = function(env) {
        var isEnabledCookie = agentStorage.read('log-enabled', true);
    
        if (isEnabledCookie !== null) {
            return isEnabledCookie == 'true';
        }
    
        // add welcome message and list logging status + contexts
    
        return !_.contains(['prod', 'prod-eu', 'rc'], env);
    };
    
    var getDefaultActiveContexts = function() {
        var ac = agentStorage.read('active-contexts', true);
        if (!ac) return [];
        return ac.split(',');
    };
    
    var enableLogging = function() {
        if (!canWeLog())
            {return 'logging unavailable';}
    
        if (logOverride)
            {return 'logging already enabled';}
    
        agentStorage.write('log-enabled', 'true', null, true);
        logOverride = true;
        return 'logging enabled';
    };
    
    var disableLogging = function() {
        if (!logOverride)
            {return 'logging already disabled';}
    
        agentStorage.write('log-enabled', 'false', null, true);
    
        logOverride = false;
        return 'logging disabled';
    };
    
    var activeContexts = getDefaultActiveContexts();
    var logOverride = getDefaultLogOverride(ENV);
    
    var createContexts = function(contexts, args) {
        return _.compact([].concat(contexts, args));
    };
    
    // Can this browser use console.log?
    var canWeLog = function() {
        //eslint-disable-next-line no-console
        return (typeof (console) !== 'undefined' && console.log !== undefined);
    };
    
    // according to environment, user elections, and contexts should we
    // show this log message?
    var shouldWeLog = function(contexts) {
        contexts = createContexts(contexts);
    
        // log only for contexts that are active.
        if (activeContexts.length > 0) {
            return (_.intersection(activeContexts, contexts).length > 0);
        }
    
        return (!!logOverride || !!pendo.isDebuggingEnabled(true));
    };
    
    var log = function(msg, contexts) {
        contexts = createContexts(contexts, _.tail(arguments, 2));
    
        if (canWeLog()) {
            if (shouldWeLog(contexts)) {
                doConsoleLog(msg);
            }
            addToLogHistory(msg, contexts);
        }
    };
    
    var MAX_HISTORY = 100;
    var logHistory = [];
    
    var addToLogHistory = function(msg, contexts) {
        if (_.contains(contexts, 'debug')) return;
    
        if (logHistory.length == MAX_HISTORY) logHistory.shift();
        logHistory.push([msg, contexts]);
    };
    
    var showLogHistory = function(contexts) {
        contexts = createContexts(contexts);
    
        _.each(
            _.map(
                _.filter(logHistory, function(item) {
                    return (contexts.length === 0 || _.intersection(contexts, item[1]).length > 0);
                }),
                function(item) { return item[0]; }
            ), function(msg) {
            doConsoleLog(msg, '[Pendo-History] ');
        }
        );
    };
    
    var getLoggedContexts = function() {
        return _.union.apply(_, _.map(logHistory, function(item) {return item[1];}));
    };
    
    var getActiveContexts = function() {
        return activeContexts;
    };
    
    var setActiveContexts = function(contexts) {
        activeContexts = createContexts(contexts);
        agentStorage.write('active-contexts', activeContexts.join(','), null, true);
    };
    
    var doConsoleLog = function(msg, prefix) {
        if (!canWeLog()) return;
    
        prefix = prefix || '[Agent] ';
    
        if (msg && msg.length) {
            var msgStart = msg.length > 1000 ? msg.length - 1000 : 0;
    
            if (msgStart) {
                prefix += '...';
            }
    
            //eslint-disable-next-line no-console
            console.log(prefix + msg.substring(msgStart));
        } else {
            //eslint-disable-next-line no-console
            console.log(prefix + msg);
        }
    };
    
    log.enableLogging = enableLogging;
    log.disableLogging = disableLogging;
    log.getActiveContexts = getActiveContexts;
    log.setActiveContexts = setActiveContexts;
    log.showLogHistory = showLogHistory;
    log.getLoggedContexts = getLoggedContexts;
    
    var isOldIE  = function(olderThan, tVersion) {
        olderThan = olderThan || 10;
    
        tVersion = isNaN(trident) ? false : (tVersion ? (trident < tVersion) : true);
    
        return (tVersion && (msie < olderThan));
    };
    
    // "borrowed" from angular.js
    // https://github.com/angular/angular.js/blob/v1.2.27/src/ng/sniffer.js
    
    
    
    // NOTE: 
    // msie represents the rendering version of the browser.  which is
    // variable b/c IE supports "compatibility modes" to try to recreate
    // the flawed environment of past IEs.
    
    // there are some incompatibilities that arise due to this b/c newer IEs
    // have different capabilities.  (e.g. DX filters aren't support in IE
    // 10+ but are required in IE 9- so renders expecting to use the msie
    // value to determine how to draw content do it wrong.  
    
    // we've added trident to track this actual version of IE so we can
    // attempt to handle these cases too.
    
    
    var /** holds major version number for IE or NaN for real browsers */
        msie,
        trident;
    
    function pint(str) { return parseInt(str, 10); }
    var lowercase = function(string) {return isString(string) ? string.toLowerCase() : string;};
    
    /**
     * IE 11 changed the format of the UserAgent string.
     * See http://msdn.microsoft.com/en-us/library/ms537503.aspx
     */
    
    var determineMSIE = function(ua) {
        var v = pint((/msie (\d+)/.exec(lowercase(ua)) || [])[1]);
        if (isNaN(v)) {
            v = pint((/trident\/.*; rv:(\d+)/.exec(lowercase(ua)) || [])[1]);
        }
        return v;
    };
    
    msie = determineMSIE(navigator.userAgent);
    
    var determineTrident = function(ua, ieV) {
        
        var v = pint((/trident\/(\d+)/.exec(lowercase(ua)) || [])[1]);
        if (isNaN(v) && ieV == 7)
            {v = 3;}
        return v;
    };
    
    trident = determineTrident(navigator.userAgent, msie);
    
    
    function isString(value) {return typeof value === 'string';}
    function isUndefined(value) {return typeof value === 'undefined';}
    
    var eventSupport = {},
        android = pint((/android (\d+)/.exec(lowercase((window.navigator || {}).userAgent)) || [])[1]),
        boxee = /Boxee/i.test((window.navigator || {}).userAgent),
        pdocument = window.document || {},
        documentMode = pdocument.documentMode,
        vendorPrefix,
        vendorRegex = /^(Moz|webkit|O|ms)(?=[A-Z])/,
        bodyStyle = pdocument.body && pdocument.body.style,
        transitions = false,
        animations = false,
        match;
    
    if (bodyStyle) {
        //eslint-disable-next-line guard-for-in
        for(var prop in bodyStyle) {
            match = vendorRegex.exec(prop);
            if(match) {
                vendorPrefix = match[0];
                vendorPrefix = vendorPrefix.substr(0, 1).toUpperCase() + vendorPrefix.substr(1);
                break;
            }
        }
    
        if(!vendorPrefix) {
            vendorPrefix = ('WebkitOpacity' in bodyStyle) && 'webkit';
        }
    
        transitions = !!(('transition' in bodyStyle) || (vendorPrefix + 'Transition' in bodyStyle));
        animations  = !!(('animation' in bodyStyle) || (vendorPrefix + 'Animation' in bodyStyle));
    
        if (android && (!transitions || !animations)) {
            transitions = isString(pdocument.body.style.webkitTransition);
            animations = isString(pdocument.body.style.webkitAnimation);
        }
    }
    
    // exports
    pendo._.extend(pendo, { 
        'sniffer': {
            // Android has history.pushState, but it does not update location correctly
            // so let's not use the history API at all.
            // http://code.google.com/p/android/issues/detail?id=17471
            // https://github.com/angular/angular.js/issues/904
    
            // older webkit browser (533.9) on Boxee box has exactly the same problem as Android has
            // so let's not use the history API also
            // We are purposefully using `!(android < 4)` to cover the case when `android` is undefined
            // jshint -W018
            'history':    !!(window.history && window.history.pushState && !(android < 4) && !boxee),
            // jshint +W018
            'hashchange': 'onhashchange' in window &&
                // IE8 compatible mode lies
                (!documentMode || documentMode > 7),
            'hasEvent': function(event) {
                // IE9 implements 'input' event it's so fubared that we rather pretend that it doesn't have
                // it. In particular the event is not fired when backspace or delete key are pressed or
                // when cut operation is performed.
                if (event == 'input' && msie == 9) return false;
    
                if (isUndefined(eventSupport[event])) {
                    var divElm = pdocument.createElement('div');
                    eventSupport[event] = 'on' + event in divElm;
                }
    
                return eventSupport[event];
            },
            'vendorPrefix':     vendorPrefix,
            'transitions':      transitions,
            'animations':       animations,
            'android':          android,
            'msie':             msie,
            'msieDocumentMode': documentMode
        }
    });
    
    // // also "borrowed" from angular.js
    // // https://github.com/angular/angular.js/blob/v1.2.27/src/ng/browser.js
    
    var pSetTimeout = window.setTimeout;
    
    var decodeURIComponent = _.isFunction(window.decodeURIComponent) ? window.decodeURIComponent : _.identity;
    var encodeURIComponent = _.isFunction(window.encodeURIComponent) ? window.encodeURIComponent : _.identity;
    
    var isElectron = function() {
        // For now, only return true if electron app supports node integration
        return window && window.process && window.process.versions && window.process.versions.electron;
    };
    
    var getWindowLocation = function() {
        var location = window.location;
        if (shouldIgnoreHashRouting()) {
            location = {
                'href':   getHrefWithoutHash(location.href),
                'origin': location.origin
            };
        }
        return location;
    };
    
    var electronResourcesPath = function() {
        return window.process.resourcesPath || '';
    };
    
    var electronUserDirectory = function() {
        return window.process.env.PWD || '';
    };
    
    var electronUserHomeDirectory = function() {
        return window.process.env.HOME || '';
    };
    
    var electronAppName = function() {
        return window.process.env.npm_package_name || '';
    };
    
    /**
     * @name getHref
     * @description
     *
     * @returns {string} the correct href based on application type
     */
    var getHref = function() {
        var applicationLocation = pendo.url.getWindowLocation();
    
        if (pendo.url.isElectron()) {
            var resourcesPath = pendo.url.electronResourcesPath();
            var directory = pendo.url.electronUserDirectory();
            var appname = pendo.url.electronAppName();
            var href = 'https://' + applicationLocation.href.replace(resourcesPath, appname);
            // Replacing url in instance of a developed electron script
            href = href.replace(applicationLocation.origin + directory, appname);
            // Last ditch effort to remove file:/// and user HOME path
            href = href.replace(pendo.url.electronUserHomeDirectory(), '');
            href = href.replace('file:///', '');
            return href;
        }
    
        return annotateUrl(applicationLocation.href);
    };
    
    /**
     * Strips the hash from the given well-formatted HREF.
     *
     * @param {string} href
     */
    var getHrefWithoutHash = function(href) {
        return href.match(/(.+?)(?:#|$)/)[1];
    };
    
    var shouldIgnoreHashRouting = function() {
        var options = originalOptions || window.pendo_options || {};
        return (getPendoConfigValue('ignoreHashRouting') || options.ignoreHashRouting) === true;
    };
    
    // ////////////////////////////////////////////////////////////
    // Poll Watcher API
    // ////////////////////////////////////////////////////////////
    var pollFns = [],
        pollTimeout;
    
    /**
     * @name $browser#addPollFn
     *
     * @param {function()} fn Poll function to add
     *
     * @description
     * Adds a function to the list of functions that poller periodically executes,
     * and starts polling if not started yet.
     *
     * @returns {function()} the added function
     */
    var addPollFn = function(fn) {
        if (isUndefined(pollTimeout)) startPoller(100, pSetTimeout);
        pollFns.push(fn);
        return fn;
    };
    
    /**
     * @param {number} interval How often should browser call poll functions (ms)
     * @param {function()} setTimeout Reference to a real or fake `setTimeout` function.
     *
     * @description
     * Configures the poller to run in the specified intervals, using the specified
     * setTimeout fn and kicks it off.
     */
    function startPoller(interval, setTimeout) {
        (function check() {
            pendo._.map(pollFns, function(pollFn) { pollFn(); });
            pollTimeout = setTimeout(check, interval);
        })();
    }
    
    // ////////////////////////////////////////////////////////////
    // URL API
    // ////////////////////////////////////////////////////////////
    
    /**
     * @name $browser#url
     *
     * @description
     * GETTER:
     * Without any argument, this method just returns current value of location.href.
     *
     * SETTER:
     * With at least one argument, this method sets url to new value.
     * Returns its own instance to allow chaining
     *
     * NOTE: this api is intended for use only by the $location service. Please use the
     * {@link ng.$location $location service} to change url.
     *
     * @param {string} url New url (when used as setter)
     */
    var url = function(url) {
        // Android Browser BFCache causes location, history reference to become stale.
        // getter
        // - reloadLocation is needed as browsers don't allow to read out
        //   the new location.href if a reload happened.
        var href;
        try {
            href = getHref();
        } catch (e) {
            // AOL_ONE_Video error spam prevention
        }
    
        return href;
    };
    
    var urlChangeListeners = [],
        urlChangeInit = false;
    
    function fireUrlChange() {
        var currentUrl = url();
    
        if (lastBrowserUrl != currentUrl) {
            lastBrowserUrl = currentUrl;
            pendo._.map(urlChangeListeners, function(listener) {
                listener(url());
            });
        }
    }
    
    var onUrlChange = function(callback) {
        log('Initializing Pendo URL Watcher');
    
        if (!urlChangeInit) {
            var sniffer = pendo.sniffer;
    
            if (sniffer.history) {
                var history = window.history;
    
                _.each(['pushState', 'replaceState'], function(method) {
                    history[method] = _.wrap(history[method], function(historyMethod) {
                        var returnValue = historyMethod.apply(history, _.toArray(arguments).slice(1));
                        getZoneSafeMethod('setTimeout')(fireUrlChange, 0);
                        return returnValue;
                    });
                });
    
                attachEvent(window, 'popstate', fireUrlChange);
            }
    
            if (sniffer.hashchange) {
                attachEvent(window, 'hashchange', fireUrlChange);
            }
    
            if (!sniffer.history || !sniffer.hashchange) {
                addPollFn(fireUrlChange);
            }
    
            urlChangeInit = true;
        }
    
        urlChangeListeners.push(callback);
        return callback;
    };
    
    var clearList = function() {
        urlChangeListeners = [];
    };
    
    var getProtocol = function() {
        return (document && document.location && document.location.protocol === 'http:' ? 'http:' : 'https:');
    };
    
    var URL_WHITELIST_KEY = 'queryStringWhitelist';
    
    function sanitizeUrl(url) {
        if (originalOptions && originalOptions.sanitizeUrl && _.isFunction(originalOptions.sanitizeUrl)) {
            return originalOptions.sanitizeUrl(url);
        }
        return url;
    }
    
    /**
     * Leverage return value from customer-provided annotateUrl function.
     * Customer-provided return value should be either an array of strings
     * or an object.
     *
     * @param {string} applicationUrl current application href
     * @return {string} URL with annotations added as encoded query parameters
     */
    function annotateUrl(applicationUrl) {
        applicationUrl = applicationUrl || getWindowLocation().href;
        var customerFunction = getOption('annotateUrl');
    
        if (customerFunction) {
            if (_.isFunction(customerFunction)) {
                var annotations = customerFunction();
    
                return pendo.ajax.urlFor(applicationUrl, annotations);
            } else {
                log('customer-provided `annotateUrl` must be of type: function');
            }
        }
        return applicationUrl;
    }
    
    function parseQueryString(href) {
        if (!href) return '';
        var searchStart = href.indexOf('?');
        if (searchStart < 0) return '';
        var hashStart = href.indexOf('#');
        if (hashStart < 0) return href.substring(searchStart);
        if (hashStart < searchStart) return '';
        return href.substring(searchStart, hashStart);
    }
    
    /*
    * externalizeURL - Apply filtering actions as specified by the application to ensure the URL
    * is in an appropriate state to be sent to Pendo.
    *
    * accepts href, query string, and xhrWhitelist array parameters optionally.
    *
    * NOTE: query string needs to have the leading '?' already trimmed off.
    */
    var externalizeURL = function(href, qs, xhrWhitelist) {
        href = href || url();
        qs = qs || parseQueryString(href).substring(1); // strip off '?'
    
        var startIdx, endIdx;
        startIdx = href.indexOf(qs);
        endIdx = startIdx + qs.length;
        var hrefStart = href.substring(0, startIdx),
            hrefEnd = href.substring(endIdx);
    
        // do whitelist or blacklist query string keys exist?
        var wl = xhrWhitelist || getOption(URL_WHITELIST_KEY);
    
        if (_.isFunction(wl)) wl = wl();
        if (_.isArray(wl))
            {qs = whitelistQueryStringParams(qs, wl);}
    
        // Pull off the ? of the href if there were query params but are no longer
        if (!qs.length && (hrefStart.charAt(hrefStart.length - 1) === '?')) {
            hrefStart = hrefStart.substr(0, (hrefStart.length - 1));
        }
    
        var newUrl = hrefStart + qs + hrefEnd;
    
        newUrl = sanitizeUrl(newUrl);
    
        return newUrl;
    };
    
    var whitelistQueryStringParams = function(qs, keys) {
        var obj = queryStringToObject(qs);
        obj = _.pick(obj, keys);
        return objectToQueryString(obj);
    };
    
    var queryStringToObject = function(querystring) {
        var keysAndValues = querystring.split('&');
        return _.reduce(keysAndValues, function(memo, kv) {
            kv = kv.split('=');
            memo[kv[0]] = kv[1];
            return memo;
        }, {});
    };
    
    var objectToQueryString = function(obj) {
        return _.reduce(obj, function(memo, v, k) {
            return !memo ? memo + k + '=' + v : memo + '&' + k + '=' + v;
        }, '');
    };
    
    pendo._.extend(pendo, {
        'url': {
            'watch':                     onUrlChange,
            'get':                       url,
            'externalizeURL':            externalizeURL,
            // for testing
            'getWindowLocation':         getWindowLocation,
            'clear':                     clearList,
            'isElectron':                isElectron,
            'electronUserDirectory':     electronUserDirectory,
            'electronAppName':           electronAppName,
            'electronUserHomeDirectory': electronUserHomeDirectory,
            'electronResourcesPath':     electronResourcesPath
        }
    });
    
    var lastBrowserUrl = getHref();
    
    // not sure why lint can't find this var
    //eslint-disable-next-line no-unused-vars
    var lastSavedOptions = null;
    var metadataHash;
    
    var getLocale = function() {
        var nav = window.navigator;
        return ((
            pendo._.isArray(nav.languages) ? nav.languages[0] :
                nav.language ||
                nav.browserLanguage ||
                nav.systemLanguage ||
                nav.userLanguage
        ) || '').split('-').join('_');
    };
    
    var OPTIONS_HASH_KEY_NAME = 'meta';
    var haveOptionsChanged = function(hash) {
        if (typeof hash === 'object')
            {hash = crc32(hash);} // or should this reject?
    
        if (typeof hash !== 'undefined' && hash.toString) {
            hash = hash.toString();//convert to string for comparison
        }
        var prevHash = _.isNumber(metadataHash) ? metadataHash : agentStorage.read(OPTIONS_HASH_KEY_NAME);
    
        if ('' + prevHash !== hash) {
            return true;
        } else
            {return false;}
    };
    
    var isScalar = function(value) {
        return _.any(['Number', 'Boolean', 'Date', 'String', 'Null', 'NaN', 'Undefined'], function(type) {
            return _['is' + type](value);
        });
    };
    
    // Filter out values that we can't do anything with on the server (e.g. subobjects and arrays of objects)
    var cleanupMetadata = function(metadata) {
        var cleaned = {};
        _.each(metadata, function(value, key) {
            if (isScalar(value)) {
                cleaned[key] = value;
            } else if (_.isArray(value)) {
                cleaned[key] = _.filter(value, isScalar);
            }
        });
        return cleaned;
    };
    
    // only want options.visitor and options.account sub-objects
    var prepareOptions = function(options) {
    
        if (!_.isObject(options)) options = {};
        if (!_.isObject(options.visitor)) options.visitor = {};
        if (!_.isObject(options.account)) options.account = {};
        if (!_.isObject(options.parentAccount)) options.parentAccount = {};
    
        if (options.visitor.id === DEFAULT_VISITOR_ID) {
            pendo.log('Missing visitor id.');
            delete options.visitor.id;
        }
    
        if (pendo.doesExist(options.account.id) &&
            pendo.doesExist(options.parentAccount.id)) {
            if (!isSubaccount(options.account.id)) {
                options.account.id = '' + options.parentAccount.id + SUBACCOUNT_DELIMITER + options.account.id;
            } else {
                options.parentAccount.id = options.account.id.split(SUBACCOUNT_DELIMITER)[0];
            }
        }
    
        // Use our "fixed" ids for the metadata
        if (pendo.doesExist(options.account.id)) {
            pendo.set_account_id(options.account.id);
            options.account.id = pendo.get_account_id();
        }
    
        if (pendo.doesExist(options.visitor.id)) {
            pendo.identify(options.visitor.id, options.account.id);
        }
    
        options.visitor.id = pendo.get_visitor_id();
        options.visitor.language = getLocale();
    
        return {
            'visitor':       options.visitor,
            'account':       cleanupMetadata(options.account),
            'parentAccount': options.parentAccount,
            'date':          getDateForOptions(),
            'version':       pendo.VERSION
        };
    };
    
    var getDateForOptions = function() {
        var today = new Date();
        var dd = today.getDate();
        var mm = today.getMonth() + 1; //January is 0!
        var yyyy = today.getFullYear();
        if(dd < 10) {dd = '0' + dd;} if(mm < 10) {mm = '0' + mm;} today = dd + '/' + mm + '/' + yyyy;
        return today;
    };
    
    /*
     * Validates that the options object passed to be submitted
     * as meta data for the subscription is valid.  Valid in this
     * case means not empty or null.
     *
     * input: options (Object)
     * output: Boolean -- true means valid
     */
    var validateOptions = function(options) {
        return (options && pendo._.keys(options).length > 0);
    };
    
    /*
     * updateOptions is called after the user identifies for the
     * load of an app page.  This is called to submit the object
     * containing the meta data for this subscription.
     *
     * There are few extra dimensions to this method as it confirms validity
     * and newness of the object before submitting.
     *
     * input: options (Object)
     * output: --
     * side effect: event sent to server containing metadata information
     */
    var updateOptions = makeSafe(function(options) {
        if (!validateOptions(options)) {
            return;
        }
    
        if (options.jwt && options.signingKeyName) {
            var jwtOptions = JWT.getJwtOptions(options, 'updateOptions');
            if(jwtOptions) {
                setJwtInfo(_.pick(options, 'jwt', 'signingKeyName'));
                options = jwtOptions;
            }
        }
    
        options = prepareOptions(options);
    
        setUpdatedOptions(options);
    
        getMetadata = function() { return options; };
        pendo.getSerializedMetadata = function() { return JSON.parse(JSON.stringify(options)); };
    
        var hash = crc32(options);
    
        // Check to see if this Application is sending metadata to the backend using
        // different mechanism (like Segment webhooks)
        var blockAgentMetadata = isMetadataBlocked();
    
        if (haveOptionsChanged(hash) && !blockAgentMetadata) {
            agentStorage.write(OPTIONS_HASH_KEY_NAME, hash);
            lastSavedOptions = options;
            metadataHash = hash;
    
            collectEvent('meta', options);
    
            flushLater(); // unconditionally on next tick
    
            queueGuideReload();
        }
    });
    
    var isMetadataBlocked = function() {
        var blockAgentMetadata = getPendoConfigValue('blockAgentMetadata');
        return blockAgentMetadata !== undefined ? blockAgentMetadata : false;
    };
    
    // getMetadata - returns the metadata obj if one exists or nothing
    //
    // - Default impl is return nothing
    // - fn will be redefined if and when metadata options are
    // determined.
    var getMetadata = function() {};
    
    // remote window support for pendo agent
    
    pendo.loadResource = function(options, callback) {
        try {
            var script;
            var cssContentType = 'text/css';
            var javascriptContentType = 'text/javascript';
            if (_.isString(options)) {
                options = { 'url': options };
            }
            options.type = options.type || /\.css/.test(options.url) ? cssContentType : javascriptContentType;
            var target = null;
            var head = (document.getElementsByTagName('head')[0] ||
                    document.getElementsByTagName('body')[0]);
            if (options.type === cssContentType) {
                var link = document.createElement('link');
                link.type = cssContentType;
                link.rel = 'stylesheet';
                link.href = options.url;
                target = link;
            } else if (isSfdcLightning()) { // alternate script loading for SF Lightning
                script = document.createElement('script');
                script.addEventListener('load', function() {
                    callback();
                    removeNode(script);
                });
                script.type = javascriptContentType;
                script.src = options.url;
                document.body.appendChild(script);
                return {};
            } else { // Assume JS file.
                script = document.createElement('script');
                script.type = javascriptContentType;
                script.async = true;
                script.src = options.url;
                target = script;
            }
    
            head.appendChild(target);
            pendo.loadWatcher(target, options.url, callback);
    
            return target;
        } catch (e) {
            return {};
        }
    };
    
    pendo.loadWatcher = function(target, url, callback) {
        var isLoaded = false;
    
        if (!pendo.doesExist(callback)) return;
    
        target.onload = function() {
            if (isLoaded !== true) {
                isLoaded = true;
                callback(null, url);
            }
        };
    
        target.onerror = function() {
            pendo.tellMaster({
                'status':    'error',
                'msg':       'Failed to load script',
                'scriptURL': url
            });
        };
    
        target.onreadystatechange = function() {
            if (!isLoaded && (!target.readyState || target.readyState == 'loaded' || target.readyState == 'complete')) {
                isLoaded = true;
                callback(null, url);
            }
        };
    
        if (target.tagName.toLowerCase() === 'link') {
            var timeout = 500;
            setTimeout(function() {
                if (!isLoaded) {
                    //Fallback for old browsers that don't support onload for CSS links
                    //If this handler fires, the CSS link probably loaded just fine
                    var loader = new Image();
                    loader.onload = loader.onerror = function() {
                        if (isLoaded !== true) {
                            isLoaded = true;
                            callback(null, url);
                        }
                    };
                    loader.src = url;
                }
            }, timeout);
    
            setTimeout(function() {
                if (!isLoaded) {
                    //Log a warning if we fail to load the resource within 10 seconds
                    writeMessage('Failed to load ' + url + ' within 10 seconds');
                }
            }, 10000);
        }
    };
    
    pendo.messageLogger = function(event) {
        var data = JSON.parse(event.data);
        var origin = event.origin;
    
        debug(pendo.app_name + ': Message: ' + JSON.stringify(data) + ' from ' + origin);
        pendo.tellMaster(event.source, {'status': 'success', 'msg': 'ack', 'originator': 'messageLogger'}, origin);
    };
    
    pendo.messageReceiver = function(msg) {
        try {
            pendo.messageDispatcher(
                pendo.messageOriginTester(
                    pendo.messageValidator(msg)));
        } catch(e) {
            if (!/"type":"frame:/.test(msg.data)) { // don't log errors on the frame "channel"
                var errStr = 'Error receiving msg: ' + JSON.stringify(msg.data) + ', Exception: ' + e;
                pendo.log(errStr);
            }
        }
    };
    
    pendo.messageValidator = function(msg) {
        var data = msg.data;
        var origin = msg.origin;
        var source = msg.source;
    
        data = JSON.parse(data);
    
        if (!data.type || typeof data.type !== 'string') {
            throw new Error('Invalid Message: Missing \'type\' in data format');
        }
    
        return {'data': data, 'origin': origin, 'source': source};
    };
    
    function getTrustedOriginPattern(origins) {
        return new RegExp('^(' + _.chain(origins).unique().map(function(origin) {
            return origin.replace(/\./g, '\\.').replace(/^https?:/, 'https?:');
        }).value().join('|') + ')$');
    }
    
    var trustedOrigin = getTrustedOriginPattern([
        HOST,
        'https://demo.pendo-dev.com',
        // HOST and server are usually the same, unless custom CNAME is configured.
        // see https://github.com/pendo-io/pendo-appengine/issues/1440
        'https://app.pendo.io',
        'https?://([a-zA-Z0-9-]+-dot-)?pendo-(dev|test|io|' + ENV + ').appspot.com'
    ]);
    
    function isTrustedOrigin2(host) {
        if (!host) return true;
    
        // for CNAME, trust the top-level origin
        if(host === window.location.origin) return true;
    
        // Domains that Pendo owns
        var patterns = [
            /^https:\/\/(app|via|adopt)(\.eu|\.us)?\.pendo\.io$/,
            /^https:\/\/([0-9]{8}t[0-9]{4}-dot-)pendo-(io|eu)\.appspot\.com$/,
            /^https:\/\/hotfix-(ops|app)-([0-9]+-dot-)pendo-(io|eu)\.appspot\.com$/
        ];
    
        if (!_.contains(['prod', 'prod-eu'], ENV)) {
            patterns = patterns.concat([
                /^https:\/\/([a-zA-Z0-9-]+\.)*pendo-dev\.com$/,
                /^https:\/\/([a-zA-Z0-9-]+-dot-)?pendo-(dev|test|io|batman|magic|atlas|wildlings|ionchef|insert-dev|insert-test|mobile-guides|mobile-plat|mobile-analytics|eu|eu-dev|apollo|security)\.appspot\.com$/,
                /^https:\/\/via\.pendo\.local:\d{4}$/,
                /^https:\/\/adopt\.pendo\.local:\d{4}$/,
                /^https:\/\/local\.pendo\.io:\d{4}$/
            ]);
        }
    
        var adoptHost = getPendoConfigValue('adoptHost');
        if(adoptHost) {
            var fullHostname = 'https://' + adoptHost;
            // We can't make this a regex because its an arbitrary user input, so do a full string match
            if(host === fullHostname) return true;
        }
    
        return _.any(patterns, function(pattern) {
            return pattern.test(host);
        });
    }
    
    function messageOriginTester2(handler) {
        return function(msg) {
            if (!msg || !isTrustedOrigin2(msg.origin)) return;
            return handler.apply(this, arguments);
        };
    }
    
    pendo.messageOriginTester = function(msg) {
        if (trustedOrigin.test(msg.origin)) {
            return msg;
        }
        throw new Error('Received message from untrusted origin ' + msg.origin);
    };
    
    var designerWindow;
    pendo.onConnectMessage = function(data, msg) {
        if (isUnlocked()) {
            stopGuides();
            lockEvents();
    
            // We should continue to stop the FrameController for the p1 designer,
            // but for p2 we'll use it to help coordinate frames for tagging
            if(!pendo.designerv2.hostConfig) {
                FrameController.stop();
            }
    
            designerWindow = msg.source;
    
            window.onbeforeunload = function() {
                unlockEvents();
                removeDesignerFunctionality();
                pendo.tellMaster(msg.source, {'type': 'unload'}, '*');
            };
    
            if(_.isFunction(detachGuideEventHandlers)) {
                detachGuideEventHandlers();
            }
    
            addDesignerFunctionality();
    
            pendo.tellMaster(msg.source, {
                'status': 'success',
                'type':   'connect'
            }, '*');
    
            if (pendo.findModuleByName('selection.js')) {
                pendo.log('Designer Modules already loaded.');
                pendo.tellMaster({'type': 'ready'});
            }
        }
    };
    
    var onModuleMessage = function(data) {
        pendo.moduleLoader(data.moduleURL);
    };
    
    var onEnableDebug = function(data) {
        addSafeWindowMessageListener(pendo.messageLogger);
    };
    
    pendo.MESSAGE_TYPES = {
        'connect':    pendo.onConnectMessage,
        'disconnect': function(data) {},
        'module':     onModuleMessage,
        'debug':      onEnableDebug
    };
    
    var registerMessageHandler = function(messageType, handler) {
        pendo.tellMaster({'type': 'msg-type-available', 'msg-type': messageType});
        pendo.MESSAGE_TYPES[messageType] = handler;
    };
    
    pendo.messageDispatcher = function(msg) {
        var data = msg.data;
    
        if (pendo.doesExist(pendo.MESSAGE_TYPES[data.type])) {
            pendo.MESSAGE_TYPES[data.type](data, msg);
        }
    };
    
    // ---------------------------------------------------------------------------------
    
    pendo.moduleRegistry = {};
    pendo.addModule = function(key) {
        pendo.moduleRegistry[key] = {};
    
        /*global CKEDITOR*/
        if (typeof CKEDITOR !== 'undefined') {
            try {
                CKEDITOR.config.customConfig = '';
            } catch (e) {
    
            }
        }
    };
    pendo.hasModule = function(key) { return pendo.doesExist(pendo.moduleRegistry[key]); };
    pendo.findModuleByName = function(name) {
        if (!pendo.moduleRegistry) {
            return null;
        }
    
        var checkKeyForName = function(key, name) {
            return key.indexOf(name) >= 0;
        };
    
        for (var key in pendo.moduleRegistry) {
            if (checkKeyForName(key, name)) return key;
        }
    
        return null;
    };
    
    pendo.modulesWaiting = [];
    pendo.loadModules = function() {
        if (pendo.modulesWaiting.length < 1) {
            return;
        }
    
        var mod = pendo.modulesWaiting.shift();
        if (pendo.hasModule(mod)) {
            return;
        }
    
        pendo.loadResource(mod, function() {
            pendo.addModule(mod);
            pendo.loadModules();
        });
    };
    pendo.moduleLoader = function(moduleURL) {
        pendo.modulesWaiting.push(moduleURL);
    
        if (pendo.modulesWaiting.length > 1) {
            return;
        }
    
        pendo.loadModules();
    };
    
    // ---------------------------------------------------------------------------------
    
    var tellMaster = function(source, msg, origin) {
        var guid = _.uniqueId('pendo-');
        try {
            if (typeof msg === 'undefined' && typeof origin === 'undefined') {
                msg = source;
                source = designerWindow || getDesignerWindow();
                origin = '*';
            }
            // add uniq id to messages
            msg.guid = guid;
            if (source && _.isFunction(source.postMessage)) {
                var jsonMsg = JSON.stringify(msg);
                source.postMessage(jsonMsg, origin);
            }
        } catch (e) {
            var message = (e && e.message) || '';
            log('Failed to postMessage: ' + message);
        }
        return guid;
    };
    
    // ---------------------------------------------------------------------------------
    
    // TODO: build a List of functions to run at start up instead of one
    // big init method then each concat'd file can contribute to what gets
    // run at start independently.
    
    var detectMaster = function() {
        return window != window.top; // yes, use != instead of !== for IE8 and friends
    };
    
    var getDesignerWindow = function() {
        var isPendo = new RegExp('^' + HOST.replace(/^https?:/, 'https?:'));
        //If the agent is running in a Pendo app instance, talk to the
        //parent window to enable "inception mode", otherwise talk
        //directly to the top window.
        return isPendo.test(location.href) ? window.parent : window.top;
    };
    
    var announceAgentLoaded = function() {
        if (detectMaster()) {
            var win = getDesignerWindow();
            pendo.tellMaster(win, {'type': 'load', 'url': location.toString()}, '*');
        }
    };
    
    var listenToMaster = function() {
        pendo.app_name = document.title;
        if (detectMaster()) {
            pendo.log(pendo.app_name + ': listening to messages');
    
            if (pendo.doesExist(window.addEventListener)) {
                window.addEventListener('message', pendo.messageReceiver, false);
            }
        }
    
        if (window.opener && pendo.doesExist(window.addEventListener)) {
            addSafeWindowMessageListener(launchPreviewListener);
            addSafeWindowMessageListener(launchDesignerListener);
            window.opener.postMessage({ 'type': 'pendo::ready' }, '*');
        }
    };
    
    var addSafeWindowMessageListener = function(cb) {
        if(pendo.doesExist(window.addEventListener) && _.isFunction(window.addEventListener)) {
            window.addEventListener('message', messageOriginTester2(cb), false);
        }
    };
    
    var isBrowserInQuirksmode = function() {
        // we don't care about this except for IE
        if (isNaN(msie)) return false;
        if (msie == 11) return false;
        return document.compatMode !== 'CSS1Compat';
    };
    
    var buildArrowDimensionsQM = function(dim, elementPos) {
    
        var height = dim.height,
            width = dim.width;
    
        if (dim.arrowPosition == 'top' || dim.arrowPosition == 'bottom') {
            var TOOLTIP_ARROW_OFFSET = 10;
            var adjustment = 0;
    
            if (dim.arrowPosition == 'top') {
                dim.top = elementPos.top + elementPos.height;
                adjustment = -1;
    
                dim.arrow.top = 3;
    
                if (msie <= 9) {
                    dim.arrow.top = 6;
                }
    
            } else if (dim.arrowPosition == 'bottom') {
                dim.top = elementPos.top - (height + pendo.TOOLTIP_ARROW_SIZE);
                dim.arrow.top = height - pendo.TOOLTIP_ARROW_SIZE;
    
                if (msie == 10)
                    {dim.arrow.top--;}
                else if (msie <= 9)
                    {dim.arrow.top += 4;}
    
                adjustment = 1;
            }
    
            if(dim.arrow.hbias == 'left') {
                dim.left = elementPos.left + (elementPos.width / 2) - (TOOLTIP_ARROW_OFFSET + (2 * pendo.TOOLTIP_ARROW_SIZE)); 
                dim.arrow.left = TOOLTIP_ARROW_OFFSET + pendo.TOOLTIP_ARROW_SIZE;
            } else if(dim.arrow.hbias == 'right') {
                dim.left = elementPos.left - width + (elementPos.width / 2) + (TOOLTIP_ARROW_OFFSET + (2 * pendo.TOOLTIP_ARROW_SIZE));
                dim.arrow.left = width - (3 * pendo.TOOLTIP_ARROW_SIZE) - TOOLTIP_ARROW_OFFSET;
            } else {
                // ASSUME CENTER
                dim.left = elementPos.left + (elementPos.width / 2) - (width / 2);
                dim.arrow.left = (width / 2) - pendo.TOOLTIP_ARROW_SIZE;
            }
    
            dim.arrow.border.top  = dim.arrow.top + adjustment;
            dim.arrow.border.left = dim.arrow.left;
    
            return dim;
        }
    
        // else left or right
    
        if (dim.arrow.hbias == 'left') {
            dim.left = elementPos.left + elementPos.width;
            dim.arrow.left = 1;
            dim.arrow.left += 5;
            dim.arrow.border.left = dim.arrow.left - 1;
        } else if (dim.arrow.hbias == 'right') {
    
            // this keeps the guide visible.
            dim.left = Math.max(0, elementPos.left - width - pendo.TOOLTIP_ARROW_SIZE);
            dim.arrow.left = width - pendo.TOOLTIP_ARROW_SIZE - 1;
            dim.arrow.left += 5;
            dim.arrow.border.left = dim.arrow.left + 1;
        }
    
        dim.top = elementPos.top + (elementPos.height / 2) - (height / 2);
        dim.arrow.top = (height / 2) - pendo.TOOLTIP_ARROW_SIZE; 
        dim.arrow.border.top  = dim.arrow.top;
    
        return dim;
    };
    
    function Wrappable() {
    
        var wrappers = {};
    
        var wrap = function(wrappedMethod, before, after) {
            return function() {
                var args = _.toArray(arguments);
                var i, ii;
    
                //Apply befores
                for (i = 0, ii = before.length; i < ii; ++i) {
                    if (before[i].apply(this, args) === false) {
                        return;
                    }
                }
    
                //Execute original
                var result = wrappedMethod.apply(this, args);
    
                //Apply afters
                for (i = 0, ii = after.length; i < ii; ++i) {
                    if (after[i].apply(this, args) === false) {
                        break;
                    }
                }
    
                return result;
            };
        };
    
        _.each(['after', 'before'], function(when) {
            this[when] = function(methodName, wrapper) {
                if (this[methodName]) {
                    var pipeline = wrappers[methodName];
                    if (!pipeline) {
                        pipeline = wrappers[methodName] = { 'before': [], 'after': [] };
                        this[methodName] = wrap(this[methodName], pipeline.before, pipeline.after);
                    }
                    pipeline[when].push(wrapper);
                }
            };
        }, this);
    
        return this;
    }
    
    var xhrEventCache = [];
    var xhrEventQueue = createXhrEventQueue({
        'cache':   xhrEventCache,
        'apiKey':  function() { return pendo.apiKey; },
        'beacon':  'xhr',
        'shorten': {
            'fields':        ['request_url', 'browser_url'],
            'siloMaxLength': ENCODED_EVENT_MAX_LENGTH
        }
    });
    
    function filterPendoAgentXhrRequests(xhrEvent, next) {
        var hostRegex = HOST.replace(/\./g, '\\.').replace(/\//g, '\\/');
        var isPendoAgentUrl = new RegExp('^' + hostRegex + '\\/data\\/');
        var requestUrl = get(xhrEvent, 'request_url', '');
        if (!isPendoAgentUrl.test(requestUrl)) {
            next(xhrEvent);
        }
    }
    
    function createXhrEventQueue(options) {
        var cache = options.cache;
        var send = createSendQueue(options, defaultSendEvent);
        var guaranteedSend = createSendQueue(options, reliableSendEventForUnload);
        var enqueue = pipeline(
            filterPendoAgentXhrRequests,
            siloReducer(cache),
            filterSiloLength,
            send
        );
    
        return {
            'push': function push(event) {
                enqueue(event, _.noop);
            },
            'clear': function clear() {
                cache.length = 0;
            },
            'flush': function flush(flushOptions) {
                if (cache.length === 0) return;
                var silo = cache.slice();
                cache.length = 0;
                var sendFunction = (flushOptions || {}).guaranteed ? guaranteedSend : send;
                sendFunction(silo, _.noop);
            }
        };
    }
    
    var openXhrIntercept = function() {
        attachEvent(window, 'unload', function() {
            flushXhrNow({ 'guaranteed': true });
        });
        (function(open) {
            XMLHttpRequest.prototype.open = function(method, url, async, user, pass) {
                var xhrData = {};
                this.addEventListener('readystatechange', function() {
                    var curEventInfo = arguments[0].target || arguments[0].srcElement || arguments[0].currentTarget;
                    modifyXhrData(xhrData, this.readyState, url, method, curEventInfo);
                }, false);
    
                open.apply(this, arguments);
            };
        })(XMLHttpRequest.prototype.open);
    };
    
    var modifyXhrData = function(xhrData, readyState, url, method, curEventInfo) {
        if (readyState === 1) {
            var vid = pendo.get_visitor_id();
            xhrData.visitor_id = vid;
    
            var aid = pendo.get_account_id();
            xhrData.account_id = aid;
            xhrData.browser_url = getScrubbedXhrUrl(pendo.url.getWindowLocation().href);
            xhrData.browser_time = new Date().getTime();
            xhrData.request_method = method;
            xhrData.type = 'xhr';
        } else if (readyState === 4) {
            xhrData.request_url = getScrubbedXhrUrl(curEventInfo.responseURL);
            xhrData.response_status = curEventInfo.status;
            xhrData.duration = new Date().getTime() - xhrData.browser_time;
            xhrEventQueue.push(xhrData);
        }
    };
    
    var getScrubbedXhrUrl = function(initialUrl) {
        var curParamsIndex = initialUrl ? initialUrl.indexOf('?') : -1;
        var curParams = (curParamsIndex === -1) ? '' : initialUrl.slice((curParamsIndex + 1), initialUrl.length);
        return externalizeURL(initialUrl, curParams, getPendoConfigValue('xhrWhitelist'));
    };
    
    var flushXhrNow = function(options) {
        try {
            xhrEventQueue.flush(options);
        } catch (e) {
            writeException(e, 'error while flushing xhr cache');
        }
    };
    
    /*
    * Config `allowedText` is expected to be an Array<String> or not set.
    * It can be provided either by local, snippet based declaration or as a Pendo server appendage.
    * If provided by both, local wins.
    */
    
    var TextCapture = (function() {
        var ALLOWED_TEXT = 'allowedText';
        var EXCLUDE_ALL_TEXT = 'excludeAllText';
        var whitelist = {}; // intended to be used as a HashSet<String>
    
        return {
            'initialize':       init,
            'isEnabled':        isEnabled,
            'isTextCapturable': isTextCapturable,
            'hasWhitelist':     hasWhitelist
        };
    
        // technically not idempotent but might actually be right. not sure.
        function init() {
            pendo.excludeAllText = ConfigReader.get(EXCLUDE_ALL_TEXT);
            var allowedText = ConfigReader.get(ALLOWED_TEXT);
    
            // we want to take an array of strings and convert them to a HashSet<String> along with sanitizing them as we go
            // ['key'] => {'key':true}
            whitelist = _.reduce(allowedText, function(acc, value) {
                if (!_.isString(value)) {
                    return acc;
                }
                acc[value] = true;
                return acc;
            }, {});
        }
    
        function isEnabled() {
            // this preserves the ability for a user to disable text collection after initialization
            return !pendo.excludeAllText;
        }
    
        function isTextCapturable(text) {
            return isEnabled() || _.has(whitelist, text);
        }
    
        function hasWhitelist() {
            return _.size(whitelist) > 0;
        }
    })();
    
    var AutoDisplay = (function() {
        var iterator = throttleIterator(50, createStatefulIterator(function(guide) {
            return guide.id;
        }));
    
        return {
            'reset':                  reset,
            'canDisplay':             canDisplay,
            'display':                display,
            'lastDismissedTime':      lastDismissedTime,
            'sortAndFilter':          sortAndFilter,
            'tryDisplay':             tryDisplay,
            'getNextAutoDisplayTime': getNextAutoDisplayTime,
            'iterator':               iterator
        };
    
        function reset() {
            iterator.reset();
        }
    
        function isAuto(guide) {
            return guide && /auto/.test(guide.launchMethod);
        }
    
        function isOverride(guide) {
            return (guide.attributes && guide.attributes.overrideAutoThrottling);
        }
    
        /**
         * @param {Guide[]} in intended sort order
         * @return {Map<'override'|'auto':Guide[]>}
         */
        function seperateAutoAndOverride(orderedGuides) {
            return _.defaults(_.groupBy(orderedGuides, function(guide) {
                return (isOverride(guide)
                    ? 'override'
                    : 'auto');
            }), { 'override': [ ], 'auto': [ ] });
        }
    
        /**
         * Apply {ordering} -- a sorted list of guide IDs -- to {guides}, unless
         * no such sorting order has been defined.
         *
         * @param {Guide[]} guides
         * @param {string[]} ordering of {Guide.id}
         * @return {Guide[]}
         */
        function applyOrdering(guides, ordering) {
            // No `ordering` was supplied: {guides} are ordered
            if (!_.isArray(ordering) || !ordering.length) return guides;
    
            var lookup = _.indexBy(guides, 'id');
    
            // initialize {ordered} from {ordering} _first_...
            var ordered = _.reduce(ordering, collectFromLookup, [ ]);
    
            // collect whatever is left...
            return _.chain(guides).pluck('id')
                .reduce(collectFromLookup, ordered)
            .value();
    
            function collectFromLookup(collection, id) {
                if (!lookup[id]) return collection;
    
                collection.push(lookup[id]);
    
                delete lookup[id]; // to prevent duplicate lookups
    
                return collection;
            }
        }
    
        /**
         * Extract automatic guides from {guidesList} with {isAuto}, sort them
         * according to the supplied {ordering}, and group via {isOverride} into
         * "override" vs "auto" (regular).
         *
         * @return {Map<"override"|"auto":Guide[]>}
         */
        function sortAndFilter(guidesList, ordering) {
            return seperateAutoAndOverride(applyOrdering(_.filter(guidesList, isAuto), ordering));
        }
    
        function lastDismissedTime(pendo) {
            return Math.max(
                pendo.latestDismissedAutoAt || -Infinity,
                pendo.finalAdvancedAutoAt || -Infinity
            );
        }
    
        function addCalendarDays(timestamp, days) {
            var date = new Date(Math.max(timestamp, 0));
            date.setHours(0, 0, 0, 0);
            date.setDate(date.getDate() + days);
            return date.getTime();
        }
    
        function getNextAutoDisplayTime(latestDismissedAutoAt, throttlingSettings) {
            var interval = throttlingSettings.interval;
            var unit = (throttlingSettings.unit || '').toLowerCase();
    
            if (_.isNumber(interval) && isFinite(latestDismissedAutoAt)) {
                if (unit === 'minute') {
                    return interval * 60000 + latestDismissedAutoAt + 1;
                } else if (unit === 'hour') {
                    return interval * 3600000 + latestDismissedAutoAt + 1;
                } else if (unit === 'day') {
                    return addCalendarDays(latestDismissedAutoAt, interval);
                }
            } else if (_.isNumber(interval)) {
                return new Date().getTime();
            }
        }
    
        function canDisplay(time, latestDismissedAutoAt, throttlingSettings) {
            if (throttlingSettings && throttlingSettings.enabled) {
                var nextAutoDisplayTime = getNextAutoDisplayTime(latestDismissedAutoAt, throttlingSettings);
                if (_.isNumber(nextAutoDisplayTime) && !isNaN(nextAutoDisplayTime)) {
                    return time >= nextAutoDisplayTime;
                }
            }
    
            return true;
        }
    
        function display(autoDisplayGuides) {
            var displayedGuide;
            iterator.eachUntil(autoDisplayGuides, function(guide) {
                if (guide.shouldAutoDisplay()) {
                    guide.autoDisplay();
                }
                if (guide.isShown()) {
                    displayedGuide = guide;
                    return true;
                }
            });
            return displayedGuide;
        }
    
        function tryDisplay(guidesList, pendo) {
            var latestDismissedAutoAt = AutoDisplay.lastDismissedTime(pendo);
            var autoDisplayGuides = AutoDisplay.sortAndFilter(guidesList, pendo.autoOrdering);
            var displayedGuide = AutoDisplay.display(autoDisplayGuides.override);
            if (!displayedGuide && AutoDisplay.canDisplay(getNow(), latestDismissedAutoAt, pendo.throttling)) {
                displayedGuide = AutoDisplay.display(autoDisplayGuides.auto);
            }
            return displayedGuide;
        }
    })();
    
    var Permalink = (function() {
        return {
            'tryDisplay':               tryDisplay,
            'getGuideFromUrl':          getGuideFromUrl,
            'showPermalinkGuide':       showPermalinkGuide,
            'shouldShowPermalinkGuide': shouldShowPermalinkGuide
        };
    
        function getGuideFromUrl(pendo) {
            var url = pendo.url.get();
            var queryString = {};
            // from https://stevenbenner.com/2010/03/javascript-regex-trick-parse-a-query-string-into-an-object/
            url.replace(
                new RegExp('([^?=&]+)(=([^&#]*))?', 'g'),
                function($0, $1, $2, $3) { queryString[$1] = $3; }
            );
    
            var guideId =  queryString.pendo;
            return guideId ? pendo.findGuideById(guideId) : null;
        }
    
        function showPermalinkGuide(guide, pendo) {
            pendo.showGuideById(guide.id);
            guide.shownFromPermalink = true;
        }
    
        function shouldShowPermalinkGuide(guide) {
            return !guide.shownFromPermalink;
        }
    
        function tryDisplay(pendo) {
            var permalinkGuide = Permalink.getGuideFromUrl(pendo);
            if(permalinkGuide && Permalink.shouldShowPermalinkGuide(permalinkGuide)) {
                Permalink.showPermalinkGuide(permalinkGuide, pendo);
                return true;
            }
            return false;
        }
    })();
    
    function RemoteFrameGuide() {
        this.shouldBeAddedToLauncher = _.wrap(this.shouldBeAddedToLauncher, function(fn) {
            return _.any(FrameController.getState(this), function(state) {
                return state.shouldBeAddedToLauncher;
            }) || fn.apply(this, arguments);
        });
    
        this.shouldBeAddedToResourceCenter = _.wrap(this.shouldBeAddedToResourceCenter, function(fn) {
            return _.any(FrameController.getState(this), function(state) {
                return state.shouldBeAddedToResourceCenter;
            }) || fn.apply(this, arguments);
        });
    
        return this;
    }
    
    function RemoteFrameStep(guide) {
        var step = this;
    
        if (step.type === 'whatsnew') {
            return step;
        }
    
        step.isShown = (function(isShown) {
            return function() {
                return isShown.apply(this, arguments) || FrameController.isShownInAnotherFrame(step);
            };
        })(step.isShown);
    
        step.before('show', function(reason) {
            if (FrameController.hasFrames() && !FrameController.isInThisFrame(guide)) {
                // This guide isn't in this frame at all, try the others
                showInAnotherFrame(reason);
                return false;
            }
        });
    
        step.after('show', function(reason) {
            if (!step.isShown() && FrameController.hasFrames() && FrameController.isInAnotherFrame(guide)) {
                // We tried to show in this frame, but it didn't work out... try some others
                showInAnotherFrame(reason);
            }
            if (step.isShown()) {
                FrameController.shown(step);
            }
        });
    
        step.after('hide', function(hideOptions) {
            unlock();
            if (!hideOptions || !hideOptions.onlyThisFrame) {
                FrameController.hide(step, hideOptions);
            }
        });
    
        function showInAnotherFrame(reason) {
            step.lock();
            FrameController.show(step, reason).then(unlock, unlock);
        }
    
        function unlock() {
            step.unlock();
        }
    
        return step;
    }
    
    var ContentLoader = (function(pendo) {
        pendo.guideContent = guideContent;
        pendo.receiveDomStructureJson = receiveDomStructureJson;
        var cache = {};
    
        /**
         * @typedef {Object} ContentRequest
         * @param {String} id uniquely identifies the container
         * @param {String} contentUrl
         * @param {String} contentUrlCss
         * @param {String} contentUrlJs
         */
    
        /**
         * @typedef {Object} ContentEntry
         * @param {string} content The raw content as a string
         * @param {Function} template The template function compiled from the raw content
         * @param {Function} script The javascript to execute
         */
    
        /**
         * Loads the content for the given container
         * @param  {ContentRequest} contentContainer
         * @return {Promise.<ContentEntry>} Resolved when all of the content is loaded
         */
        function load(contentContainer) {
            var cacheEntry = cache[contentContainer.id];
    
            if(cacheEntry && cacheEntry.language !== contentContainer.language) {
                delete cache[contentContainer.id];
            }
    
            if (!cache[contentContainer.id]) {
                var promises = [];
                var entry = {
                    'deferred': {},
                    'language': contentContainer.language
                };
                var fetchedDomContent = false;
                cache[contentContainer.id] = entry;
    
                if (GuideLoader.usesXhr() && contentContainer.domUrl) {
                    entry.deferred.domJson = q.defer();
                    pendo.ajax.get(replaceWithContentHost(contentContainer.domUrl)).then(function(result) {
                        entry.domJson = result.data;
                        entry.deferred.domJson.resolve();
                    });
                    promises.push(entry.deferred.domJson.promise);
                    fetchedDomContent = true;
                } else if (contentContainer.domJsonpUrl) {
                    entry.deferred.domJson = q.defer();
                    var jsonpNode = pendo.loadResource(replaceWithContentHost(contentContainer.domJsonpUrl), function() {
                        dom.removeNode(jsonpNode);
                    });
                    promises.push(entry.deferred.domJson.promise);
                    fetchedDomContent = true;
                }
    
                if (contentContainer.contentUrlJs && !getPendoConfigValue('preventCodeInjection')) {
                    // Content, template, and script for 2.1+ agents
                    entry.deferred.content = q.defer();
                    var scriptNode = pendo.loadResource(replaceWithContentHost(lightningRedirect(contentContainer.contentUrlJs)), function() {
                        dom.removeNode(scriptNode);
                    });
                    promises.push(entry.deferred.content.promise);
    
                    // Style
                    if (contentContainer.contentUrlCss) {
                        entry.deferred.css = q.defer();
                        pendo.loadResource({ 'url': replaceWithContentHost(contentContainer.contentUrlCss), 'type': 'text/css' }, function() {
                            entry.deferred.css.resolve();
                        });
                        promises.push(entry.deferred.css.promise);
                    }
                } else if (contentContainer.contentUrl && !getPendoConfigValue('preventCodeInjection')) {
                    // Content with inlined script and css (2.0.x agents, or guides that have not migrated to the 2.1 format yet)
                    entry.deferred.content = q.defer();
                    var contentNode = pendo.loadResource(replaceWithContentHost(contentContainer.contentUrl) + '.js', function() {
                        dom.removeNode(contentNode);
                    });
                    promises.push(entry.deferred.content.promise);
                } else if (!fetchedDomContent) {
                    return q.reject();
                }
    
                entry.deferred.promise = q.all(promises).then(function() {
                    return _.omit(entry, 'deferred');
                });
            }
    
            return cache[contentContainer.id].deferred.promise;
        }
    
        /**
         * Clears the content cache. Used for testing.
         */
        function reset() {
            cache = {};
        }
    
        /**
         * JSONP-style callback for loading guide content
         * from script resources. Step content stored in
         * GCS is wrapped with pendo.guideContent(...)
         * @param {String} guideId
         * @param {String} stepId
         * @param {String} content
         * @param {Function} templateFn
         * @param {Function} scriptFn
         */
        function guideContent(guideId, stepId, content, templateFn, scriptFn) {
            if (_.isString(content)) {
                if (!_.isFunction(templateFn)) {
                    templateFn = _.template(content);
                }
                var entry = cache[guideId + stepId];
                if (entry && entry.deferred.content) {
                    entry.content = content;
                    entry.template = templateFn;
                    entry.script = scriptFn;
                    entry.deferred.content.resolve();
                }
            }
        }
    
        function receiveDomStructureJson(guideId, stepId, domJson) {
            var entry = cache[guideId + stepId];
    
            if (entry && entry.deferred.domJson) {
                entry.domJson = domJson;
                entry.deferred.domJson.resolve();
            }
        }
    
        function lightningRedirect(url) {
            if (isSfdcLightning()) {
                // https://pendo-static-1234.storage.googleapis.com/guide-content/:guideId/:stepId/:someKindaHash.guide.js
                var path = url.replace(/^https?:\/\/[^/]+\/guide-content\//, '').split('/');
                var guideId = path[0];
                var resourcePath = $A.get('$Resource.pendoGuide' + base32Encode(pendo.toUTF8Array(guideId)));
                if (_.isString(resourcePath)) {
                    return resourcePath + '/' + path.join('/');
                }
            }
            return url;
        }
    
        return {
            'load':  load,
            'reset': reset
        };
    })(pendo);
    
    var ContentVerifier = (function() {
        var cache = {
            'failed':   {},
            'verified': {}
        };
    
        return {
            'verify': ifVerificationEnabled(
                applyCache(
                    cache,
                    logFailures(writeErrorPOST, verify)
                )
            ),
            'reset': reset
        };
    
        function verify(contentContainer) {
            var promises = [];
            if (!GuideLoader.usesXhr() && contentContainer.domJsonpUrl) {
                promises.push(verifyContentHash(contentContainer, 'domJsonpUrl'));
            } else if (GuideLoader.usesXhr() && contentContainer.domUrl) {
                promises.push(verifyContentHash(contentContainer, 'domUrl'));
            }
    
            if (contentContainer.contentUrlJs) {
                promises.push(verifyContentHash(contentContainer, 'contentUrlJs'));
            } else if (contentContainer.contentUrl) {
                promises.push(verifyContentHash(contentContainer, 'contentUrl'));
            }
    
            return q.all(promises);
        }
    
        function ifVerificationEnabled(nextVerify) {
            var configKey = 'guideValidation';
            return function verifyIfEnabled(contentContainer) {
                if (!getPendoConfigValue(configKey) && !getOption(configKey)) return q.resolve();
                return nextVerify(contentContainer);
            };
        }
    
        function applyCache(cache, nextVerify) {
            return function verifyWithCache(contentContainer) {
                if (cache.failed[contentContainer.id]) return q.reject();
                if (cache.verified[contentContainer.id]) return q.resolve();
                return nextVerify(contentContainer).then(function() {
                    cache.verified[contentContainer.id] = true;
                }, function(error) {
                    cache.failed[contentContainer.id] = true;
                    return q.reject(error);
                });
            };
        }
    
        function logFailures(log, nextVerify) {
            return function verifyWithLogging(contentContainer) {
                return nextVerify(contentContainer).then(_.noop, function(error) {
                    if (/verify/.test(error)) log(error);
                    return q.reject(error);
                });
            };
        }
    
        function verifyContentHash(contentContainer, urlProp) {
            var url = contentContainer[urlProp];
            if (!_.isString(url)) return q.reject('unable to parse "' + url + '"');
    
            var stepHash = computeStepHash(contentContainer, urlProp);
            return pendo.ajax.get(url).then(function(response) {
                if (computeHashFromFile(response.data) === stepHash) return;
                return q.reject('Unable to verify content at "' + url + '"');
            });
        }
    
        function computeStepHash(contentContainer, urlProp) {
            var propMap = { 'domUrl': 'domHash', 'domJsonpUrl': 'domJsonpHash' };
            var prop = propMap[urlProp];
    
            return contentContainer[prop] || getHashFromContentUrl(contentContainer[urlProp]);
        }
    
        function computeHashFromFile(str) {
            if (typeof str === 'object') {
                str = JSON.stringify(str);
            }
    
            var hashBuilder = sha1.create();
            hashBuilder.update(str);
            return pendo.fromByteArray(hashBuilder.digest());
        }
    
        function reset() {
            cache.failed = {};
            cache.verified = {};
        }
    })();
    
    
    /**
     * @description
     * A tooltip guide step
     */
    function Tooltip(guide) {
        if (this.type === 'tooltip') {
            var step = this;
    
            //Set default attributes
            step.attributes.height = step.attributes.height || pendo.TOOLTIP_DEFAULT_HEIGHT;
            step.attributes.width = step.attributes.width || pendo.TOOLTIP_DEFAULT_WIDTH;
            step.attributes.layoutDir = step.attributes.layoutDir || 'DEFAULT';
    
            this.getTriggers = function(stepOnly) {
                var step = this;
                var guide = step.getGuide();
                var element = step.element || getElementForGuideStep(step);
    
                if (!element && !!stepOnly) return [];
    
                var advanceMethod = step.advanceMethod || '';
    
                var methods = advanceMethod.split(',');
    
                this.triggers = _.map(methods, function(method) {
                    return new AdvanceTrigger(element, method, step);
                });
    
                // get the remaining triggers for this Section
                if (!stepOnly && guide && guide.isMultiStep && currentMode == OBM) {
                    var section = guide.findSectionForStep(step);
                    var rem = guide.getSubSection(section, step);
                    this.triggers = this.triggers.concat(
                        _.flatten(
                            _.map(rem, function(step) {
                                if (!step.getTriggers) return [];
                                return step.getTriggers(true);
                            })
                        )
                    );
                }
    
                return this.triggers;
            };
    
            this.removeTrigger = function(trigger) {
                this.triggers = _.without(this.triggers, trigger);
                if (this.triggers.length === 0) this.triggers = null;
            };
    
            this.canShow = function() {
                if (isDismissedUntilReload(step)) {
                    return false;
                }
                return !step.isShown() &&
                    step.canShowOnPage(pendo.getCurrentUrl()) &&
                    canTooltipStepBeShown(step);
            };
    
            this.after('render', function() {
                var step = this;
    
                if (showTooltipGuide(step, step.elements)) {
    
                    var element = step.element;
                    _.each(step.getTriggers(), function(trigger) {
                        trigger.add();
                    });
    
                    // attach scroll handlers
                    var overflowScroll = /(auto|scroll)/,
                        scrollParent = getScrollParent(element, overflowScroll),
                        pbody = getBody();
                    while (scrollParent && scrollParent !== pbody) {
                        step.attachEvent(scrollParent, 'scroll',
                            _.throttle(_.bind(step.onscroll, step, scrollParent, overflowScroll), 10));
                        scrollParent = getScrollParent(scrollParent, overflowScroll);
                    }
                }
            });
    
            this.reposition = function() {
                var step = this,
                    width = step.attributes.width,
                    height = step.attributes.height,
                    layoutDir = step.attributes.layoutDir,
                    guideElement = step.guideElement,
                    containerElement = dom('._pendo-guide-container_', guideElement),
                    elementPos = getOffsetPosition(step.element),
                    dim = getTooltipDimensions(elementPos, height, width, layoutDir);
    
                //Reset the position class on the container
                containerElement.removeClass('top right bottom left')
                    .removeClass('_pendo-guide-container-top_ _pendo-guide-container-right_ _pendo-guide-container-bottom_ _pendo-guide-container-left_')
                    .addClass(dim.arrowPosition)
                    .addClass('_pendo-guide-container-' + dim.arrowPosition + '_');
    
                //Re-render the arrow
                dom('._pendo-guide-arrow_,._pendo-guide-arrow-border_', guideElement).remove();
                buildAndAppendArrow(guideElement, dim);
    
                // Reposition the guide
                guideElement.css({
                    'top':      dim.top,
                    'left':     dim.left,
                    'height':   dim.height,
                    'width':    dim.width,
                    'position': elementPos.fixed ? 'fixed' : ''
                });
    
                step.dim = dim;
            };
    
            this.onscroll = function(scrollParent, overflowPattern) {
                var step = this,
                    elementRect = getClientRect(step.element),
                    dim = step.dim;
                if (isVisibleInScrollParent(elementRect, scrollParent, overflowPattern)) {
                    dim = getTooltipDimensions(elementRect,
                        step.attributes.height,
                        step.attributes.width,
                        dim.arrowPosition);
                    setStyle(step.elements[0], 'display:block;top:' + dim.top + 'px;left:' + dim.left + 'px');
                    step.dim = dim;
                } else {
                    //Hide if element is scrolled out of view
                    setStyle(step.elements[0], 'display:none');
                }
            };
    
            this.teardownElementEvent = function() {
                _.each(this.triggers, function(trigger) {
                    trigger.remove();
                });
            };
    
            this.after('hide', function() {
                // clean up from block
                dom('._pendo-guide-tt-region-block_').remove();
                lastBlockBox = null;
                lastBodySize = null;
                lastScreenCoords = null;
            });
        }
    
        return this;
    }
    
    
    /**
     * @description
     * A lightbox guide step
     */
    function Lightbox() {
        var step = this;
    
        if (/lightbox/i.test(step.type)) {
            //Set default attributes
            step.attributes.height = step.attributes.height || pendo.LB_DEFAULT_HEIGHT;
            step.attributes.width = step.attributes.width || pendo.LB_DEFAULT_WIDTH;
    
            step.after('render', function() {
                if (isMobileUserAgent()) {
                    showMobileLightboxGuide(step, step.elements);
                } else {
                    showLightboxGuide(step, step.elements);
                }
            });
    
            step.reposition = function() {
                if (!isMobileUserAgent()) {
                    step.guideElement.css({
                        'margin-left': -Math.floor((step.attributes.width / 2)),
                        'margin-top':  -Math.floor((step.attributes.height / 2))
                    });
                }
            };
        }
    
        return step;
    }
    
    var BANNER_DEFAULT_HEIGHT = 500;
    var BANNER_CSS_NAME = '_pendo-guide-banner_';
    
    /**
     * @description
     * A banner guide step
     */
    function Banner() {
        var step = this;
    
        if (step.type === 'banner') {
            //Set default attributes
            step.attributes.height = step.attributes.height || BANNER_DEFAULT_HEIGHT;
            step.attributes.position = step.attributes.position || 'top';
    
            step.after('render', function() {
                var guideElement = step.guideElement,
                    arrowSize = pendo.TOOLTIP_ARROW_SIZE;
    
                guideElement.css({ 'width': '' })
                    .addClass(BANNER_CSS_NAME)
                    .addClass('_pendo-guide-banner-' + step.attributes.position + '_');
    
                if (!isPreviewing()) {
                    guideElement.addClass('_pendo-in_');
                }
    
                dom('._pendo-guide-container_', guideElement).css({
                    'bottom': arrowSize,
                    'right':  arrowSize
                });
    
                step.element = getElementForGuideStep(step);
                step.elements.push(guideElement[0]);
                guideElement.appendTo(getGuideAttachPoint());
            });
        }
    
        return step;
    }
    
    function WhatsNew(guide) {
        var step = this;
        var type = 'whatsnew';
        var seenClass = '_pendo-guide-whatsnew-seen_';
        var active = 'active';
        var defaultSeenDelay = 1000;
    
        if (step.type === type) {
            _.extend(step, {
                // What's new guides are special, they're always "shown", just in the launcher.
                // However, we need the rest of the guide system to consider them *not* shown
                'isShown': _.constant(false),
                // Never launch what's new guides
                'launch':  noop,
                // Tracking seenState works differently for whatsnew guides
                'onShown': noop,
                'render':  render,
                'seen':    seen
            });
    
            _.extend(guide, {
                'addToLauncher': addToLauncher,
                'isReady':       isReady
            });
    
            step.after('show', seen);
        }
    
        return step;
    
        function isReady() {
            return !!step.guideElement;
        }
    
        function addToLauncher() {
            var guideElement = step.guideElement;
            if (guideElement && !isInDocument(guideElement[0])) {
                dom('._pendo-launcher_ #launcher-' + step.guideId).html('').append(guideElement);
    
                if (_.isFunction(step.script)) {
                    step.script(step, guide);
                }
            }
        }
    
        function render() {
            var guideElement = step.guideElement;
            var height = step.attributes.height;
    
            /*
            IE will sometimes "empty out" the guideElement, even
            though we're still holding a reference to it. For example,
            when the launcher template is re-evaluated. So we need to
            check if guideElement exists OR is empty.
            */
            if (!guideElement || !guideElement.html()) {
                guideElement = dom('<div>')
                    .attr('id', getStepDivId(step))
                    .addClass('_pendo-guide-whatsnew_')
                    .html(step.getContent());
    
                if (_.isNumber(height) && !step.attributes.autoHeight) {
                    guideElement.height(height);
                }
    
                if (step.seenState === active) {
                    guideElement.addClass(seenClass);
                }
    
                step.guideElement = guideElement;
            }
        }
    
        function seen() {
            if (isPreviewing()) return;
            if (!isReady()) return;
            if (step.seenState === active) return;
            if (!isVisible(step.guideElement[0])) return;
    
            seenGuide(step.guideId, step.id, pendo.get_visitor_id(), type, guide.language);
            step.seenState = active;
            _.delay(function() {
                step.guideElement.addClass(seenClass + ' out');
            }, _.isNumber(step.attributes.seenDelay) ? step.attributes.seenDelay : defaultSeenDelay);
        }
    
        function isVisible(guideElement) {
            if (isElementVisible(guideElement, /(auto|scroll|hidden)/)) {
                var scrollParent = getScrollParent(guideElement);
                var scrollRect = getClientRect(scrollParent);
                var elementRect = getClientRect(guideElement);
                var upperThird = scrollRect.top + Math.floor(scrollRect.height / 3);
                // The bottom of the element is in the scrollable area, or the top is in the upper 1/3 of the scrollable area
                return elementRect.bottom <= scrollRect.bottom || elementRect.top <= upperThird;
            }
        }
    
        function noop() {
        }
    }
    
    
    /**
     * @description
     * A poll guide step
     */
    function Poll(guide) {
        var step = this;
        if (step.pollIds && step.pollIds.length) {
            var selectedClass = '_pendo-poll-selected_',
                pollsById = _.indexBy(guide.polls, 'id'),
                polls = _.map(step.pollIds, function(id) {
                    return pollsById[id];
                }),
                shownTime;
    
            //TODO
            // - maxlength enforcement in non-HTML5 browsers
    
            var parseResponseValue = function(poll, value) {
                if (!poll || value === undefined) {
                    return;
                }
                return poll.numericResponses ? parseInt(value, 10) : value;
            };
    
            var advanceButDoNotHide = function() {
                var guideId = guide.id,
                    stepId = step.id;
                advancedGuide(guideId, stepId, pendo.get_visitor_id(), step.seenReason, guide.language);
                _updateGuideStepStatus(guideId, stepId, 'advanced');
                lastGuideStepSeen = {
                    'guideId':     guideId,
                    'guideStepId': stepId,
                    'time':        new Date().getTime(),
                    'state':       'advanced'
                };
                writeLastStepSeenCache(lastGuideStepSeen);
            };
    
            var afterResponse = function() {
                var pollElement = dom('._pendo-poll_'),
                    messageElement = dom('._pendo-poll-message_');
                if (messageElement.length) {
                    pollElement.addClass('_pendo-poll-submitted_');
                    messageElement.css('margin-top:-' + (messageElement.height() / 2) + 'px');
                    advanceButDoNotHide();
                } else {
                    step.advance();
                }
            };
    
            var getPoll = function(pollId, guide) {
                if (!guide || 
                    !guide.polls || 
                    !guide.polls.length) {
                    return;
                }
                return _.find(guide.polls, function(poll) {
                    return poll.id === pollId;
                });
            };
    
            step.after('render', function() {
                var pollElement = Sizzle('._pendo-poll_')[0],
                    pollSubmit = Sizzle('._pendo-poll-submit_', pollElement)[0];
                if (pollSubmit) {
                    step.attachEvent(pollSubmit, 'click', function(e) {
                        var questions = Sizzle('._pendo-poll-question_', pollElement);
                        var responses = _.map(questions, function(question, i) {
                            var input = Sizzle('textarea,input:text,select,input:radio:checked', question);
                            if (input && input.length && input[0].value) {
                                var poll = polls[i];
                                return {
                                    'pollId': poll.id,
                                    'value':  parseResponseValue(poll, input[0].value)
                                };
                            }
                        });
                        step.response(_.compact(responses));
                        afterResponse();
                    });
                } else {
                    step.attachEvent(pollElement, 'click', function(e) {
                        var submit = dom(getTarget(e)).closest('._pendo-poll-question_ :button,._pendo-poll-question_ :radio');
                        if (submit.length) {
                            var poll = polls[0],
                                submitValue = parseResponseValue(poll, submit.attr('data-pendo-poll-value') || submit.attr('value'));
                            step.response([{
                                'pollId': poll.id,
                                'value':  submitValue
                            }]);
                            afterResponse();
                        }
                    });
                }
            });
    
            step.after('render', function() {
                var npsRating = Sizzle('._pendo-poll_ ._pendo-poll-npsrating_')[0],
                    pollSubmit = dom('._pendo-poll_ ._pendo-poll-submit_'),
                    npsRatingSelectedClass = '_pendo-poll-npsrating-selected_';
                if (npsRating) {
                    pollSubmit.css({ 'display': 'none' });
                    step.attachEvent(npsRating, 'click', function(e) {
                        var radio = Sizzle(':radio:checked', npsRating)[0],
                            pollElement = dom('._pendo-poll_');
    
                        dom('label', npsRating).removeClass(selectedClass);
                        pollElement.removeClass(npsRatingSelectedClass);
    
                        if (radio) {
                            //Add class to mark radio labels as selected
                            dom('label[for="' + radio.id + '"]').addClass(selectedClass);
                            //Add class to mark nps rating as selected
                            pollElement.addClass(npsRatingSelectedClass);
                            //Show the submit button
                            pollSubmit.css({ 'display': '' });
                        }
    
                        if (_.isFunction(step.resize)) {
                            step.resize();
                        }
                    });
                }
            });
    
            step.after('show', function() {
                shownTime = new Date().getTime();
            });
    
            step.response = function(responses, options) {
                if (!responses || !responses.length) return;
                var events = _.map(responses, function(response, i) {
                    var curPoll = getPoll(response.pollId, guide);
                    var evt = createGuideEvent('pollResponse', step.guideId, step.id, pendo.get_visitor_id(), undefined, guide.language);
                    _.extend(evt.props, {
                        'poll_id':       response.pollId,
                        'poll_response': response.value,
                        'duration':      (new Date().getTime() - shownTime)
                    });
    
                    if(curPoll &&
                        curPoll.attributes &&
                        curPoll.attributes.type) {
                        _.extend(evt.props, {
                            'poll_type': curPoll.attributes.type
                        });
                    }
    
                    return evt;
                });
                writeBeacon('poll', _.extend({
                    'ct':  new Date().getTime(),
                    'v':   VERSION,
                    'jzb': pendo.squeezeAndCompress(events)
                }, options));
            };
        }
    
        return step;
    }
    
    /**
     * @description
     * Allows guide content to be validated before display
     */
    var ContentValidation = (function() {
    
        var allow = 'allow';
        var deny = 'deny';
        var cache = {};
        var steps = [];
        var pending;
        var cancelled;
    
        var enabled = function() {
            return _.size(pendo.events._handlers.validateGuide) > 0;
        };
    
        var validate = function(guide) {
            return isResourceCenter(guide) ? validateResourceCenter(guide) : validateGuide(guide);
        };
    
        function isResourceCenter(guide) {
            return get(guide, 'attributes.resourceCenter.isTopLevel', false);
        }
    
        function validateResourceCenter(resourceCenter) {
            var modules = BuildingBlockResourceCenter.findResourceCenterModules(resourceCenter, activeGuides);
            var resourceCenterAndModules = [resourceCenter].concat(modules);
            return q.all(_.map(resourceCenterAndModules, validateGuide));
        }
    
        function validateGuide(guide) {
            pending = guide.id;
            return guide.fetchContent().then(function() {
                var signatureString = JSON.stringify(guide.signature());
                var key = guide.id + '-' + crc32(signatureString);
                return pendo.events.validateGuide(signatureString, guide).then(function() {
                    pending = null;
                    cache[key] = allow;
                },function(error) {
                    pending = null;
                    cache[key] = deny;
                    return q.reject(error);
                });
            });
        }
    
        var status = function(guide) {
            var key = guide.id + '-' + crc32(guide.signature());
            return cache[key];
        };
    
        var getKeyValuePairs = function(variables, prefix) {
            var signature = [];
            _.each(variables, function(value, key) {
                var path = key;
                if (prefix) {
                    path = prefix + '.' + path;
                }
                if (_.isObject(value)) {
                    _.each(getKeyValuePairs(value, path), function(tuple) {
                        signature.push(tuple);
                    });
                } else {
                    signature.push([path, value]);
                }
            });
            return signature;
        };
    
        function Step(guide) {
            var step = this;
    
            step.before('hide', function() {
                cancelled = true;
            });
    
            step.before('show', function(reason) {
                if (enabled()) {
                    cancelled = false;
                    if (pending) {
                        if (step.guideId === pending && !_.contains(steps, step)) {
                            //If step is in the guide currently being validated, queue it for display (group guides)
                            steps.push(step);
                        }
    
                        //If a validation is in progress, do not display anything, since
                        //the guide that is currently being validated will (most likely)
                        //display as soon as validation completes.
                        return false;
                    }
                    var guideStatus = status(guide);
                    if (guideStatus === deny) {
                        //Prevent the step from displaying
                        return false;
                    } else if (guideStatus !== allow) {
                        //Queue the step for display
                        steps.push(step);
    
                        var always = function() {
                            _.each(steps, function(s) {
                                s.unlock();
                            });
                            steps.length = 0;
                            setTimeout(startGuides, 0); // Kick the guide loop
                        };
    
                        step.lock();
                        validate(guide).then(function() {
                            //Force the steps to diplay
                            _.each(steps, function(s) {
                                s.unlock();
                                if (cancelled) return;
                                s.show(reason);
                                if (!step.isShown()) {
                                    step.hide();
                                }
                            });
                            always();
                        }, always);
    
                        //Prevent the step from displaying for now
                        return false;
                    }
                }
            });
    
            this.signature = function() {
                if (this.domUrl) {
                    if (this.guide.authoredLanguage === this.language) {
                        return buildingBlockGuideSignature(this);
                    } else {
                        var translatedStep = buildTranslatedStep(step);
                        return buildingBlockGuideSignature(translatedStep);
                    }
                }
    
                var signature = [['content', this.content]],
                    variables = this.attributes && this.attributes.variables;
                if (variables) {
                    var variableSignature = getKeyValuePairs(variables);
                    if (variableSignature.length) {
                        variableSignature = _.sortBy(variableSignature, function(tuple) {
                            return tuple[0];
                        });
    
                        signature.push(['variables', variableSignature]);
                    }
                }
                return signature;
            };
    
            function buildTranslatedStep(step, language) {
                var stepTranslations = get(step, 'guide.translationStates.' + step.language + '.stepTranslations.' + step.id);
                // including domUrl && domJasonpUrl in case step is partially translated
                // including contentUrl, contentUrlCss, and contentUrlJs for possible edge edge cases
                return {
                    'contentUrl':    step.contentUrl,
                    'contentUrlCss': step.contentUrlCss,
                    'contentUrlJs':  step.contentUrlJs,
                    'domUrl':        step.domUrl,
                    'domJsonpUrl':   step.domJsonpUrl,
                    'domHash':       stepTranslations && stepTranslations.domHash,
                    'domJsonpHash':  stepTranslations && stepTranslations.domJsonpHash
                };
            }
    
            function buildingBlockGuideSignature(step) {
                return _.filter([
                    ['content', getHashFromContentUrl(step.contentUrl)],
                    ['contentCss', getHashFromContentUrl(step.contentUrlCss)],
                    ['contentJs', getHashFromContentUrl(step.contentUrlJs)],
                    ['dom', get(step, 'domHash', getHashFromContentUrl(step.domUrl))],
                    ['domJsonp', get(step, 'domJsonpHash', getHashFromContentUrl(step.domJsonpUrl))]
                ], function(tuple) {
                    return tuple[1];
                });
            }
    
            return step;
        }
    
        function Guide() {
    
            this.signature = function() {
                return _.map(this.steps, function(step) {
                    return step.signature();
                });
            };
    
            return this;
        }
    
        function Launcher() {
    
            var launcher = this,
                pending = false;
    
            var enabled = function() {
                return _.size(pendo.events._handlers.validateLauncher) > 0 && launcher.data.template;
            };
    
            var validate = function() {
                var signatureString = JSON.stringify(launcher.signature());
                var key = 'launcher-' + crc32(signatureString);
                return pendo.events.validateLauncher(signatureString).then(function() {
                    cache[key] = allow;
                },function() {
                    cache[key] = deny;
                });
            };
    
            var status = function() {
                var key = 'launcher-' + crc32(launcher.signature());
                return cache[key];
            };
    
            launcher.before('update', function() {
                if (enabled() && pending) {
                    return false;
                }
            });
    
            launcher.before('render', function() {
                if (enabled()) {
                    if (pending) {
                        return false;
                    }
    
                    var launcherStatus = status();
                    if (launcherStatus === deny) {
                        //Prevent the launcher from displaying
                        return false;
                    } else if (launcherStatus !== allow) {
                        pending = true;
                        validate().then(function() {
                            pending = false;
                            //Render and update the launcher
                            launcher.render();
                            launcher.update(getActiveGuides());
                        }, function() {
                            pending = false;
                        });
    
                        return false;
                    }
                }
            });
    
            launcher.signature = function() {
                var signature = [],
                    variableSignature = getKeyValuePairs(this.data);
                if (variableSignature.length) {
                    variableSignature = _.chain(variableSignature).filter(function(tuple) {
                        // strip the junk added by the launcher guide
                        return !/^contentUrl/.test(tuple[0]);
                    }).sortBy(function(tuple) {
                        return tuple[0];
                    }).value();
    
                    signature.push(['variables', variableSignature]);
                }
                return signature;
            };
    
            return launcher;
        }
    
        return {
            'Step':     Step,
            'Guide':    Guide,
            'Launcher': Launcher,
            'validate': validate,
            'reset':    function() {
                cache = {};
                pending = null;
                steps.length = 0;
            }
        };
    
    })();
    
    var AsyncContent = (function() {
        function AsyncContent(guide) {
            var step = this;
            var promise;
            var preloadCount = 3;
            var cancelled;
            if (step.contentUrl || step.domJsonpUrl) {
                _.extend(step, {
                    'fetchContent': fetchContent
                });
    
                step.before('hide', beforeHide);
                step.before('show', beforeShow);
            }
    
            function beforeHide() {
                cancelled = true;
            }
    
            /**
             * Interrupts step.show() and loads guide content
             * from an external source.
             */
            function beforeShow(reason) {
                preloadNextSteps(preloadCount); // Avoid flickering in walkthroughs
                cancelled = false;
                if (!pendo.doesExist(step.content) && !pendo.doesExist(step.domJson)) {
                    step.lock();
    
                    step.fetchContent().then(function() {
                        step.unlock();
                        if (cancelled) return;
    
                        var guide = _.isFunction(step.getGuide) && step.getGuide();
                        if(guide && guide.attributes && guide.attributes.doNotResume) {
                            return step.hide();
                        }
    
                        step.show(reason);
    
                        if (!step.isShown()) {
                            step.hide();
                        }
                    }, function() {
                        step.unlock();
                    });
    
                    return false; // Prevent the guide from showing until the content loads
                }
            }
    
            /**
             * Fetches the step content
             * @todo Time out after some period of time? I think not for now, if
             *       fetching fails, just leave the guide loop halted until the next
             *       guide.js load.
             * @return {Promise} Resolved when the step content is loaded
             */
            function fetchContent() {
                if (!promise) {
                    var guide = step.getGuide();
                    var language, domHash, domJsonpHash;
    
                    if (guide && guide.language) {
                        language = guide.language;
    
                        if (language !== guide.authoredLanguage) {
                            domHash = get(guide, 'translationStates.' + language + '.stepTranslations.' + step.id + '.domHash');
                            domJsonpHash = get(guide, 'translationStates.' + language + '.stepTranslations.' + step.id + '.domJsonpHash');
                        }
                    }
    
                    var uniqueContentKey = step.guideId + step.id;
                    var container = _.extend(
                        { 'id': uniqueContentKey, 'language': language, 'domHash': domHash, 'domJsonpHash': domJsonpHash },
                         _.pick(step, 'contentUrl', 'contentUrlCss', 'contentUrlJs', 'domJsonpUrl', 'domUrl')
                    );
                    promise = ContentVerifier.verify(container).then(function() {
                        return ContentLoader.load(container);
                    }).then(function(content) {
                        _.extend(step, content);
                    });
                }
    
                return promise;
            }
    
            /**
             * If the guide has multiple steps, this pre-fetches
             * the content for the next N steps in order to
             * avoid delays and flickering when advancing
             * between steps.
             * @param  {Number} count How many steps to pre-fetch
             */
            function preloadNextSteps(count) {
                var currentStepIndex = _.indexOf(guide.steps, step);
                _.chain(guide.steps)
                    .rest(currentStepIndex + 1)
                    .first(count)
                    .each(function(step) {
                        step.fetchContent();
                    })
                    .value();
            }
    
            return step;
        }
    
        AsyncContent.reset = function() {
            ContentLoader.reset();
        };
    
        AsyncContent.reset();
    
        return AsyncContent;
    })();
    
    /**
     * @description
     * Abstract guide step class
     *
     * @param {Object} step The step properties
     */
    function GuideStep(guide) {
        var locked = false;
        var timedOut = false;
    
        this.guide = guide;
    
        this.elements = [];
        this.handlers = [];
        this.attributes = this.attributes || {};
    
        this.getGuide = function() {
            return this.guide;
        };
    
        this.getContent = function() {
            var step = this;
    
            // var guide = findGuideById(step && step.guideId);
            var guide = this.getGuide();
            var steps = (guide && guide.steps) || [];
            var stepIndex = _.indexOf(steps, step);
    
            var metadata = getMetadata();
            if (!_.isObject(metadata)) metadata = prepareOptions();
    
            try {
                var variables = step.attributes.variables || {};
                var obj = {
                    'step': {
                        'id':      step.id,
                        'isFirst': stepIndex === 0,
                        'isLast':  stepIndex === steps.length - 1,
                        'index':   stepIndex,
                        'number':  stepIndex + 1
                    },
                    'guide': {
                        'id':              guide.id,
                        'name':            guide.name,
                        'publishedAt':     guide.publishedAt,
                        'showsAfter':      guide.showsAfter,
                        'percentComplete': (steps.length ? Math.round(((stepIndex + 1) / steps.length) * 100) : 0),
                        'stepCount':       steps.length
                    },
                    'metadata': escapeStringsInObject(metadata),
                    'template': variables
                };
                if (!step.template) {
                    step.template = _.template(step.content || '');
                }
                return replaceWithContentHost(
                    step.template(obj)
                        .replace(/#_pendo_g_undefined/g, '#_pendo_g_' + step.id)
                        .replace(/pendo-src="([^"]+)"/g, function(match, src) {
                            if (/<%=[^>]+>/.test(src)) {
                                // If pendo-src is still templated, leave it alone
                                return match;
                            } else {
                                // Change pendo-src to src
                                return 'src="' + src + '"';
                            }
                        })
                );
            } catch (e) {
                // If the template fails to render or compile, just return the content
                return step.content;
            }
        };
    
        /**
         * If true, the step is provisionally "shown", but we're waiting on the
         * completion of an asynchronous operation to actually show the step.
         * @return {Boolean}
         */
        this.isLocked = function() {
            return locked;
        };
    
        this.lock = function() {
            locked = true;
        };
    
        this.unlock = function() {
            locked = false;
        };
    
        this.isTimedOut = function() {
            return timedOut;
        };
    
        this.timeout = function() {
            timedOut = true;
        };
    
        this.isShown = function() {
            // this.elements represents an array of html elements created by a legacy guide
            // this.buildingBlockDomNodeRoot represents the root node of a building block guide
            return this.elements.length > 0 || this.isLocked();
        };
    
        // NOTE: this is really *should* Show b/c of the logic in there about
        //       already being shown.
        this.canShow = function() {
            var step = this;
            var guideContainer = null;
    
            if(get(step, 'guide.attributes.isAnnouncement')) {
                return false;
            }
    
            if (step.domJson) {
                guideContainer = BuildingBlockGuides.findGuideContainerJSON(step.domJson);
            }
    
            if (guideContainer) {
                var isTooltip = guideContainer.props['data-vertical-alignment'] === 'Relative to Element';
                if (isTooltip) {
                    if (isDismissedUntilReload(step)) {
                        return false;
                    }
    
                    if (!step.hasBeenScrolledTo) {
                        return !step.isShown() && step.canShowOnPage(pendo.getCurrentUrl()) && canTooltipStepBeShown(step);
                    }
                }
            }
            return !step.isShown() && step.canShowOnPage(pendo.getCurrentUrl()) && canStepBeRendered(step);
        };
    
        this.canShowOnPage = function(urlToCheck) {
            return pendo.testUrlForStep(this.regexUrlRule, urlToCheck); // && canStepBeRendered(this);
        };
    
        this.shouldAutoDisplay = function() {
            return !_.contains(['dismissed', 'advanced'], this.seenState);
        };
    
        this.autoDisplay = function() {
            var step = this;
            if (step.shouldAutoDisplay()) {
                step.show('auto');
            }
        };
    
        this.render = function() {
            var step = this;
    
            if (step.domJson) {
                step.eventRouter = new EventRouter();
                return BuildingBlockGuides.renderGuideFromJSON(step.domJson, step);
            }
    
            var width = step.attributes.width,
                height = step.attributes.height,
                arrowSize = pendo.TOOLTIP_ARROW_SIZE,
                guideIdClass = '_pendo-group-id-' + guide.id + '_',
                guideElement = dom('<div>').attr('id', getStepDivId(step)).addClass(GUIDE_CSS_NAME + ' ' + guideIdClass),
                contentElement = dom('<div/>').addClass('_pendo-guide-content_').html(step.getContent()),
                containerElement = dom('<div/>').addClass('_pendo-guide-container_'),
                overlayDiv = dom('<div/>').addClass('_pendo-backdrop_');
    
            guideElement.width(width);
            guideElement.height(height);
    
            containerElement.css({
                'left': arrowSize,
                'top':  arrowSize
            });
    
            if (step.isEditable) {
                contentElement.attr('contenteditable', 'true');
            }
    
            contentElement.appendTo(containerElement);
            containerElement.appendTo(guideElement);
    
            if (guide && _.isFunction(guide.isOnboarding) && guide.isOnboarding()) {
                guideElement.addClass('_pendo-onboarding_');
            }
    
            step.overlayDiv = overlayDiv;
            step.guideElement = guideElement;
        };
    
        this.teardown = function() {
            log('guide step teardown', 'guide', 'render');
    
            _.each(this.handlers, function(handler) {
                detachEvent(handler.element, handler.type, handler.fn, true);
            });
            this.hasBeenScrolledTo = false;
            clearInterval(this.timeoutTimer);
            delete this.timeoutTimer;
            this.handlers.length = 0;
            this.attributes.imgCount = 0;
        };
    
        this.show = function(reason) {
            var step = this;
            if (!guide.canShowOnDevice() || !step.canShow()) {
                // Don't do this if the option to enable it is not on
                if (!getPendoConfigValue('enableGuideTimeout') && !getOption('enableGuideTimeout')) return;
                // If the step is seen stop trying to time it out as well....
                if (step.seenState === 'active') return;
                // Don't do this if it isn't a walkthrough
                if (!isWalkthrough(guide) || guide.steps.length === 1 || this.isTimedOut()) return;
    
                var steps = (guide && guide.steps);
                if (!steps) return;
                // If it is the first step of the walkthrough we don't care
                var stepIndex = _.indexOf(steps, step);
                if (stepIndex === 0) return;
                if (step.shouldStartTimer()) step.beginTimeoutTimer();
                return;
            }
    
            step.render();
    
            if (step.isShown()) {
                step.onShown(reason);
            }
        };
    
        this.shouldStartTimer = function() {
            return guide.canShowOnDevice() && !guide.attributes.isAnnouncement && !isDismissedUntilReload(this);
        };
    
        this.getStepPollTypes = function(guide, step) {
            if (!step.pollIds || !step.pollIds.length) {
                return;
            }
    
            var stepPollTypes = [];
    
            _.forEach(step.pollIds, function(id) {
                var curPoll = _.find(guide.polls, function(poll) {
                    return poll.id === id;
                });
    
                if (curPoll &&
                    curPoll.attributes &&
                    curPoll.attributes.type) {
                    stepPollTypes.push(curPoll.attributes.type);
                }
            });
    
            return stepPollTypes;
        };
    
        this.onShown = function(reason) {
            var step = this;
    
            if (step.overrideElement) {
                dom.addClass(step.overrideElement, 'triggered');
            }
    
            if (!isPreviewing()) {
                step.seenReason = reason;
                step.seenState = 'active';
                seenTime = new Date().getTime();
                var pollTypes = this.getStepPollTypes(guide, step);
    
                seenGuide(step.guideId, step.id, pendo.get_visitor_id(), reason, guide.language, pollTypes);
    
                if (_.isFunction(step.script)) {
                    step.script(step, guide);
                }
            }
        };
    
        this.hide = function(hideOptions) {
            var step = this;
            step.teardown();
            _.each(step.elements, function(element) {
                element.parentNode.removeChild(element);
            });
    
            if (step.attributes && hideOptions && hideOptions.stayHidden) { step.attributes.stayHidden = hideOptions.stayHidden; }
    
            step.elements.length = 0;
            step.element = null;
            step.guideElement = null;
            if (step.overrideElement) {
                dom.removeClass(step.overrideElement, 'triggered');
            }
        };
    
        this.advance = function() {
            if (this.seenState === 'advanced') return;
            pendo.onGuideAdvanced(this);
        };
    
        this.dismiss = function() {
            if (this.seenState === 'dismissed') return;
            pendo.onGuideDismissed(this);
        };
    
        this.isPoweredByEnabled = function() {
            return this.hideCredits !== true;
        };
    
        this.attachEvent = function(element, type, fn) {
            var handler = { 'element': element, 'type': type, 'fn': fn };
            attachEvent(element, type, fn, true);
            this.handlers.push(handler);
        };
    
        this.searchFor = function(txt) {
            // check content
            if (txt.length < 3) return false;
            return strContains(this.content, txt, true);
        };
    
        this.hasBeenSeen = function() {
            return this.seenState == 'advanced' ||
                this.seenState == 'dismissed';
        };
    
        this.reposition = function() {
        };
    
        this.beginTimeoutTimer = function() {
            var TIMEOUT_LENGTH = getGuideSeenTimeoutLength();
    
            var timeoutFunc = _.bind(function() {
                var guide = this.getGuide();
                var seenReason;
                if (!this.canShowOnPage(pendo.getCurrentUrl())) {
                    seenReason = 'page';
                } else if (!canTooltipStepBeShown(this) || !canStepBeRendered(this)) {
                    seenReason = 'element';
                } else {
                    seenReason = 'other';
                }
    
                timeoutGuide(guide.id, this.id, pendo.get_visitor_id(), seenReason, guide.language, TIMEOUT_LENGTH);
                pendo.log('Guide Timed Out');
                this.timeout();
                delete this.timeoutTimer;
            }, this);
    
            if (!this.timeoutTimer) {
                this.timeoutTimer = setTimeout(function() {
                    timeoutFunc();
                }, TIMEOUT_LENGTH);
            }
        };
    
        return this;
    }
    
    GuideStep.create = function(step, guide) {
        return _.reduce(GuideStep.behaviors, function(step, behavior) {
            return behavior.call(step, guide);
        }, step);
    };
    
    GuideStep.isGuideStep = function(step) {
        return !!step && _.isFunction(step.render);
    };
    
    GuideStep.behaviors = [
        Wrappable,
        GuideStep,
        RemoteFrameStep,
        AsyncContent,
        ContentValidation.Step,
        CloseButton,
        Credits,
        Tooltip,
        Lightbox,
        Banner,
        WhatsNew,
        Poll,
        AutoHeight,
        PreviewMode
    ];
    
    /**
     * @description
     * Automatically sizes a guide
     */
    function AutoHeight() {
        var step = this;
        if (step.attributes && step.attributes.autoHeight) {
            var useWidth = function() {
                /*
                Tooltips use a different container sizing method than lightboxes...
                Unless we're in quirksmode, in which case lightboxes use the same
                sizing method as tooltips... except for mobile lightboxes, which
                always use the different sizing method. Mobile browsers should never
                be in quirksmode though, so ignore that extra-special case here.
                Cannot use the same method across the board because some customers have
                guide layouts that depend on the different approaches.
                */
                return step.type == 'tooltip' ||
                    (isBrowserInQuirksmode() && step.type == 'lightbox');
            };
    
            step.after('render', function() {
                step.resize();
    
                step.attachEvent(step.guideElement[0], 'load', function() {
                    // Resize on image (or whatever) loads
                    step.resize();
                });
            });
    
            step.resize = function() {
                var arrowSize = pendo.TOOLTIP_ARROW_SIZE,
                    guideElement = step.guideElement,
                    guideContainer = dom('._pendo-guide-container_', guideElement);
    
                if (useWidth()) {
                    guideContainer.css({
                        'width':  step.attributes.width - arrowSize * 2,
                        'height': ''
                    });
                } else {
                    guideContainer.css({
                        'right':  arrowSize,
                        'bottom': ''
                    });
                }
    
                step.attributes.height = guideContainer.height() + arrowSize * 2;
                guideElement.height(step.attributes.height);
    
                step.reposition();
            };
        }
        return step;
    }
    
    /**
     * @description
     * Adds a close button to the guide
     */
    function CloseButton(guide) {
        var step = this;
    
        // We only want to have the agent add close buttons to legacy guides, not building block inserts
        if (step.domJson || step.domJsonpUrl) return step;
    
        step.after('render', function() {
            addCloseButton(step.guideElement[0], function() {
                //eslint-disable-next-line no-alert
                if (!guide.isOnboarding() || confirm('Are you sure you want to stop this tutorial?')) { pendo.onGuideDismissed(step); }
            });
        });
        return step;
    }
    
    /**
     * @description
     * Adds pendo credits to the guide unless disabled
     */
    function Credits() {
        var step = this;
        if (!step.hideCredits && !step.domJson && !step.domJsonpUrl) {
            step.after('render', function() {
                pendo._addCredits(step.guideElement[0]);
            });
        }
        return step;
    }
    
    function PreviewMode() {
        var step = this;
        step.after('render', function() {
            adjustPreviewBarPosition();
        });
        return step;
    }
    
    
    /**
     * @description
     * A multi-step guide that displays one step at a time
     * in order.
     */
    function WalkthroughGuide() {
        if (this.isMultiStep || this.isModule || this.isTopLevel) {
    
            _.each(this.steps, function(step) {
                step.after('render', function() {
                    _.each(step.elements, function(element) {
                        dom(element).addClass('_pendo-guide-walkthrough_');
                    });
                });
            });
    
            // does last step in section have matching isRequired?
            // if yes, then return false;
            // if no, then is the last step isRequired == false?
            // if yes, then return false
            // if no, then return true
            var isStepNewSection = function(section, step) {
                if (!section) return true;
    
                var lastStep = _.last(section);
    
                if (lastStep.attributes.isRequired != step.attributes.isRequired &&
                    lastStep.attributes.isRequired)
                {return true;}
    
                return false;
            };
    
            var currSection = null;
            this.sections = _.reduce(this.steps, function(memo, step) {
                if (isStepNewSection(currSection, step)) {
                    memo.push(currSection);
                    currSection = [step];
                } else {
                    currSection.push(step);
                }
                return memo;
            }, []);
            this.sections = _.compact(this.sections.concat([currSection]));
    
            this.findSectionForStep = function(step) {
                return _.find(this.sections, function(sect) {
                    return _.contains(sect, step);
                });
            };
    
            this.getSubSection = function(section, step) {
                var idx = _.indexOf(section, step);
                return section.slice(idx + 1);
            };
    
            this.isContinuation = function(lastSeenObj) {
                // RC's should only be continued if they have content
                var isRC = this.isTopLevel || this.isModule;
                var shouldRCShow = this.hasResourceCenterContent;
                if (isRC) return shouldRCShow && !!this.nextStep(lastSeenObj);
                return !!this.nextStep(lastSeenObj);
            };
    
            var MULTISTEP_CONTINUATION_TIME_LIMIT = 12 * 60 * 60 * 1000;// time in millis
    
            this.nextStep = function(lastSeenObj) {
                var nextStep = null;
                var currentGuide = this;
    
                lastSeenObj = lastSeenObj || {};
    
                for(var j = 0; j < currentGuide.steps.length; j++) {
                    if(currentGuide.steps[j].id === lastSeenObj.guideStepId) {
                        if(lastSeenObj.state === 'dismissed') {
                            // The guide was dismissed
                            break;
                        } else if(lastSeenObj.state === 'active') {
                            // This is current.
                            nextStep = currentGuide.steps[j];
                            break;
                        } else if((j + 1) < currentGuide.steps.length) {
                            // Get the step after that last one seen
                            nextStep = currentGuide.steps[j + 1];
                            break;
                        }
                    }
                }
    
                if(nextStep) {
                    var now = new Date().getTime(), lastSeenTime = lastSeenObj.time;
                    if (
                        lastSeenTime &&
                        ((now - lastSeenTime) > MULTISTEP_CONTINUATION_TIME_LIMIT) &&
                        !isOB(currentGuide)) {
                        log('Multi-step continuation has expired', 'guides', 'info');
                        return null;
                    }
    
                    return nextStep;
                }
    
                return null;
            };
    
            this.shouldAutoDisplay = function() {
                var guide = this;
                var nextStep = guide.nextStep(lastGuideStepSeen) || _.first(guide.steps);
                return guide.hasLaunchMethod('auto') &&
                    nextStep &&
                    nextStep.shouldAutoDisplay();
            };
    
            this.autoDisplay = function() {
                var guide = this;
                if (guide.shouldAutoDisplay()) {
                    var nextStep = guide.nextStep(lastGuideStepSeen) || _.first(guide.steps);
                    nextStep.autoDisplay();
                }
            };
    
            this.launch = function(reason) {
                var firstStep = _.first(this.steps);
                firstStep.show(reason);
            };
    
            this.show = function(reason) {
                var guide = this;
                var nextStep = guide.nextStep(lastGuideStepSeen) || _.first(guide.steps);
                nextStep.show(reason);
            };
    
            this.isComplete = function() {
                var terminalStates = ['advanced', 'dismissed'];
                var lastStep = _.last(this.steps);
                return lastStep ? _.contains(terminalStates, lastStep.seenState) : false;
            };
    
            this.activeStep = function() {
                var revArr = [].concat(this.steps).reverse();
                return _.findWhere(revArr, {'seenState': 'active'});
            };
        }
    
        return this;
    }
    
    function GroupGuide() {
        var guide = this;
    
        if (guide.attributes && guide.attributes.type == 'group') {
            guide.checkForHiddenGroupSteps = function() {
                _.each(guide.steps, function(step) {
                    if (!step.isShown()) {
                        step.autoDisplay();
                    }
                });
            };
        }
    
        return guide;
    }
    
    /**
     * Traps and logs errors that occur while displaying a guide. If the
     * number of errors crosses a threshold for number of errors per
     * minute, the guide will be removed from the guide list until the
     * next guide.js load. Note that the error will be logged twice,
     * once here so that the stack trace is intact, then again in the
     * guide loop.
     */
    function GuideErrorThrottle() {
        var guide = this;
    
        _.each(['canShow', 'placeBadge', 'show'], function(methodName) {
            guide[methodName] = _.wrap(guide[methodName], createWrapper(methodName));
        });
    
        function createWrapper(methodName) {
            var errorTimestamps = [];
    
            return function errorThrottleWrapper(wrappedMethod) {
                try {
                    return wrappedMethod.apply(guide, _.toArray(arguments).slice(1));
                } catch (e) {
                    var maxErrors = 5;
                    var message = 'ERROR in guide ' + methodName + ' (ID="' + guide.id + '")';
                    errorTimestamps.push(getNow());
                    if (errorTimestamps.length >= maxErrors) {
                        var timeSpan = _.last(errorTimestamps) - _.first(errorTimestamps);
                        var errorsPerMinute = timeSpan > 0 ? (errorTimestamps.length - 1) / (timeSpan / 60000) : Infinity;
                        if (errorsPerMinute >= GuideErrorThrottle.MAX_ERRORS_PER_MINUTE) {
                            message = 'Exceeded error rate limit, dropping guide.\n' + message;
                            var guides = getActiveGuides();
                            var i = _.indexOf(guides, guide);
                            if (i >= 0) {
                                guides.splice(i, 1);
                            }
                        }
                        errorTimestamps.shift();
                    }
                    writeException(e, message);
                    throw e;
                }
            };
        }
    
        return guide;
    }
    
    GuideErrorThrottle.MAX_ERRORS_PER_MINUTE = 30;
    
    
    /**
     * @description
     * A group of one or more guide steps with no ordering.
     */
    function Guide() {
        this.elements = [];
    
        this.attributes = this.attributes || {};
    
        if (this.attributes.device && this.attributes.device.type) {
            if (this.attributes.device.type == 'all') {
                this.attributes.device = { 'desktop': true, 'mobile': true };
            } else {
                var type = this.attributes.device.type;
                this.attributes.device = { 'mobile': false, 'desktop': false };
                this.attributes.device[type] = true;
            }
        } else {
            this.attributes.device = this.attributes.device || {};
        }
    
        _.each(this.steps, function(step) {
            if (step.type === 'mobile-lightbox') {
                this.attributes.device.desktop = false;
                this.attributes.device.mobile = true;
            }
            GuideStep.create(step, this);
        }, this);
    
        this.isActivatedByEvent = function(eventType) {
            var guide = this;
            return !!(guide.hasLaunchMethod('dom') &&
                guide.attributes &&
                guide.attributes.activation &&
                _.contains(guide.attributes.activation.event, eventType) &&
                this.canEventActivatedGuideBeShown());
        };
    
        this.isContinuation = function(lastSeenObj) {
            return false;
        };
    
        this.isGuideWidget = function() {
            var guide = this;
            return guide.attributes && guide.attributes.type === 'launcher';
        };
    
        this.isOnboarding = function() {
            var guide = this;
            return guide.attributes && !!guide.attributes.isOnboarding;
        };
    
        this.isWhatsNew = function() {
            var firstStep = _.first(this.steps);
            return firstStep && firstStep.type === 'whatsnew';
        };
    
        // The Resource Center version of whatsNew
        this.isAnnouncement = function() {
            return get(this, 'attributes.isAnnouncement');
        };
    
        this.isHelpGuide = function() {
            return !this.isOnboarding() && !this.isWhatsNew() && !this.isGuideWidget();
        };
    
        this.nextStep = function(lastSeenObj) {
            return null;
        };
    
        this.hasLaunchMethod = function(method) {
            return this.launchMethod && this.launchMethod.indexOf(method) >= 0;
        };
    
        this.shouldAutoDisplay = function() {
            var guide = this;
            return guide.hasLaunchMethod('auto') && _.any(guide.steps, function(step) {
                return step.shouldAutoDisplay();
            });
        };
    
        this.autoDisplay = function() {
            var guide = this;
            if (guide.shouldAutoDisplay()) {
                _.each(guide.steps, function(step) {
                    step.autoDisplay();
                });
            }
        };
    
        this.isShown = function() {
            return _.any(this.steps, function(step) {
                return step.isShown();
            });
        };
    
        this.canShowOnDevice = function() {
            var guide = this;
            if (!isPreviewing()) { // Always show if previewing
                var isMobile = isMobileUserAgent(),
                    isDesktop = !isMobile,
                    device = guide.attributes && guide.attributes.device || {};
                if (isDesktop && device.desktop === false) {
                    return false;// Not desktop/tablet enabled (defaults to true)
                } else if (isMobile && device.mobile !== true) {
                    return false;// Not mobile enabled (defaults to false)
                }
            }
            return true;
        };
    
        this.canShow = function() {
            var guide = this;
            return guide.canShowOnDevice() && _.any(guide.steps, function(step) {
                return step.canShow();
            });
        };
    
        this.launch = function(reason) {
            var guide = this;
            guide.show(reason);
            if (guide.isShown()) {
                // Make sure all steps were reset to active
                _.each(guide.steps, function(step) {
                    step.seenState = 'active';
                });
            }
        };
    
        this.show = function(reason) {
            var guide = this;
            _.each(guide.steps, function(step) {
                step.show(reason);
            });
        };
    
        this.checkForHiddenGroupSteps = function() {
        };
    
        this.hide = function(hideOptions) {
            var guide = this;
            _.each(guide.steps, function(step) {
                step.hide(hideOptions);
            });
        };
    
        this.hasBeenSeen = function() {
            var guide = this;
            return _.all(guide.steps, function(step) {
                return step.hasBeenSeen();
            });
        };
    
        this.canBadgeBeShown = function() {
            var badgeInfo = this.attributes.badge;
            if (badgeInfo && !!badgeInfo.isOnlyShowOnce && this.hasBeenSeen()) {
                return false;
            }
            return true;
        };
    
        this.placeBadge = function() {
            if (this.canShowOnDevice() &&
                this.hasLaunchMethod('badge') &&
                this.canBadgeBeShown()) {
                var firstStep = _.first(this.steps);
                if (firstStep && _.isFunction(firstStep.fetchContent)) {
                    firstStep.fetchContent();
                }
                if (firstStep &&
                    _.isFunction(firstStep.canShowOnPage) &&
                    firstStep.canShowOnPage(pendo.getCurrentUrl()))
                {
                    placeBadge(this);
                }
            } else {
                removeBadgeForGuide(this);
            }
        };
    
        this.findStepById = function(stepId) {
            return _.find(this.steps, function(step) {
                return step.id === stepId;
            });
        };
    
        this.isPoweredByEnabled = function() {
            return !!_.find(this.steps, function(step) {
                return step.isPoweredByEnabled();
            });
        };
    
        this.searchFor = function(text) {
            var guide = this;
    
            var field = null;
    
            if (strContains(this.name, text, true)) {
                field = 'name';
            } else {
                var keywords = [];
                var isFound = false;
    
                if (this.attributes &&
                    this.attributes.launcher &&
                    this.attributes.launcher.keywords) {
                    keywords = this.attributes.launcher.keywords;
                }
    
                if (keywords.length > 0) {
                    isFound = _.find(keywords, function(kw) {
                        return strContains(kw.text, text, true);
                    });
                }
    
                if (isFound) {
                    field = 'tag';
                } else {
                    var results = _.map(this.steps, function(step) {
                        return step.searchFor(text);
                    });
                    var testSteps = _.compact(results).length > 0;
                    if (testSteps) {
                        field = 'content';
                    }
                }
            }
    
            if (!field) return false;
    
            return {
                'guide': guide,
                'field': field
            };
        };
        this.shouldBeAddedToResourceCenter = function() {
            // check url
            var guide = this;
    
            if (!guide.steps || !guide.steps.length) {
                return false;
            }
    
            if(guide.eligibleInFrame) return true;
    
            var step = guide.steps[0];
    
            if (!guide.hasLaunchMethod('launcher') && !guide.isWhatsNew()) {
                return false;
            }
            if (!step.canShowOnPage(pendo.getCurrentUrl())) {
                return false;
            }
            if (!guide.canShowOnDevice()) {
                return false;
            }
            if (!canStepBeRendered(step)) {
                return false;
            }
    
            return true;
        };
        this.shouldBeAddedToLauncher = function() {
            // check url
            var guide = this;
    
            if (!guide.steps || !guide.steps.length) {
                return false;
            }
    
            var step = guide.steps[0];
    
            // guide is launcher and guide is on the page and guide can be shown
            if (!guide.hasLaunchMethod('launcher') && !guide.isWhatsNew()) {
                return false;
            }
            if (!step.canShowOnPage(pendo.getCurrentUrl())) {
                return false;
            }
            if (!guide.canShowOnDevice()) {
                return false;
            }
            if (!canStepBeRendered(step)) {
                return false;
            }
    
            // var searchStr = getLauncherSearchText();
            // if (searchStr)
            //     return !!guide.searchFor(searchStr);
    
            return true;
        };
    
        var PENDO_HELPER_KEY = 'PENDO_HELPER_STEP';
        this.getPositionOfStep = function(step) {
            var guide = this;
    
            // remove helper steps
            var steps = _.reject(guide.steps, function(step) {
                return strContains(step.content, PENDO_HELPER_KEY);
            });
    
            return _.indexOf(steps, step) + 1;
        };
    
        this.getTotalSteps = function() {
            var guide = this;
    
            // remove helper steps
            var steps = _.reject(guide.steps, function(step) {
                return strContains(step.content, PENDO_HELPER_KEY);
            });
    
            return steps.length;
        };
    
        this.getSeenSteps = function() {
            return _.size(_.filter(this.steps, function(step) {
                return step.hasBeenSeen();
            }));
        };
    
        this.isComplete = function() {
            var terminalStates = ['advanced', 'dismissed'];
            return _.all(this.steps, function(step) {
                return _.contains(terminalStates, step.seenState);
            });
        };
    
        this.isInProgress = function() {
            var activeStates = ['active', 'advanced', 'dismissed'];
            return !this.isComplete() && _.any(this.steps, function(step) {
                return _.contains(activeStates, step.seenState);
            });
        };
    
        this.isNotStarted = function() {
            return !this.isInProgress() && !this.isComplete();
        };
    
        /**
         * Fetches the content for all steps in this guide (if necessary)
         * @return {Promise} Resolved when all the guide content is loaded
         */
        this.fetchContent = function() {
            return q.all(_.map(this.steps, function(step) {
                if (_.isFunction(step.fetchContent)) {
                    return step.fetchContent();
                }
            }));
        };
    
        this.canEventActivatedGuideBeShown = function() {
            var guide = this;
            if (guide.attributes.dom) {
                if (guide.attributes.dom.isOnlyShowOnce && guide.steps[0].hasBeenSeen()) {
                    return false;
                }
            }
            return true;
        };
    
        return this;
    }
    
    Guide.create = function(guide) {
        return _.reduce(Guide.behaviors, function(guide, behavior) {
            return behavior.call(guide);
        }, guide);
    };
    
    Guide.behaviors = [
        Wrappable,
        Guide,
        ContentValidation.Guide,
        GroupGuide,
        WalkthroughGuide,
        GuideErrorThrottle,
        RemoteFrameGuide
    ];
    
    /**
     * @description
     * Instantiates the correct guide class
     */
    function GuideFactory(guide) {
        return Guide.create(guide);
    }
    
    
    function AdvanceTrigger(element, method, step) {
        this.element = element;
    
        if (method == 'element')
            {this.method = 'click';}
        else if (method == 'hover')
            {this.method = 'mouseover';}
        else
            {this.method = method;}
    
        this.step = step;
        this.guide = step.getGuide();
    }
    
    AdvanceTrigger.prototype.add = function() {
        if (_.indexOf(this.guide.steps, this.step) === 0 && !AdvanceTrigger.shouldAttachHandler(this.guide, this.method)) return;
        if (!isBadge(this.guide) || isWalkthrough(this.guide)) {
            this.setupElementEvent(this.element, this.method);
        }
    };
    
    AdvanceTrigger.prototype.remove = function() {
        this.teardownElementEvent(this.element, this.method);
    };
    
    // HTBD: (aka Here There Be Dragons)
    // Instead of detaching on hide, we're going to leave the
    // attach live until it's either advanced, dismissed or
    // re-rendered.  The reason for this is it's too easy for
    // a race case to happen where the hide for this guide can
    // happen before the element click event happens and thus we
    // never get the onguideadvanced action being called.
    AdvanceTrigger.prototype.setupElementEvent = function(element, evt) {
        if (!this.advanceFn) {
            this.advanceFn = _.compose(
                _.bind(this.teardownElementEvent, this, element, evt),
                _.bind(this.step.advance, this.step)
            );
        }
    
        AdvanceTrigger.attach(this.step, element, evt, this.advanceFn);
    };
    
    AdvanceTrigger.prototype.teardownElementEvent = function(element, evt) {
        log('detach onGuideAdvanced', 'guide');
        detachEvent(element, evt, this.advanceFn, true);
    
        this.step.removeTrigger(this);
    };
    
    AdvanceTrigger.shouldAttachHandler = function shouldAttachHandler(guide, method) {
        return !guide.isActivatedByEvent(method) ||
            DOMActivation.activates(guide) ||
            (guide.attributes.activation.selector !== guide.steps[0].elementPathRule &&
             !!guide.attributes.activation.selector);
    };
    
    AdvanceTrigger.attach = function(step, element, evt, advanceFn) {
        if (!step) return;
    
        var handlers = AdvanceTrigger.handlers = AdvanceTrigger.handlers || {};
        var stepHandlers = handlers[step.id] = handlers[step.id] || [];
    
        for (var i = 0; i < stepHandlers.length; ++i) {
            var handler = stepHandlers[i];
            if (element === handler[0] && evt === handler[1]) {
                detachEvent(element, evt, handler[2], true);
                stepHandlers.splice(_.indexOf(stepHandlers, handler), 1);
                i--;
            }
        }
    
        stepHandlers.push([element, evt, advanceFn]);
    
        detachEvent(element, evt, advanceFn, true);
        attachEvent(element, evt, advanceFn, true);
    };
    
    /**
     * Runs the global script by script including it.
     * @param  {String} globalScriptUrl Where to load the global script from.
     * @return {Promise}
     */
    function loadGlobalScript(globalScriptUrl) {
        var deferred = q.defer();
        pendo.loadResource(globalScriptUrl, function() {
            deferred.resolve();
        });
        return deferred.promise;
    }
    
    /**
     * Validates the global script, if a validation handler is defined.
     * @param {Function} loadScript The actual script loading function.
     * @param  {String} globalScriptUrl Where to load the global script from.
     * @return {Promise}
     */
    function validateGlobalScript(loadScript, globalScriptUrl) {
        if (_.size(pendo.events._handlers.validateGlobalScript) > 0) {
            return pendo.ajax.get(globalScriptUrl).then(function(response) {
                return pendo.events.validateGlobalScript(response.data);
            }).then(function() {
                return loadScript(globalScriptUrl);
            });
        } else {
            return loadScript(globalScriptUrl);
        }
    }
    
    /**
     * Returns immediately if globalScriptUrl is falsy.
     * @param {Function} loadScript The actual script loading function.
     * @param  {String} globalScriptUrl Where to load the global script from, or falsy if there is no global script.
     * @return {Promise}
     */
    function ignoreEmptyGlobalScript(loadScript, globalScriptUrl) {
        if (!globalScriptUrl) {
            return q.resolve();
        } else {
            return loadScript(globalScriptUrl);
        }
    }
    
    /**
     * Validates and runs the global script exactly once per agent session.
     * @param  {String} globalScriptUrl Where to load the global script from, or falsy if there is no global script.
     * @return {Promise}
     */
    var loadGlobalScriptOnce = _.wrap(_.once(_.wrap(loadGlobalScript, validateGlobalScript)), ignoreEmptyGlobalScript);
    
    var EventRouter = function() {
        var self = this;
        this.eventable = Eventable.call({});
        this.eventable.on('pendoEvent', function(evt) {
            try {
                self.eventHandler(evt); 
            } catch (error) {
                var eventType = evt && evt.action || 'NO ACTION DEFINED';
                writeException(error, 'Error in Action ' + eventType);
            }
        });
    
        this.eventHandler = eventHandler;
        this.submitPoll = submitPoll;
        this.setElementDisplay = setElementDisplay;
        this.setElementAnimation = setElementAnimation;
        this.openLink  = openLink;
        this.goToStep = goToStep;
        this.searchGuides = searchGuides;
        this.searchAllTerms = searchAllTerms;
    
        function eventHandler(evt) {
            var containerJSON;
            if(!evt.ignore) {
                //eslint-disable-next-line default-case
                switch (evt.action) {
                case 'advanceGuide':
                    pendo.onGuideAdvanced(evt, evt.step);
                    break;
                case 'previousStep':
                    pendo.onGuidePrevious(evt, evt.step);
                    break;
                case 'goToStep':
                    this.goToStep(evt);
                    break;
                case 'submitPoll':
                    this.submitPoll(evt);
                    break;
                case 'dismissGuide':
                    BuildingBlockResourceCenter.attemptToPreserveIntegrationIframes(evt);
                    dismissGuide(evt);
                    break;
                case 'showElements':
                    this.setElementDisplay(evt, 'block');
                    containerJSON = BuildingBlockGuides.findGuideContainerJSON(evt.step.domJson);
                    BuildingBlockGuides.recalculateGuideHeight(containerJSON.props.id);
                    BuildingBlockGuides.flexAllThings(containerJSON.props.id);
                    break;
                case 'hideElements':
                    this.setElementDisplay(evt, 'none');
                    containerJSON = BuildingBlockGuides.findGuideContainerJSON(evt.step.domJson);
                    BuildingBlockGuides.recalculateGuideHeight(containerJSON.props.id);
                    BuildingBlockGuides.flexAllThings(containerJSON.props.id);
                    break;
                case 'slideElement':
                    this.setElementAnimation(evt);
                    break;
                case 'showGuide':
                    pendo.showGuideById(evt.params[0].value);
                    break;
                case 'launchGuide':
                    if(!window.pendo.designer) {
                        pendo.onGuideDismissed(evt, evt.step);
                        var shouldShowGuide = evt && evt.params && evt.params[0] && evt.params[0].value;
                        if (shouldShowGuide) pendo.showGuideById(evt.params[0].value);
                    }
                    break;
                case 'renderResourceCenterModule':
                    BuildingBlockResourceCenter.replaceResourceCenterContent(evt.params[0].value);
                    break;
                case 'returnToResourceCenterHome':
                    var resourceCenterHomeView = BuildingBlockResourceCenter.findResourceCenterHomeView(pendo.guides);
                    if(!resourceCenterHomeView) return;
    
                    BuildingBlockResourceCenter.attemptToPreserveIntegrationIframes(evt);
                    BuildingBlockResourceCenter.replaceResourceCenterContent(resourceCenterHomeView.id, evt.params);
    
                    break;
                case 'openFeedback':
                    Feedback.openFeedback(evt);
                    break;
                case 'openLink':
                    !window.pendo.designer && this.openLink(evt);
                    break;
                case 'searchGuides':
                    this.searchGuides(evt);
                    break;
                }
            }
        }
    
        function dismissGuide(evt) {
            if(!evt || !evt.step) {
                return pendo.onGuideDismissed();
            }
    
            var guideToDismiss = evt.step.getGuide();
    
            // If the guide we're dismissing is part of the resource center, always call dismiss on the home view
            if (guideToDismiss && guideToDismiss.attributes && guideToDismiss.attributes.resourceCenter) {
                var resourceCenterHomeView = BuildingBlockResourceCenter.findResourceCenterHomeView(pendo.guides);
                evt.step = resourceCenterHomeView.steps[0];
                return pendo.onGuideDismissed(evt, evt.step);
            }
    
            pendo.onGuideDismissed(evt, evt.step);
        }
    
        function submitPoll(evt) {
            var step = evt.step;
            var responses = [];
            // Yes No Poll
            if (evt.srcElement && evt.srcElement.getAttribute('data-pendo-poll-type') && evt.srcElement.getAttribute('data-pendo-poll-type') === 'yesNo') {
                var pollId = evt.srcElement.getAttribute('data-pendo-poll-id');
                var pollValue = evt.srcElement.value;
                responses.push({
                    'pollId': pollId,
                    'value':  parseInt(pollValue, 10)
                });
            }
    
            var questions = Sizzle('[data-pendo-poll-id]', step.guideElement[0]);
            responses = responses.concat(_.map(questions, function(question) {
                var input = Sizzle('textarea,input:text,select,input:radio:checked', question);
                if (input && input.length && input[0].value) {
                    var pollId = question.getAttribute('data-pendo-poll-id');
                    var curPoll = _.find(step.guide.polls, function(poll) {
                        return poll.id === pollId;
                    });
    
                    var pollValue = input[0].value;
                    if (curPoll && curPoll.numericResponses) {
                        pollValue = parseInt(pollValue, 10);
                    }
    
                    return {
                        'pollId': pollId,
                        'value':  pollValue
                    };
                }
            }));
    
            if (step.response && responses) {
                step.response(_.compact(responses));
            } else {
                pendo.log('[Agent] Error! Trying to submit a poll response but step does not have response function!');
            }
    
            step.advance();
        }
    
        function setElementDisplay(evt, displayProp) {
            var step = evt.step;
            var selectors = _.find(evt.params, function(param) {
                return param.name === 'selectors';
            }).value;
            var elems = dom(selectors, step.guideElement[0]);
    
            _.each(elems, function(elem) {
                elem.style.display = displayProp;
            });
        }
    
        function setElementAnimation(evt) {
            var selector = _.find(evt.params, function(param) {
                return param.name === 'selector';
            }).value;
    
            var elem = dom(selector, evt.step.guideElement[0])[0];
    
            var transition = _.find(evt.params, function(param) {
                return param.name === 'transition';
            }).value;
    
            var left = _.find(evt.params, function(param) {
                return param.name === 'left';
            }).value;
    
            elem.style.transition = transition;
            elem.style.left = left;
        }
    
        function openLink(evt) {
            var url = _.find(evt.params, function(param) {
                return param.name === 'url';
            }).value;
    
            var target = _.find(evt.params, function(param) {
                return param.name === 'target';
            }).value;
    
            window.open(url, target);
        }
    
        function searchAllTerms(haystack, currentGuideTerms, text) {
            if(!currentGuideTerms) return false;
            return currentGuideTerms.some(function(term) {
                return _.contains(haystack,(term)) && term === text;
            });
        }
    
        function searchGuides(evt) {
            var searchTerms = '';
            var searchText = evt.srcElement.value;
            var resourceCenterContainer = pendo.Sizzle('#pendo-resource-center-container')[0];
            var guides = pendo.dom(resourceCenterContainer).find('[id^="pendo-list-item-"]');
            var noMatchesInfo = pendo.dom(resourceCenterContainer).find('[id^="pendo-no-matches-container"]');
            var allSearchTerms = [];
    
            var noResultsFoundText = _.find(evt.params, function(obj) {return obj.name === 'searchTextInfo';});
            pendo.dom(noMatchesInfo[0].childNodes[0]).text(noResultsFoundText.value);
            var noMatches = true;
    
            if (guides) {
                for (var element in guides) {
                    if (element && guides[element]) {
                        // 1st order - partial text match; otherwise hide
                        if (pendo.dom(guides[element]).text()) {
                            if (pendo.dom(guides[element]).text().toLowerCase().indexOf(searchText.toLowerCase()) !== -1) {
                                pendo.dom(guides[element]).css({'display': 'list-item'});
                                noMatches = false;
                            }
                            else {
                                pendo.dom(guides[element]).css({'display': 'none'});
                            }
                        }
    
                        // 2nd order - all guides that fully match against one of a guides search terms
                        if (_.isFunction(guides[element].getAttribute)) {
                            searchTerms = guides[element].getAttribute('data-_pendo-text-list-item-1').split(',');
                            searchTerms.forEach(function(term) {
                                if (!_.contains(allSearchTerms, term)) allSearchTerms.push(term); //allSearchTerms is a collection of all unique terms
                            });
                        }
    
                        var isGuideMatch = this.searchAllTerms(allSearchTerms, searchTerms, searchText);
                        if (isGuideMatch && guides[element]) {
                            pendo.dom(guides[element]).css({'display': 'list-item'});
                            noMatches = false;
                        }
                        searchTerms = '';
                    }
                }
            }
            if (noMatches) {
                pendo.dom(noMatchesInfo[0]).css({'display': 'block'});
            } else {
                pendo.dom(noMatchesInfo[0]).css({'display': 'none'});
            }
        }
    
        function goToStep(evt) {
            var step = evt.step;
            var goToStepIdParam = _.find(evt.params, function(param) {
                return param.name === 'goToStepId';
            });
            var goToStepId = goToStepIdParam && goToStepIdParam.value;
            if (!goToStepId) {
                pendo.log('[Agent] Error! Trying to handle a goToStep action but event has no goToStepId param!');
                return;
            }
            if (goToStepId === step.id) {
                pendo.log('[Agent] Error! Trying to handle a goToStep action but goToStepId matches current step!');
                return;
            }
            var currentGuide = pendo.findGuideById(step.guideId);
            var goToStep = _.find(currentGuide.steps, function(stepItem) {
                return stepItem.id === goToStepId;
            });
            if (!goToStep) {
                pendo.log('[Agent] Error! Trying to handle a goToStep action but guide has no step matching provided goToStepId param!');
                return;
            }
            var goToStepIndex = _.indexOf(currentGuide.steps, goToStep);
            var currentIndex = _.indexOf(currentGuide.steps, step);
            evt.steps = Math.abs(goToStepIndex - currentIndex);
            if (currentIndex < goToStepIndex) {
                pendo.onGuideAdvanced(evt, step);
            } else {
                pendo.onGuidePrevious(evt, step);
            }
        }
    
        return this;
    };
    
    var DOMActivation = (function() {
        var iterator;
        var keyAttr = 'pendoTargetId';
        var maxTargets = 50;
    
        /*
        domActivatedGuides = [
            {
                id: 'aGuideId',
                events: ['click', 'mouseover'],
                selector: '.selector .for .target',
                targets: [array, of, dom, references]
            }
        ]
        */
        var domActivatedGuides = [];
    
        /*
        activationTargets = {
            aGuideId: 'aTargetId',
            aTargetId: {
                target: {{referenceToDomElement}},
                events: {
                    click: {
                        guideIds: {
                            aGuideId: 1,
                            anotherGuideId: 1
                        },
                        fn: {{partial(eventHandler, guideIds)}}
                    },
                    mouseover: {{same format as click}}
                }
            }
            {{more guide and target ids...}}
        }
        */
        var activationTargets = {};
    
        return {
            'key':       keyAttr,
            'guides':    domActivatedGuides,
            'targets':   activationTargets,
            'reset':     reset,
            'init':      init,
            'update':    update,
            'attach':    attachGuideToTarget,
            'detach':    detachGuideFromTarget,
            'handler':   eventHandler,
            'activates': activates
        };
    
        function attachGuideToTarget(target, domActivationGuide, activationTargets) {
            var targetKey = target[keyAttr];
            var handler = targetKey ? activationTargets[targetKey] : null;
    
            if (!handler) {
                targetKey = targetKey || 'target' + _.uniqueId();
                handler = {
                    'target': target,
                    'events': {}
                };
                activationTargets[targetKey] = handler;
                target[keyAttr] = targetKey;
            }
    
            var targetList = activationTargets[domActivationGuide.id] || [];
            targetList.push(targetKey);
            activationTargets[domActivationGuide.id] = targetList;
    
            _.each(domActivationGuide.events, function(eventType) {
                var eventTypeHandler = handler.events[eventType];
                if (!eventTypeHandler) {
                    eventTypeHandler = {
                        'guideIds': {}
                    };
                    eventTypeHandler.fn = _.partial(eventHandler, eventTypeHandler.guideIds);
                    attachEvent(target, eventType, eventTypeHandler.fn);
                    handler.events[eventType] = eventTypeHandler;
                }
                eventTypeHandler.guideIds[domActivationGuide.id] = 1;
            });
        }
    
        function detachGuideFromTarget(domActivationGuide, activationTargets) {
            _.each(activationTargets[domActivationGuide.id], function(targetKey) {
                var handler = targetKey ? activationTargets[targetKey] : null;
    
                if (handler) {
                    _.each(handler.events, function(eventTypeHandler, eventType) {
                        if (eventTypeHandler && eventTypeHandler.guideIds) {
                            delete eventTypeHandler.guideIds[domActivationGuide.id];
                            if (_.size(eventTypeHandler.guideIds) <= 0) {
                                detachEvent(handler.target, eventType, eventTypeHandler.fn);
                                delete handler.events[eventType];
                            }
                        }
                    });
    
                    if (_.size(handler.events) <= 0) {
                        delete handler.target[keyAttr];
                        handler.target = null;
                        delete activationTargets[targetKey];
                    }
                }
            });
    
            delete activationTargets[domActivationGuide.id];
        }
    
        function eventHandler(guideIds) {
            var guides = _.compact(_.map(_.keys(guideIds), function(id) {
                return pendo.findGuideById(id);
            }));
            guides = _.filter(guides, function(guide) {
                if (!guide.steps || !guide.steps.length) {
                    return false;
                }
                if (get(guide, 'attributes.dom.isOnlyShowOnce')) {
                    return !guide.steps[0].hasBeenSeen();
                }
                return true;
            });
            guides = _.sortBy(guides, function(guide) {
                return guide.state === 'staged' ? 0 : 1;
            });
            _.find(guides, function(guide) {
                var firstStep = _.first(guide.steps);
                if (firstStep.isShown()) return true;
                return showGuide(firstStep, 'dom');
            });
        }
    
        function reset() {
            _.each(domActivatedGuides, function(domActivationGuide) {
                detachGuideFromTarget(domActivationGuide, activationTargets);
                domActivationGuide.targets = [];
            });
            domActivatedGuides.length = 0;
            iterator = null;
        }
    
        function activates(guide) {
            if (!guide.id || !guide.steps || !guide.steps.length || !guide.hasLaunchMethod('dom')) return;
    
            var events = get(guide, 'attributes.activation.event', []);
            if (!events || !events.length) return;
    
            var selector = getActivationSelector(guide);
            if (!selector) return;
    
            return {
                'id':       guide.id,
                'events':   events,
                'selector': selector,
                'targets':  []
            };
        }
    
        function getActivationSelector(guideToActivate) {
            var activationSelector = get(guideToActivate, 'attributes.activation.selector');
            if (activationSelector) {
                return activationSelector;
            }
            return guideToActivate.steps[0].elementPathRule;
        }
    
        function init(guideList) {
            if (iterator) return;
    
            _.each(guideList, function(guide) {
                var domActivatedGuide = activates(guide);
                if (domActivatedGuide) {
                    domActivatedGuides.push(domActivatedGuide);
                }
            });
    
            iterator = throttleIterator(50, createStatefulIterator());
        }
    
        function arrayEquals(array1, array2) {
            if (array1.length != array2.length) return false;
    
            return _.all(array1, function(item, i) {
                return item === array2[i];
            });
        }
    
        function update(guideList, timeout) {
            init(guideList);
    
            iterator.eachUntil(domActivatedGuides, function(domActivationGuide) {
                var targets = Sizzle(domActivationGuide.selector);
    
                if (targets.length > maxTargets) {
                    targets.length = maxTargets;
                }
    
                if (!arrayEquals(targets, domActivationGuide.targets)) {
                    domActivationGuide.targets = targets;
    
                    detachGuideFromTarget(domActivationGuide, activationTargets);
    
                    _.each(targets, function(target) {
                        attachGuideToTarget(target, domActivationGuide, activationTargets);
                    });
                }
            });
        }
    })();
    
    var ScriptGuideLoader = {
        'load': function(url, callback) {
            return q.resolve(pendo.loadResource(url, callback));
        },
        'buildUrl': function(apiKey, params) {
            return buildBaseDataUrl('guide.js', apiKey, params);
        },
        'usesXhr': function() {
            return false;
        }
    };
    
    var GuideLoader = ScriptGuideLoader;
    
    var guideEvtCache = [];
    var activeElements = [];
    var detachGuideEventHandlers;
    var activeGuides = [];
    
    function getAssetHost() {
        var contentHost = getPendoConfigValue('contentHost');
        var protocol = getProtocol() + '//';
        if (contentHost) {
            return protocol + contentHost;
        }
        return getOption('contentHost', protocol + 'cdn.pendo.io');
    }
    
    function getDefaultCssUrl() {
        var assetHost = getAssetHost();
        if (/local\.pendo\.io/.test(assetHost)) {
            return assetHost + '/dist/guide.css';
        } else {
            return assetHost + '/agent/releases/2.54.0/guide.css';
        }
    }
    
    function replaceWithContentHost(str) {
        var contentHost = getOption('contentHost');
        if (!contentHost) return str;
        return str.replace(/(https:)?\/\/pendo-static-\d+\.storage\.googleapis\.com/g, contentHost)
            .replace(/(https:)?\/\/pendo-\w+-static\.storage\.googleapis\.com/g, contentHost)
            .replace(/(https:)?\/\/cdn\.pendo\.io/g, contentHost);
    }
    
    function getActiveGuides() {
        return activeGuides;
    }
    
    function setActiveGuides(guideArray) {
        activeGuides = guideArray;
    }
    
    var DEFAULT_GUIDE_SEEN_TIMEOUT_LENGTH = 10000;
    
    function getGuideSeenTimeoutLength() {
        return getPendoConfigValue('guideSeenTimeoutLength') || DEFAULT_GUIDE_SEEN_TIMEOUT_LENGTH;
    }
    
    var GUIDE_CSS_NAME = '_pendo-guide_';
    
    var GUIDE_ID_PREFIX = '_pendo_g_';
    
    var lastGuideStepSeen = null;
    
    // This is used to determine the duration of a guide event.
    // It gets set at the time a guide is shown and then used in
    // comparison with the time the guide is closed.
    var seenTime = 0;
    
    // Fix: this is a terrible name.
    var isGuideShown = function() {
        return _.any(getActiveGuides(), function(guide) {
            return guide.isShown();
        });
    };
    
    var addCloseButton = function(elem, cb) {
        var closeButton = dom('._pendo-close-guide_', elem);
        if (closeButton.length) {
            return closeButton[0];
        }
    
        closeButton = dom('<button>')
            .attr('id', '_pendo-close-guide_')
            .attr('aria-label', 'close')
            .addClass('_pendo-close-guide_')
            .html('&times;');
    
        if (isBrowserInQuirksmode()) { //Quirks mode
            if (msie > 9) { //IE10+, small offset from top
                closeButton.css({ 'top': 3 });
            }
        } else { // Standards mode
            // IE7 is (shockingly) fine with the defaults
            if (msie === 8) { //Big offset in IE8 (drop shadow part of guide container width/height)
                closeButton.css({ 'top': 9, 'right': 2 });
            } else if (msie === 9) { //IE9
                closeButton.css({ 'right': 2, 'top': 3 });
            } else if (msie > 9) { //IE10+, small offset from top
                closeButton.css({ 'top': 3 });
            }
        }
    
        //Attempt to append to the guide container, if found in the given element
        var container = dom('._pendo-guide-container_', elem)[0] || elem;
        closeButton.appendTo(container);
    
        closeButton[0].onclick = function() {
            cb();
        };
    
        return closeButton[0];
    };
    
    var findGuideBy = function(field, value) {
        var guides = getActiveGuides();
        for(var i = 0; i < guides.length; i++) {
            if(guides[i][field] === value) {
                return guides[i];
            }
        }
        return null;
    };
    
    var findGuideById = function(guideId) {
        return pendo.findGuideBy('id', guideId);
    };
    var findGuideByName = function(name) {
        return pendo.findGuideBy('name', name);
    };
    
    var findStepInGuide = function(guide, stepId) {
        if (guide && guide.id) {
            guide = findGuideById(guide.id);
            return guide.findStepById(stepId);
        }
    
        return null;
    };
    
    var _updateGuideStepStatus = function(guideId, stepId, seenState) {
        var step = pendo.findStepInGuide(findGuideById(guideId), stepId);
        if (step) {
            step.seenState = seenState;
        }
    };
    
    var getStepIdFromElement = function(element) {
        var stepIdPattern = new RegExp('^' + GUIDE_ID_PREFIX);
        while (element) {
            if (_.isString(element.id) && stepIdPattern.test(element.id)) {
                return element.id.replace(stepIdPattern, '');
            }
            element = element.parentNode;
        }
        return null;
    };
    
    function hideGuides(hideOptions) {
        _.each(getActiveGuides(), function(guide) {
            if (_.isFunction(guide.isShown) && guide.isShown()) {
                guide.hide(hideOptions);
            }
        });
    }
    
    var findStepForGuideEvent = function(evt, step) {
        if (evt && evt.guideId) {
            //The first parameter is a step
            step = evt;
            evt = null;
        }
    
        if (GuideStep.isGuideStep(step)) {
            //Step is already wrapped as GuideStep
            return step;
        }
    
        if (step) {
            //Return the step that was requested
            var guide = findGuideById(step.guideId);
            return guide && guide.findStepById(step.id);
        }
    
        var currentGuide = _.find(getActiveGuides(), function(guide) {
            return guide.isShown();
        });
    
        if (!currentGuide) {
            //Nothing is displayed
            return;
        }
    
        var stepId;
        if (evt) {
            //The first parameter is an event object, or an element
            stepId = getStepIdFromElement(evt.target || evt.srcElement || evt);
        }
    
        if (stepId) {
            step = currentGuide.findStepById(stepId);
            if (!step) {
                writeMessage('findStepForGuideEvent: step with id ' + stepId);
            }
        } else {
            // Return the first shown step
            step = _.find(currentGuide.steps, function(step) {
                return step.isShown();
            });
            if (!step) {
                writeMessage('findStepForGuideEvent: no step shown');
            }
        }
    
        return step;
    };
    
    /**
     * Removes event listeners from guide steps
     * @param {object} guideStep
     */
    var removeGuideEventListeners = function(guideStep) {
        var advEvt = guideStep.advanceMethod === 'element' ? 'click' : 'mouseover';
        var element = pendo.getElementForGuideStep(guideStep);
        if (guideStep.type === 'tooltip' && _.isFunction(guideStep.teardownElementEvent)) {
            guideStep.teardownElementEvent(element, advEvt);
        } else {
            detachEvent(element, advEvt, onGuideAdvanced, true);
        }
    };
    
    /*
     * Called when the user has dismissed the current displayed Guide
     *
     * NOTE: can be invoked by a click action so must be able to handle
     * receiving a click event.
     *
     * input: step being displayed in the guide
     * visitorId: the user that is being shown the guide
     *
     * output: none
     * side-effect(s): update the lastGuideStepSeen obj w/ guide step info
     *                 restart the start guides process (if it's stopped)
     *                 send event for the guide dismissal
     */
    var onGuideDismissed = function(evt, step) {
        var until = null;
        if (evt && evt instanceof Object && evt.until)
        {until = evt.until;}
    
        step = findStepForGuideEvent(evt, step);
    
        // still dismiss the guide.  and log the error.
        // leaving guides stopped is probably a good idea as there is
        // clearly something wrong
        if (!step || !step.id) {
            stopGuides();
            return;
        }
    
        if (step.isLocked()) {
            return;
        }
    
        if (until) {
            // TODO: define what options until should support
            step.hide({
                'stayHidden': true
            });
            return;
        }
    
        removeGuideEventListeners(step);
    
        var stepId = step.id;
        var guideId = step.guideId;
        var currentGuide = findGuideById(guideId);
        var firstStep = _.first(currentGuide && currentGuide.steps);
        var seenReason = firstStep && firstStep.seenReason;
        var language = currentGuide && currentGuide.language;
    
        dismissedGuide(guideId, stepId, pendo.get_visitor_id(), seenReason, language);
    
        var now = getNow();
        _updateGuideStepStatus(guideId, stepId, 'dismissed');
        var guide = _.isFunction(step.getGuide) && step.getGuide();
        var doNotResume = guide && guide.attributes && guide.attributes.doNotResume;
    
        if(!doNotResume) {
            lastGuideStepSeen = {
                'guideId':     guideId,
                'guideStepId': stepId,
                'time':        now,
                'state':       'dismissed',
                'seenReason':  seenReason,
                'visitorId':   pendo.get_visitor_id()
            };
        }
    
        writeLastStepSeenCache(lastGuideStepSeen);
    
        // maintain latestDismissedAutoAt client-side
        if (seenReason === 'auto') {
            writeLatestDismissedAutoAtCache(now);
        }
    
        step.hide();
    
        if (!isGuideShown()) {
            stopGuides();
            startGuides();
        }
    };
    
    var cleanupActiveGuide = function() {
        var activeObj = getActiveGuide();
        if (!activeObj) return;
    
        _.each(activeObj.steps, function(step) {
            var advEvt = step.advanceMethod == 'element' ? 'click' : 'mouseover';
            var element = pendo.getElementForGuideStep(step);
            if (step.type === 'tooltip' && _.isFunction(step.teardownElementEvent)) {
                step.teardownElementEvent(element, advEvt);
            } else {
                detachEvent(element, advEvt, onGuideAdvanced, true);
            }
        });
    };
    
    /*
     * Called when the user has advanced the current displayed Guide in a
     * multistep guide.
     *
     * NOTE: can be invoked by a click action so must be able to handle
     * receiving a click event.
     *
     * input: step being displayed in the guide
     * visitorId: the user that is being shown the guide
     *
     * output: none
     * side-effect(s): update the lastGuideStepSeen obj w/ guide step info
     *                 restart the start guides process (if it's stopped)
     *                 send event for the guide advancement
     */
    var onGuideAdvanced = function(evt, step, isIntermediateStep) {
        // clean up currently shown guide
        cleanupActiveGuide();
    
        log('onGuideAdvanced called', 'guides');
        step = findStepForGuideEvent(evt, step);
        if (!step) {
            log('missing step.  can\'t advance', ['guides', 'error']);
            stopGuides();
            writeMessage('onGuideAdvanced: missing step');
            return;
        }
    
        if (step.isLocked()) {
            return;
        }
    
        var currentGuide = findGuideById(step.guideId);
        var language = currentGuide && currentGuide.language;
    
        if (evt && _.isNumber(evt.steps) && evt.steps > 1) {
            //Advance more than one step
            var number = evt.steps - 1;
            var currentIndex = _.indexOf(currentGuide.steps, step);
            var destinationIndex = currentIndex + number;
            if (destinationIndex >= currentGuide.steps.length) {
                destinationIndex = currentGuide.steps.length - 1;
            }
            var lastStepIndexToAdvance = destinationIndex;
            if (evt.skip === true) {
                lastStepIndexToAdvance = currentIndex + 1;
            }
            //Advance intermediate steps
            for (var i = currentIndex; i < lastStepIndexToAdvance; ++i) {
                step = currentGuide.steps[i];
                advancedGuide(currentGuide.id, step.id, pendo.get_visitor_id(), step.seenReason, language, i !== currentIndex);
                _updateGuideStepStatus(currentGuide.id, step.id, 'advanced');
            }
            return onGuideAdvanced(currentGuide.steps[destinationIndex], step, true);
        }
    
        var stepId = step.id;
        var guideId = step.guideId;
        var firstStep = _.first(currentGuide && currentGuide.steps);
        var seenReason = firstStep && firstStep.seenReason;
    
        log('advancing guide');
        advancedGuide(guideId, stepId, pendo.get_visitor_id(), seenReason, language, isIntermediateStep);
        log('update guide status');
        _updateGuideStepStatus(guideId, stepId, 'advanced');
        var now = new Date().getTime();
        var guide = _.isFunction(step.getGuide) && step.getGuide();
        var doNotResume = guide && guide.attributes && guide.attributes.doNotResume;
    
        if (!doNotResume) {
            lastGuideStepSeen = {
                'guideId':     guideId,
                'guideStepId': stepId,
                'time':        now,
                'state':       'advanced',
                'seenReason':  seenReason,
                'visitorId':   pendo.get_visitor_id()
            };
        }
        writeLastStepSeenCache(lastGuideStepSeen);
    
        // maintain latestDismissedAutoAt client-side
        if (firstStep && firstStep.seenReason === 'auto') {
            writeFinalAdvancedAutoAtCache(now);
        }
    
        log('stop guide');
        stopGuides();
        log('start guides');
        startGuides();
    };
    
    var onGuidePrevious = function(evt, step) {
        step = findStepForGuideEvent(evt, step);
    
        if (!step) {
            stopGuides();
            writeMessage('onGuidePrevious: missing step');
            return;
        }
    
        var guideId = step.guideId;
        var currentGuide = findGuideById(guideId);
    
        var currentIndex = _.indexOf(currentGuide.steps, step);
        if (currentIndex === 0) {
            return;
        }
    
        var advEvt = step.advanceMethod == 'element' ? 'click' : 'mouseover';
        var element = pendo.getElementForGuideStep(step);
        if (step.type === 'tooltip' && _.isFunction(step.teardownElementEvent)) {
            step.teardownElementEvent(element, advEvt);
        } else {
            detachEvent(element, advEvt, onGuideAdvanced, true);
        }
    
        var stepsToGoBack = evt && _.isNumber(evt.steps) ? evt.steps : 1;
        var previousStep = currentGuide.steps[currentIndex - stepsToGoBack];
    
        _updateGuideStepStatus(step.guideId, step.id, 'active');
        _updateGuideStepStatus(previousStep.guideId, previousStep.id, 'active');
        var guide = _.isFunction(step.getGuide) && step.getGuide();
        var doNotResume = guide && guide.attributes && guide.attributes.doNotResume;
    
        if (!doNotResume) {
            lastGuideStepSeen = {
                'guideId':     previousStep.guideId,
                'guideStepId': previousStep.id,
                'time':        new Date().getTime(),
                'state':       'active',
                'visitorId':   pendo.get_visitor_id()
            };
        }
        writeLastStepSeenCache(lastGuideStepSeen);
        stopGuides();
        startGuides();
    };
    
    pendo._addCredits = function(elem) {
        if (dom('._pendo-credits_', elem).length) {
            return;
        }
    
        var credits = dom('<div>').addClass('_pendo-credits_')
            .html('<img src="' + getAssetHost() + '/img/tiny-logo.png" />')
            .css({
                'bottom': 0,
                'right':  pendo.TOOLTIP_ARROW_SIZE
            });
    
        activeElements.push(credits[0]);
        credits.appendTo(elem);
    };
    
    
    
    /*
     * TODO: refactor this.
     * override is really only used for steps with badges.
     *
     * need a way to check: is original element visible.
     * if so, rendering is a go.
     * then
     * where do we render?  find destination for that.
     */
    
    
    // this is used for rendering
    var getElementForGuideStep = function(step) {
        if (!step) {
            log('Can\'t get element for null step');
            return null;
        }
    
        var guide = step.getGuide();
    
        if (
            !step.overrideElement &&
            ((guide && guide.attributes && guide.attributes.type === 'building-block') ||
                !isWalkthrough(guide))
        ) {
            step.overrideElement = findBadgeForStep(step);
        }
    
        if(step.overrideElement) {
            return step.overrideElement;
        }
    
        return getElementForTargeting(step);
    };
    
    
    var getElementForTargeting = function(step) {
        try {
            var selector = step.elementPathRule || null;
            var results;
    
            if (selector)
            {results = Sizzle(selector);}
            else
            {results = [getBody()];}
    
            if (results.length === 0) {
                return null;
            }
            return _.first(results);
        } catch (e) {
            log('Invalid selector expression');
        }
    };
    
    function isDismissedUntilReload(step) {
        return step && step.attributes && step.attributes.stayHidden;
    }
    
    function isResourceCenterModule(step) {
        if (!step) return false;
    
        var guide = step.getGuide();
        return guide && guide.attributes && guide.attributes.resourceCenter && !guide.attributes.resourceCenter.isTopLevel;
    }
    
    var canStepBeRendered = function(step) {
        if (isResourceCenterModule(step)) return false;
        if (isDismissedUntilReload(step)) return false;
        if (!step.elementPathRule && (step.type === 'lightbox' || step.type === 'whatsnew')) return true;
    
        var elm = getElementForGuideStep(step);
        return isElementVisible(elm);
    };
    
    // ??? only tooltip?
    var getStepDivId = function(step) {
        return GUIDE_ID_PREFIX + step.id;
    };
    
    /*
     * watches the current displaying step to make sure the
     * element used to anchor it is still visible.  if the
     * anchor goes away the step should also go away.  it should
     * return to 'pending' state where it's waiting for the element
     * to reappear.
     *
     * input: step being displayed
     * output: --
     * side-effect: either a timeout to setup the next watch or
     * a stop / restart of guide processing
     */
    var setupWatchOnElement = function(step) {
        var element = step.element;
        var tooltip = _.first(Sizzle('#' + getStepDivId(step)));
    
        if (element && tooltip) {
            var isVisible = isElementVisible(element);
            if (isVisible || dom.hasClass(tooltip, 'mouseover')) {
                setTimeout(function() {
                    setupWatchOnElement(step);
                }, DEFAULT_TIMER_LENGTH);
                return;
            } else {
                if (step.hide) {
                    step.hide();
                    if (!isGuideShown()) {
                        stopGuides();
                        startGuides();
                    }
                } else {
                    //Case where this was called by the deprecated API
                    stopGuides();
                    startGuides();
                }
            }
        } else if (!element && tooltip) {
            if (step.hide) {
                step.hide();
                if (!isGuideShown()) {
                    stopGuides();
                    startGuides();
                }
            } else {
                stopGuides();
                startGuides();
            }
        }
    };
    
    var showPreview = function() {
        //Deprecated, selection module handles previewing now
        return false;
    };
    
    var findBadgeForStep = function(step) {
        return _.first(Sizzle('#_pendo-badge_' + step.id));
    };
    
    var showGuide = function(step, reason) {
        if (!step || !step.guideId) {
            return false;
        }
        var guide = findGuideById(step.guideId);
        if (!guide) {
            return false;
        }
        if (isGuideShown()) {
            var guideStep = findStepForGuideEvent();
            removeGuideEventListeners(guideStep);
            var isResourceCenter = guide && guide.attributes && guide.attributes.resourceCenter;
            if (!isResourceCenter) {
                hideGuides();
            }
        }
        guide.launch(reason);
        return guide.isShown();
    };
    
    var seenGuide = function(guideId, stepId, visitorId, reason, language, pollTypes) {
        var evt = createGuideEvent({
            'type':      'guideSeen',
            'guideId':   guideId,
            'stepId':    stepId,
            'visitorId': visitorId,
            'reason':    reason,
            'language':  language
        });
    
        if(pollTypes) {
            _.extend(evt.props, {
                'step_poll_types': pollTypes
            });
        }
    
        stageGuideEvent(evt);
    
        // XXX consider publishing an event guideShown
        // and then hook writing this up to that.
        writeLastStepSeenCache({
            'guideId':     guideId,
            'guideStepId': stepId,
            'time':        getNow(),
            'state':       'active',
            'seenReason':  reason,
            'visitorId':   pendo.get_visitor_id()
        });
    };
    
    function dismissedGuide(guideId, stepId, visitorId, seenReason, language) {
        var evt = createGuideEvent({
            'type':        'guideDismissed',
            'guideId':     guideId,
            'stepId':      stepId,
            'visitorId':   visitorId,
            'seen_reason': seenReason,
            'language':    language
        });
        stageGuideEvent(evt);
    }
    
    function advancedGuide(guideId, stepId, visitorId, seenReason, language, isIntermediateStep) {
        var evt = createGuideEvent({
            'type':        'guideAdvanced',
            'guideId':     guideId,
            'stepId':      stepId,
            'visitorId':   visitorId,
            'seen_reason': seenReason,
            'language':    language
        });
        stageGuideEvent(evt, null, isIntermediateStep);
    }
    
    function timeoutGuide(guideId, stepId, visitorId, seenReason, language, guideSeenTimeoutLength) {
        var evt = createGuideEvent({
            'type':                   'guideTimeout',
            'guideId':                guideId,
            'stepId':                 stepId,
            'visitorId':              visitorId,
            'seen_reason':            seenReason,
            'language':               language,
            'guideSeenTimeoutLength': guideSeenTimeoutLength
        });
        stageGuideEvent(evt);
    }
    
    var writeLastStepSeenCache = function(lastSeen) {
        var lastSeenJson = JSON.stringify(lastSeen);
        var ttl = 10 * 1000; // 10 secs
    
        log('writing ' + lastSeenJson + ' to a cookie named lastStepAdvanced for ' + ttl);
    
        agentStorage.write('lastStepAdvanced', lastSeenJson, ttl);
        setPreviewState(lastSeen, pendoLocalStorage);
    };
    
    function writeLatestDismissedAutoAtCache(time) {
        if (_.isFunction(time.getTime)) {
            time = time.getTime();
        }
        pendo.latestDismissedAutoAt = time;
        agentStorage.write('latestDismissedAutoAt', time, 10000);
    }
    
    function writeFinalAdvancedAutoAtCache(time) {
        if (_.isFunction(time.getTime)) {
            time = time.getTime();
        }
        pendo.finalAdvancedAutoAt = time;
        agentStorage.write('finalAdvancedAutoAt', time, 10000);
    }
    
    function createGuideEvent(name, guideId, stepId, visitorId, reason, language) {
        var params = name;
        if (typeof params !== 'object') {
            params = {
                'type':      name,
                'guideId':   guideId,
                'stepId':    stepId,
                'visitorId': visitorId,
                'language':  language
            };
        }
    
        if (reason) {
            params.reason = reason;
        }
    
        if (!_.isString(params.language)) {
            delete params.language;
        }
    
        var props = _.extend({
            'guide_id':      params.guideId,
            'guide_step_id': params.stepId
        }, _.omit(params, 'type', 'guideId', 'stepId', 'visitorId'));
    
        return EventTracer.addTracerIds({
            'type':         params.type,
            'visitor_id':   params.visitorId,
            'account_id':   pendo.get_account_id(),
            'browser_time': new Date().getTime(),
            'url':          pendo.url.externalizeURL(),
            'props':        props
        });
    }
    
    var stagedEventsTimer = null;
    var startStagedTimer = function(timeLimit) {
        window.clearTimeout(stagedEventsTimer);
        stagedEventsTimer = window.setTimeout(processGuideEventCache, timeLimit);
    };
    
    var stageGuideEvent = function(evt, delay, isIntermediateStep) {
        delay = delay || 500;
    
        evt.props.duration = isIntermediateStep ? 0 : (new Date().getTime() - seenTime);
        guideEvtCache.push(evt);
    
        startStagedTimer(delay);
    };
    
    var getNextStepInMultistep = function(lastSeen, urlToCheck) {
        if(lastSeen.state === 'dismissed') {
            return null;
        }
        // Show the next Guide
        var currentGuide = findGuideById(lastSeen.guideId);
        return currentGuide.nextStep(lastSeen, urlToCheck || pendo.getCurrentUrl());
    };
    
    var shouldAutoDisplayGuide = function(guide, urlToCheck) {
        var foundGuide = findGuideById(guide && guide.id);
        if (!foundGuide) {
            return false;
        }
        return foundGuide.shouldAutoDisplay(urlToCheck);
    };
    
    pendo.getCurrentUrl = function() {
        return pendo.normalizedUrl || pendo.url.get();
    };
    
    
    
    
    /*
     * Takes a Guide obj and determines if it's intended to be a Badge.
     */
    var isBadge = function(guide) {
        return guide && guide.launchMethod && guide.launchMethod.indexOf('badge') >= 0;
    };
    
    var isWalkthrough = function(guide) {
        return guide &&
            guide.isMultiStep &&
            !(guide.attributes && guide.attributes.type === 'group');
    };
    
    pendo.testUrlForStep = function(regexUrlRule, pageUrl) {
        if (!pendo.doesExist(regexUrlRule)) {
            return true;//Show guide on all pages
        }
    
        var regex = new RegExp(regexUrlRule);
        var normalizedUrl = null;
        var idxOfQ  = pageUrl.indexOf('?');
    
        if (idxOfQ == -1) {
            normalizedUrl = pageUrl;
        } else {
            var baseUrl = pageUrl.substr(0, idxOfQ);
            var qString = pageUrl.substr(idxOfQ + 1);
    
            var queries = qString.split('&');
    
            // non-fun stuff version
            normalizedUrl = baseUrl + '?' + queries.sort().join('&');
        }
    
        return regex.test(normalizedUrl);
    };
    
    pendo.showGuideByName = function(name) {
        var guide = pendo.findGuideByName(name);
        if (guide) {
            return showGuide(_.first(guide.steps));
        }
        return false;
    };
    
    pendo.showGuideById = function(id) {
        if (FrameController.isConnectedToMaster) {
            return FrameController.showGuideById(id);
        }
        var guide = pendo.findGuideById(id);
        if (guide) {
            return showGuide(_.first(guide.steps));
        }
        return false;
    };
    
    var applyLastAdvancedCache = function(lastGuideStepSeen) {
        var cookie = agentStorage.read('lastStepAdvanced') || JSON.stringify(getPreviewState(pendoLocalStorage));
        if (!cookie) return lastGuideStepSeen;
    
        var tuple = JSON.parse(cookie);
        if (!tuple) return lastGuideStepSeen;
    
        if (tuple.visitorId && tuple.visitorId !== pendo.get_visitor_id()) return lastGuideStepSeen;
    
        log('applying cookie to guide list ' + cookie);
    
        if (tuple[0]) { //Very temporary backwards compatibility, remove after 1.2.3 release
            tuple = {
                'guideId':     tuple[0],
                'guideStepId': tuple[1],
                'state':       'advanced',
                'time':        new Date().getTime()
            };
        }
    
        var guideId = tuple.guideId;
        var stepId = tuple.guideStepId;
    
        // checking / updating seenState in step list
        var guide = findGuideById(guideId);
        if (guide) {
            var firstStep = _.first(guide.steps);
            if (firstStep && tuple.seenReason) {
                firstStep.seenReason = tuple.seenReason;
            }
            var step = pendo.findStepInGuide(guide, stepId);
            if (step) {
                if (step.seenState != tuple.state) {
                    log('making sure that seenState = \'' + tuple.state + '\' for lastStepAdvanced: ' + stepId);
                    step.seenState = tuple.state;
                }
    
                var stepIndex = guide.steps.indexOf(step);
                _.each(guide.steps.slice(0, stepIndex), function(step) {
                    if (!_.contains(['advanced', 'dismissed'], step.seenState)) {
                        // Make sure steps before the last seen step are advanced so that we don't
                        // re-activate the guide when the last step is dismissed/advanced
                        // This is generally only a concern when skipping over multiple steps
                        step.seenState = 'advanced';
                    }
                });
            }
        }
    
        // updating lastGuideStepSeen
        log('updating lastGuideStepSeen so that the state matches our local value for ' + stepId);
        return _.extend(lastGuideStepSeen, tuple);
    };
    
    function applyTimerCache(timerValue, cachedTimerValue) {
        cachedTimerValue = parseInt(cachedTimerValue, 10);
        if (isNaN(cachedTimerValue) || !_.isNumber(cachedTimerValue)) return timerValue;
        if (_.isNumber(timerValue) && cachedTimerValue > timerValue) {
            return cachedTimerValue;
        }
        if (!_.isNumber(timerValue)) {
            return cachedTimerValue;
        }
        return timerValue;
    }
    
    var isMobileUserAgent = function() {
        if (isPreviewing() && getScreenDimensions().width <= 320) {
            return true;
        }
        return (/Android|webOS|iPhone|iPod|BlackBerry|IEMobile|Opera Mini/i).test(getUA());
    };
    
    var isPreviewing = function() {
        /*global selmo*/
        return (typeof selmo !== 'undefined' && !!selmo.isPreviewing);
    };
    
    var resetPendoUI = function() {
        stopGuides();
        clearLoopTimer();
        removeAllBadges();
        DOMActivation.reset();
        hideLauncher();
        flushLater();
    };
    
    var resetPendoContent = function() {
        // Nuke previous state from space
        if (pendo.guides) {
            activeGuides.length = 0;
            pendo.guides.length = 0;
            all_ob_guides.length = 0;
        }
    
        clearMode();
    };
    
    function postLoadGuideJs(url, payload, done) {
    
        return pendo.ajax.postJSON(url, payload)
            .then(function(response) {
                _.extend(pendo, response.data);
                done();
            });
    }
    
    var loadGuideJs = (function() {
        var mostRecentGuideRequestId;
        var restoreState;
        return function(apiKey, params, callback) {
            var guideRequestId = _.uniqueId();
            mostRecentGuideRequestId = guideRequestId;
    
            if (!isMetadataBlocked()) {
                var metadata = getMetadata();
                if (metadata) {
                    log('sending metadata: ' + JSON.stringify(metadata), ['guides', 'metadata']);
                    params.metadata = metadata;
                } else {
                    log('no metadata to send', ['guides', 'metadata']);
                }
            }
    
            // how to test size of params.  what is max size metadata can be?
    
            var jzb = pendo.compress(params);
    
            var queryString = {
                'jzb': jzb,
                'v':   VERSION,
                'ct':  (new Date()).getTime()
            };
    
            if (isDebuggingEnabled(true)) {
                // Include debug info from server
                queryString.debug = true;
            }
    
            var loader = previewGuideLoaderWrapper(GuideLoader, pendoLocalStorage);
            var url = loader.buildUrl(apiKey, queryString);
    
            var maxLength = 1000;
            if (url.length > maxLength) {
                debug('Max length exceeded for a guide.js request');
    
                params.url = limitURLSize(maxLength, params.url);
                jzb = pendo.compress(params);
    
                url = loader.buildUrl(apiKey, {
                    'jzb': jzb,
                    'v':   VERSION,
                    'ct':  (new Date()).getTime()
                });
            }
    
            var restoreStateForRacingRequests = function() {
                if (guideRequestId === mostRecentGuideRequestId) {
                    callback.apply(this, arguments);
                    /**
                     * AGENT-122 save the state of the pendo object if this
                     * is the response to the most recent guide request. If
                     * we get a response to an earlier request after this,
                     * then restore the saved state.
                     */
                    restoreState = backupObjectState(pendo, [
                        'guides',
                        'normalizedUrl',
                        'lastGuideStepSeen',
                        'guideWidget',
                        'throttling',
                        'autoOrdering',
                        'olark',
                        'globalJsUrl',
                        'segmentFlags',
                        'latestDismissedAutoAt',
                        'finalAdvancedAutoAt'
                    ]);
                } else if (_.isFunction(restoreState)) {
                    restoreState();
                }
            };
    
            var loadingPromise;
            var jwtOptions = getJwtInfoCopy();
    
            if (url.length > URL_MAX_LENGTH || !_.isEmpty(jwtOptions)) {
                url = buildBaseDataUrl('guide.json', apiKey, {
                    'v':  VERSION,
                    'ct': (new Date()).getTime()
                });
    
                var payload = _.extend({ 'events': jzb }, jwtOptions);
    
                loadingPromise = postLoadGuideJs(url, payload, restoreStateForRacingRequests);
            } else {
                loadingPromise = loader.load(url, restoreStateForRacingRequests);
            }
    
            return loadingPromise.fail(function(result) {
                if (result.status === 451) {
                    pendo.stopGuides();
    
                    pendo.stopSendingEvents();
    
                    log('not tracking visitor due to 451 response');
                }
    
                // passthrough rejections to subscribers
                return q.reject(result);
            });
        };
    })();
    
    function sortGuidesByPriority(guides) {
        _.each(guides, function(guide, i) {
            if (!guide.attributes) {
                guide.attributes = {};
            }
            if (isNaN(guide.attributes.priority) || !_.isNumber(guide.attributes.priority)) {
                guide.attributes.priority = i;
            }
        });
    
        guides.sort(function(guide1, guide2) {
            return guide2.attributes.priority - guide1.attributes.priority;
        });
    
        return guides;
    }
    
    function saveGuideShownState(guides) {
        var shownGuide = _.find(guides, function(guide) {
            return _.isFunction(guide.isShown) && guide.isShown();
        });
    
        if (!shownGuide) {
            return function nullRestoreGuideShownState() {};
        }
    
        var shownStepIds = _.chain(shownGuide.steps).filter(function(step) {
            return step.isShown();
        }).indexBy('id').value();
    
        return function restoreGuideShownState(guides) {
            var sameGuide = _.findWhere(guides, { 'id': shownGuide.id });
    
            if (!sameGuide) return;
    
            if(get(sameGuide, 'attributes.doNotResume')) return;
    
            _.each(sameGuide.steps, function(step) {
                var previouslyShownStep = shownStepIds[step.id];
                if (!previouslyShownStep) return;
                if (step.seenState && step.seenState !== 'active') return;
                step.show(previouslyShownStep.seenReason);
            });
        };
    }
    
    var shouldLoadGlobalCSS = function() {
        var localSetting = getOption('disableGlobalCSS');
        if (_.isBoolean(localSetting)) {
            return !localSetting;
        }
        return !getPendoConfigValue('disableGlobalCSS', false);
    };
    
    var loadGuides = function(apiKey, visitorId, page, callback) {
        var deferred = q.defer(),
            timedOut = false,
            timeout;
    
        log('loading guides for ' + page + '...', 'guides');
    
        // use Defaults when needed
        apiKey    = apiKey || pendo.apiKey;
        visitorId = visitorId || pendo.get_visitor_id();
        page      = pendo.url.externalizeURL(page);
    
        var restoreGuideShownState = loadGuides.lastVisitorId === visitorId ? saveGuideShownState(activeGuides) : _.noop;
        loadGuides.lastVisitorId = visitorId;
    
        resetPendoUI();
        resetPendoContent();
    
        if (!isURLValid(getURL())) {
            log('bad url:  probably local file system', 'guides', 'error');
            if (_.isFunction(callback)) {
                callback('error: invalid url');
            }
            deferred.reject();
            return deferred.promise;
        }
    
        var params = {
            'visitorId': visitorId,
            'accountId': pendo.get_account_id(),
            'url':       page
        };
    
        FrameController.loadingGuideList();
    
        loadGuideJs(apiKey, params,  function() {
            if (!timedOut && isUnlocked()) {
                pendo.events.deliverablesLoaded();
    
                log('successfully loaded guides for ' + page, 'guides');
                if(window.pendo.designerEnabled && !(pendoLocalStorage.getItem('pendo-designer-mode') === 'true')) {
                    // This is important for iframes that load after the designer has already loaded.
                    // Once guide.js comes back with pendo.designerEnabled, we'll attempt to broadcast that the frame has joined,
                    // so that the designer can orchestrate its plugins in that frame
                    pendo.P2AutoLaunch.attemptToLaunch();
                }
                resetPendoUI();
                lastGuideStepSeen = preparePreviewLastGuideStepSeen(pendoLocalStorage, pendo.guides, pendo.lastGuideStepSeen);
    
                activeGuides = _.map(pendo.guides, GuideFactory);
                activeGuides = preparePreviewGuide(window, activeGuides);
                activeGuides = sortGuidesByPriority(activeGuides);
    
                lastGuideStepSeen.visitorId = visitorId;
                lastGuideStepSeen = applyLastAdvancedCache(lastGuideStepSeen);
                pendo.latestDismissedAutoAt = applyTimerCache(
                    pendo.latestDismissedAutoAt, agentStorage.read('latestDismissedAutoAt'));
                pendo.finalAdvancedAutoAt = applyTimerCache(
                    pendo.finalAdvancedAutoAt, agentStorage.read('finalAdvancedAutoAt'));
    
                // This needs to run *immediately* when pendo.guides changes
                // so pendo.events.guidesLoaded() doesn't cut it, since it
                // waits for a bunch of other stuff to load
                FrameController.updateGuideList(activeGuides);
                // define event properties to be consumed during handle_event
                pendo.eventProperties = createEventPropertiesFromFeatures(pendo.features);
    
                if (activeGuides.length) {
                    q.all([
                        loadGuideCss(),
                        loadGlobalScriptOnce(replaceWithContentHost(pendo.globalJsUrl)),
                        loadLauncherContent(upgradeLauncher(pendo.guideWidget, activeGuides)),
                        initializeResourceCenter(pendo.guides),
                        BuildingBlockWatermark.initializeWatermark(pendo.guides),
                        waitForGlobalCssToLoad(5000)
                    ]).then(function() {
                        initLauncher();
    
                        restoreGuideShownState(activeGuides);
                        prefetchDomActivatedGuideContent(activeGuides);
    
                        pendo.events.guidesLoaded();
                        startGuides();
    
                        clearTimeout(timeout);
    
                        if (_.isFunction(callback)) {
                            callback();
                        }
    
                        deferred.resolve();
                    }, function() {
                        pendo.events.guidesFailed();
                        deferred.reject();
                    });
                } else {
                    pendo.events.guidesLoaded();
                    deferred.resolve();
                }
            }
        });
    
        var guideTimeout = getOption('guideTimeout') || getOption('guides.timeout');
        if (_.isNumber(guideTimeout)) {
            timeout = setTimeout(function() {
                timedOut = true;
                deferred.reject();
            }, guideTimeout);
        }
    
        return deferred.promise;
    };
    
    function loadExternalCss(id, cssUrl) {
        var link = document.getElementById(id);
        if (link && link.href && link.href.indexOf(cssUrl) >= 0) { // Only load the CSS once
            return q.resolve();
        } else {
            var deferred = q.defer();
            dom(link).remove();
            var style = pendo.loadResource(cssUrl + '?ct=' + getNow(), function() {
                deferred.resolve();
            });
            style.id = id;
            return deferred.promise;
        }
    }
    
    function waitForGlobalCssToLoad(timeout, nowFn, sentinelClass) {
        if(!shouldLoadGlobalCSS()) {
            return q.resolve();
        }
        nowFn = nowFn || getNow;
        sentinelClass = sentinelClass || '_pendo-hidden_';
        var cssLoadSentinel = dom('<div>')
            .addClass(sentinelClass)
            .css({
                'position':   'absolute',
                'bottom':     '0px',
                'right':      '0px',
                'width':      '0px',
                'height':     '0px',
                'visibility': 'hidden'
            })
            .appendTo(getGuideAttachPoint());
    
    
        var startTime = nowFn();
        var deferred = q.defer();
        pollForDisplayNone(0);
        return deferred.promise;
    
        function pollForDisplayNone(delay) {
            setTimeout(function() {
                if (hasDisplayNone(cssLoadSentinel[0])) {
                    cssLoadSentinel.remove();
                    deferred.resolve();
                } else if (nowFn() - startTime > timeout) {
                    cssLoadSentinel.remove();
                    deferred.reject();
                } else {
                    pollForDisplayNone(100);
                }
            }, delay);
        }
    
        function hasDisplayNone(elem) {
            var style = getComputedStyle_safe(elem);
            if (!style) return;
            return style.display === 'none';
        }
    }
    
    function loadGuideCss() {
        var promises = [];
    
        if(!shouldLoadGlobalCSS()) {
            return q.resolve();
        }
    
        promises.push(loadExternalCss('_pendo-default-css_', getDefaultCssUrl()));
    
        var guideWidget = pendo.guideWidget || {};
        var data = guideWidget.data || {};
        var customCssUrl = data.guideCssUrl;
        var customCssId = '_pendo-css_';
        if (customCssUrl) {
            promises.push(loadExternalCss(customCssId, replaceWithContentHost(customCssUrl)));
        } else {
            dom('#' + customCssId).remove();
        }
    
        return q.all(promises);
    }
    
    var processGuideEventCache = function() {
        var events = [].concat(guideEvtCache);
        guideEvtCache = [];
    
        if (events.length > 0) {
            _.map(events, writeGuideEvent);
        }
    };
    
    var getGuideEventCache = function() {
        return guideEvtCache;
    };
    
    var initializeResourceCenter = function(guides) {
        return pendo.BuildingBlocks.BuildingBlockResourceCenter.initializeResourceCenter(guides);
    };
    
    var initGuides = function() {
        guideEvtCache = [];
    
        attachEvent(window, 'unload', processGuideEventCache);
    
        // Override tooltip size from options hash
        var arrowSize = getOption('guides.tooltip.arrowSize');
        if (_.isNumber(arrowSize)) {
            pendo.TOOLTIP_ARROW_SIZE = arrowSize;
        }
    
        FrameController.init();
    };
    
    var areGuidesDisabled = function() {
        return getOption('guides.disabled', false) || getOption('disableGuides', false) || !pendoCore;
    };
    
    var areGuidesDelayed = function() {
        return getOption('guides.delay', false) || getOption('delayGuides', false);
    };
    
    var setGuidesDisabled = function(areDisabled) {
        originalOptions.disableGuides = areDisabled;
    };
    
    function prefetchDomActivatedGuideContent(guides) {
        _.each(guides, function(guide) {
            if (!_.isFunction(guide.hasLaunchMethod) || !guide.hasLaunchMethod('dom')) return;
            if (!guide.steps || !guide.steps.length || !_.isFunction(guide.steps[0].fetchContent)) return;
            guide.steps[0].fetchContent();
        });
    }
    
    var createEventPropertiesFromFeatures = makeSafe(function(features) {
        if(!features || !features.length) { return; }
        var result = [];
        for (var index = 0; index < features.length; index++) {
            var rules = features[index].featureRule;
            var eventProperties = _.map(
                features[index].eventProperties,
                function parseEPRule(eventPropertyConfig) {
                    if (eventPropertyConfig.selector) {
                        return eventPropertyConfig;
                    } else if (JSON && JSON.parse && eventPropertyConfig.rule) {
                        return JSON.parse(eventPropertyConfig.rule);
                    }
                }
            );
            result.push({'featureRules': rules, 'eventPropertyRules': eventProperties, 'featureId': features[index].featureId});
        }
        return result;
    });
    
    function getGuideAttachPoint() {
        var attachPoint = getGuideAttachPoint.attachPoint;
    
        if (attachPoint == null) {
            var attachPointSelector = getOption('guides.attachPoint');
    
            if (attachPointSelector) {
                try {
                    attachPoint = Sizzle(attachPointSelector)[0];
                } catch (e) {
                    log('Error finding guide attach point "' + attachPointSelector + '"');
                }
    
                if (!attachPoint) {
                    attachPoint = document.createElement('div');
                }
            } else {
                attachPoint = false;
            }
    
            getGuideAttachPoint.attachPoint = attachPoint;
        }
    
        return attachPoint || getBody();
    }
    
    var pendoPreview = 'pendo-preview';
    
    function startPreviewMode(window) {
        if (detectMaster()) return;
    
        var config = findUrlPreviewConfig(window.location.search) || findStoredPreviewConfig(pendoLocalStorage);
        if (!config) return;
    
        var previewFrame = document.getElementById(pendoPreview);
        if (previewFrame) return true;
    
        if (pendoLocalStorage && _.isFunction(pendoLocalStorage.setItem)) {
            pendoLocalStorage.setItem(pendoPreview, JSON.stringify(_.extend(config, { 'apiKey': pendo.apiKey })));
        }
    
        if (_.isFunction(window.addEventListener)) {
            window.addEventListener('message', previewMessageHandler);
        }
    
        getBody().appendChild(createPreviewBar());
    
        return true;
    }
    
    function launchPreviewListener(msg) {
        if (!msg || !msg.data) return;
        if (msg.data.type === pendoPreview + '::launch') {
            pendoLocalStorage.setItem(pendoPreview, JSON.stringify(_.extend({ 'apiKey': pendo.apiKey, 'origin': msg.origin }, msg.data.config)));
            if (startPreviewMode(window)) {
                msg.source.postMessage({
                    'type':      pendoPreview + '::ready',
                    'apiKey':    pendo.apiKey,
                    'accountId': pendo.accountId
                }, '*');
                forceGuideReload();
                FrameController.startPreview();
            }
        }
    }
    
    function restartPreview(pendoLocalStorage, activeGuides, lastGuideStepSeen) {
        hideGuides();
        var guide = activeGuides[0];
        var step = guide.steps[0];
        step.seenState = null;
        return preparePreviewLastGuideStepSeen(pendoLocalStorage, activeGuides, lastGuideStepSeen);
    }
    
    function resizePreview(height) {
        var previewFrame = document.getElementById(pendoPreview);
        if (!previewFrame) return;
        previewFrame.style.height = height;
    }
    
    function previewMessageHandler(e) {
        var type = e.data.type;
        if (type === pendoPreview + '::exit') {
            exitPreviewMode();
            FrameController.stopPreview();
        } else if (type === pendoPreview + '::restart') {
            lastGuideStepSeen = restartPreview(pendoLocalStorage, activeGuides, lastGuideStepSeen);
            FrameController.restartPreview();
        } else if (type === pendoPreview + '::resize') {
            resizePreview(e.data.height);
        }
    }
    
    function isInPreviewMode() {
        try {
            return !!findStoredPreviewConfig(pendoLocalStorage);
        } catch (e) {
            return false;
        }
    }
    
    function setPreviewState(state, localStorage) {
        var config = findStoredPreviewConfig(localStorage);
        if (!config) return;
        config.state = state;
        if (localStorage && _.isFunction(localStorage.setItem)) {
            localStorage.setItem(pendoPreview, JSON.stringify(config));
        }
    }
    
    function getPreviewState(localStorage) {
        var config = findStoredPreviewConfig(localStorage);
        if (!config) return;
        return config.state;
    }
    
    function createPreviewBar() {
        var frame = document.createElement('iframe');
        frame.id = pendoPreview;
        frame.src = 'about:blank';
        _.extend(frame.style, {
            'position': 'fixed',
            'top':      0,
            'left':     0,
            'right':    0,
            'width':    '100%',
            'height':   '60px',
            'border':   'none',
            'z-index':  400000
        });
    
        frame.onload = function() {
            var script = document.createElement('script');
            script.src = getAssetHost() + '/agent/releases/2.54.0/pendo.preview.min.js';
            frame.contentDocument.body.appendChild(script);
        };
    
        return frame;
    }
    
    function preparePreviewGuide(window, activeGuides) {
        var config = findStoredPreviewConfig(pendoLocalStorage);
        if (!config) return activeGuides;
    
        var previewGuides = _.map(_.filter(activeGuides, function(guide) {
            return guide.id === config.guideId;
        }), function(guide) {
            _.each(guide.steps, function(step) {
                step.seenState = step.id === config.stepId ? null : 'advanced';
            });
            guide.launchMethod = getPreviewLaunchMethod(guide.launchMethod);
            return guide;
        });
    
        return previewGuides;
    }
    
    function getPreviewLaunchMethod(launchMethod) {
        if (/badge/.test(launchMethod) && /auto/.test(launchMethod)) {
            return 'auto-badge';
        } else if (/badge/.test(launchMethod)) {
            return 'badge';
        } else if (/dom/.test(launchMethod)) {
            return 'dom';
        } else {
            return 'auto';
        }
    }
    
    function preparePreviewLastGuideStepSeen(pendoLocalStorage, activeGuides, lastGuideStepSeen) {
        var config = findStoredPreviewConfig(pendoLocalStorage);
        if (!config) return lastGuideStepSeen;
    
        var previewGuide = _.findWhere(activeGuides, { 'id': config.guideId });
        if (!previewGuide) return lastGuideStepSeen;
    
        if (!/auto/.test(previewGuide.launchMethod) && config.stepId === previewGuide.steps[0].id) return {};
    
        return {
            'guideId':     config.guideId,
            'guideStepId': config.stepId,
            'state':       'active'
        };
    }
    
    function updatePreview(document, activeGuides, lastGuideStepSeen) {
        var previewFrame = document.getElementById(pendoPreview);
        if (!previewFrame || !previewFrame.contentWindow) return;
        if (!activeGuides || !activeGuides.length) {
            previewFrame.contentWindow.postMessage({
                'action':  'preview/setError',
                'payload': {
                    'error': 'guideNotFound'
                }
            }, '*');
            return;
        }
    
        var guide = activeGuides[0];
        var currentStep = 0;
        var stepCount = guide.steps.length;
        var lastSeen = lastGuideStepSeen || {};
        _.find(guide.steps, function(step, i) {
            if (lastSeen.guideStepId !== step.id) return false;
            if (lastSeen.state === 'dismissed') {
                currentStep = stepCount;
            } else if (lastSeen.state === 'active') {
                currentStep = i + 1;
            } else {
                currentStep = i + 2;
            }
            return true;
        });
        var step = guide.steps[currentStep - 1];
        var completed = lastSeen.state === 'dismissed' || currentStep > stepCount;
    
        previewFrame.contentWindow.postMessage({
            'action':  'preview/updateGuideName',
            'payload': {
                'guideName': guide.name
            }
        }, '*');
    
        previewFrame.contentWindow.postMessage({
            'action':  'preview/updateGuideProgress',
            'payload': {
                'stepId':      step && step.id,
                'currentStep': Math.max(1, Math.min(currentStep, stepCount)),
                'stepCount':   stepCount,
                'completed':   completed
            }
        }, '*');
    
        checkForGuidePreviewError(step, completed, previewFrame);
    }
    
    function adjustPreviewBarPosition() {
        var previewFrame = document.getElementById(pendoPreview);
        if (!previewFrame) return;
        var guideElement = _.first(Sizzle('[id^="pendo-g-"]'));
        if (!guideElement) return;
        var computedStyle = getComputedStyle_safe(guideElement);
        if (!computedStyle) return;
    
        if (computedStyle.top === '0px') {
            previewFrame.style.top = 'auto';
            previewFrame.style.bottom = '0px';
        } else if(computedStyle.bottom === '0px' || !previewFrame.style.top) {
            previewFrame.style.top = '0px';
            previewFrame.style.bottom = 'auto';
        } else {
            // Do nothing, maintain its position
        }
    }
    
    function checkForGuidePreviewError(activeStep, completed, previewFrame) {
        if (!activeStep) return;
    
        if (isGuideShown() || completed) {
            previewFrame.contentWindow.postMessage({
                'action': 'preview/clearError'
            }, '*');
            return;
        }
    
        if (_.isFunction(activeStep.canShowOnPage) && !activeStep.canShowOnPage(pendo.getCurrentUrl())) {
            previewFrame.contentWindow.postMessage({
                'action':  'preview/setError',
                'payload': {
                    'error': 'pageMismatch'
                }
            }, '*');
            return;
        }
    
        if (activeStep.elementPathRule) {
            var targetedElement = _.first(pendo.Sizzle(activeStep.elementPathRule));
            if (!targetedElement) {
                previewFrame.contentWindow.postMessage({
                    'action':  'preview/setError',
                    'payload': {
                        'error': 'elementNotFound'
                    }
                }, '*');
                return;
            }
    
            if (!isElementVisible(targetedElement)) {
                previewFrame.contentWindow.postMessage({
                    'action':  'preview/setError',
                    'payload': {
                        'error': 'elementNotVisible'
                    }
                }, '*');
                return;
            }
        }
    }
    
    function exitPreviewMode() {
        if (pendoLocalStorage && _.isFunction(pendoLocalStorage.removeItem)) {
            pendoLocalStorage.removeItem(pendoPreview);
        }
        buffersClearAll();
        dom('#' + pendoPreview).remove();
        forceGuideReload();
        window.close();
    }
    
    function parsePreviewToken(token) {
        try {
            return JSON.parse(atob(decodeURIComponent(token)));
        } catch (e) {
        }
    }
    
    function findUrlPreviewConfig(locationSearch) {
        var pairs = _.map(locationSearch.replace(/^\?/, '').split('&'), function(keyVal) {
            return keyVal.split('=');
        });
        var preview = _.find(pairs, function(pair) {
            return pair[0] === pendoPreview;
        });
        if (!preview) return;
        return parsePreviewToken(preview[1]);
    }
    
    function findStoredPreviewConfig(localStorage) {
        try {
            var config = JSON.parse(localStorage.getItem(pendoPreview));
            if (config.apiKey === pendo.apiKey) return config;
        } catch (e) {
        }
    }
    
    function previewGuideRequest(config) {
        return pendo.ajax({
            'url':             config.origin + config.guideUrl + '?url=' + encodeURIComponent(pendo.url.get()),
            'withCredentials': true
        }).then(function(response) {
            pendo.guides = [response.data.guide];
            pendo.guideWidget = {
                'enabled': false,
                'data':    {
                    'guideCssUrl': response.data.guideCssUrl
                }
            };
            pendo.guideCssUrl = response.data.guideCssUrl;
            pendo.normalizedUrl = response.normalizedUrl;
            return response;
        });
    }
    
    function previewGuideLoaderWrapper(GuideLoader, localStorage) {
        return {
            'buildUrl': GuideLoader.buildUrl,
            'load':     function(url, callback) {
                var config = findStoredPreviewConfig(localStorage);
                if (!config || !config.guideUrl) return GuideLoader.load(url, callback);
                return previewGuideRequest(config).then(callback);
            }
        };
    }
    
    var pendoDesignerLaunchKey = 'pendo-designer-launch';
    
    
    function launchDesignerListener(msg) {
        if (!msg || !msg.data || !msg.data.token) return;
        if (msg.data.type === pendoDesignerLaunchKey + '::launch') {
            var token = msg.data.token;
            var launchOptions = {
                'lookaside': token.baseUrl,
                'host':      token.host,
                'target':    token.target || 'latest'
            };
            pendo.designerv2.launchInAppDesigner(launchOptions);
        }
    }
    
    /*
    * Guide Loop
    *
    * The function that gets called to process and handle the ever
    * changing landscape of a web app to best handle showing / hiding of
    * guides as needed.
    */
    
    /*
     * Holds the timeout handle for the startGuides process.
     * This should work as a simple monitor on that process
     * to prevent it from being run too often.
     */
    pendo.guidesProcessingThreadHandle = null;
    
    var DEFAULT_TIMER_LENGTH = 500;
    var waitThenLoop = function(delayAmount) {
        delayAmount = delayAmount || DEFAULT_TIMER_LENGTH;
        pendo.guidesProcessingThreadHandle = _.delay(function() {
            pendo.guidesProcessingThreadHandle = null;
            startGuides();
        }, delayAmount);
    };
    
    var clearLoopTimer = function() {
        if (pendo.guidesProcessingThreadHandle) {
            clearTimeout(pendo.guidesProcessingThreadHandle);
            pendo.guidesProcessingThreadHandle = null;
        }
    };
    
    var stopGuides = function() {
        AutoDisplay.reset();
    
        hideGuides();
    
        // Remove other stuff.
        for(var i = 0; i < activeElements.length; i++) {
            var elem = activeElements[i];
            elem.parentNode.removeChild(elem);
        }
    
        activeElements.length = 0;
    };
    
    var currentMode = 'default';
    var modeProcMap = {};
    var registerMode = function(name, proc) {
        modeProcMap[name] = proc;
    };
    
    var setMode = function(mode) {
        if (!mode || mode == 'default') {
            currentMode = 'default';
            return;
        }
        if (!modeProcMap[mode]) {
            //eslint-disable-next-line no-alert
            alert('Bad Mode: ' + mode);
            return;
        }
        currentMode = mode;
    };
    
    var getMode = function() {
        return currentMode;
    };
    pendo.getMode = getMode;
    
    function clearMode() {
        if (FrameController.isConnectedToMaster) {
            setMode(FrameController.SLAVE_MODE);
        } else {
            setMode('default');
        }
    }
    
    /*
     * starts the process that loops over all available guides and
     * determines what if anything needs to be done.
     *
     * Handles checking for multistep guide continuation, automatically
     * shown guides, launcher guides, and badges.
     */
    var startGuides = function() {
        clearLoopTimer();
    
        if (areGuidesDisabled()) {
            log('guides are disabled.', 'guides', 'disabled');
            return;
        }
    
        if (areGuidesDelayed()) {
            log('guides are delayed.', 'guides', 'delayed');
            return;
        }
    
        try {
            var activeGuides = getActiveGuides();
            if (!activeGuides || activeGuides.length === 0) return;
    
            getLoopProc()(activeGuides);
        } catch (e) {
            writeException(e, 'ERROR in guide-loop');
        } finally {
            waitThenLoop();
        }
    };
    
    /*
     * If delayGuides is true, removes the delay and starts guides.
     * Otherwise, it is the same as calling startGuides.
     */
    var manuallyStartGuides = function() {
        if (getOption('delayGuides')) {
            delete originalOptions.delayGuides;
        }
        if (getOption('guides.delay')) {
            delete originalOptions.guides.delay;
        }
        startGuides();
    };
    
    var getLoopProc = function() {
    
        if (modeProcMap[currentMode])
        {return modeProcMap[currentMode];}
    
        return defaultLoopProc;
    };
    
    var defaultLoopProc = function(guidesList) {
        placeBadgesProc(guidesList);
    
        DOMActivation.update(guidesList);
    
        launcherProc(guidesList);
        resourceCenterProc(BuildingBlockResourceCenter.getResourceCenter());
    
        FrameController.updateFrameVisibility();
    
        if (isGuideShown()) {
            guideShowingProc();
        } else {
            noGuideShowingProc(guidesList);
        }
    
        updatePreview(document, guidesList, lastGuideStepSeen);
    };
    
    /**
     * Runs on a timer whenever a guide is displayed.
     * @param  {Guide} guide The currently visible guide
     * @param  {GuideStep} step The currently visible step
     */
    function guideShowingProc() {
        var active = getActiveGuide();
        _.each(active.steps, function(step) {
            stepShowingProc(active.guide, step);
        });
        active.guide.checkForHiddenGroupSteps();
    }
    
    function stepShowingProc(guide, step) {
        if (step.isLocked()) {
            return;
        }
    
        if (FrameController.isShownInAnotherFrame(step)) {
            return;
        }
    
        var element = step.element;
        var guideElm = dom('.' + GUIDE_CSS_NAME);
        if (element && (isElementVisible(element) || guideElm.hasClass('mouseover'))) {
            // check placement
            if (step.type == 'tooltip') {
                placeTooltip(step);
            }
    
            if (step.domJson) {
                if (step.attributes.calculatedType === 'tooltip') {
                    var guideContainerJSON = BuildingBlockGuides.findGuideContainerJSON(step.domJson);
                    var guideContainer = dom('#' + guideContainerJSON.props.id);
                    pendo.BuildingBlocks.BuildingBlockTooltips.placeBBTooltip(step, guideContainer[0]);
                }
    
                if(step.attributes.blockOutUI && step.attributes.blockOutUI.enabled) {
                    pendo.BuildingBlocks.BuildingBlockGuides.updateBackdrop(step);
                }
            }
    
            return;
        }
    
        if ((step.type === 'tooltip' || step.attributes.calculatedType === 'tooltip') && wouldBeVisibleAfterAutoScroll(element)) {
            // the element was scrolled out of view, the guide should be invisible for now, but still "active"
            return;
        }
    
        step.hide();
    }
    
    var badgeIterator = throttleIterator(50, createStatefulIterator(function(guide) {
        return guide.id;
    }));
    
    var placeBadgesProc = function(guidesList) {
        // show/update all badges that we can within 50ms
        var badges = _.filter(guidesList, isBadge);
        badgeIterator.eachUntil(badges, function(badge) {
            badge.placeBadge();
        });
    };
    
    var launcherProc = function(guidesList) {
        // filter list down to launcher based guides
        var launcherGuides = getLauncherGuideList(guidesList);
        // add all launcher based guides
        updateLauncher(launcherGuides, true);
    };
    
    function resourceCenterProc(resourceCenter) {
        if(!resourceCenter) return;
    
        // Reset state to start each loop
        resourceCenter.skipResourceCenterHomeView = false;
        resourceCenter.hasResourceCenterContent = true;
        delete resourceCenter.moduleIdToReplaceHomeViewWith;
        var reEvaluateModuleContent = false;
    
        var isFullyCustomRC = resourceCenter.attributes &&
            resourceCenter.attributes.resourceCenter &&
            resourceCenter.attributes.resourceCenter.moduleId &&
            resourceCenter.attributes.resourceCenter.moduleId === 'FullyCustomModule';
    
        if (isFullyCustomRC) {
            resourceCenter.hasResourceCenterContent = true;
            return true;
        }
    
        // Find eligible modules
        var eligibleModules = _.filter(resourceCenter.modules, function(module) {
            if (!module) return false;
            var resourceCenterConfig = module.attributes.resourceCenter;
            var moduleId = resourceCenterConfig.moduleId;
    
            // Sandbox and integration modules can not dynamically show/hide.
            if ((moduleId === 'SandboxModule' || moduleId === 'IntegrationModule') && module.hasResourceCenterContent) return true;
    
            var eligibleGuidesInModule = _.filter(module.guidesInModule, function(guide) {
                if(!guide.shouldBeAddedToResourceCenter()) {
                    guide.ineligibleForRC = true;
                    return false;
                }
                guide.ineligibleForRC = false;
                return true;
            });
    
            var isEligible = eligibleGuidesInModule.length;
            module.hasResourceCenterContent = !!isEligible;
            // We only need to hash the active module, no other module has content rendered
            if (resourceCenter.activeModule && module.id === resourceCenter.activeModule.id) {
                var moduleContentHash = crc32(_.map(eligibleGuidesInModule, function(guide) {
                    // don't change content hash when announcements update their seen state, as that will cause
                    // the RC to re-render (and lose scroll position)
                    var isAnnouncementOrWhatsNew = guide.isAnnouncement() || guide.isWhatsNew();
                    var seenState = isAnnouncementOrWhatsNew ? null : _.pluck(guide.steps, 'seenState');
                    return {
                        'id':        guide.id,
                        'seenState': seenState
                    };
                }));
                if (module.eligibleGuidesInModuleHash && moduleContentHash !== module.eligibleGuidesInModuleHash) reEvaluateModuleContent = true;
                module.eligibleGuidesInModuleHash = moduleContentHash;
            }
            return isEligible;
        });
    
        // If we are rendering the home view and its modules change re-render it
        var reEvaluateHomeViewContent = false;
        if (!resourceCenter.activeModule) {
            var eligibleModulesHash = crc32(_.map(eligibleModules, function(module) {
                return {
                    'id': module.id
                };
            }));
            if (resourceCenter.eligibleModulesHash && resourceCenter.eligibleModulesHash !== eligibleModulesHash) {
                reEvaluateHomeViewContent = true;
                BuildingBlockResourceCenter.replaceResourceCenterContent(resourceCenter.id, undefined, true);
            }
            resourceCenter.eligibleModulesHash = eligibleModulesHash;
        }
    
        var RCBadge = pendo.badgesShown[resourceCenter.id];
    
        // If we get no modules back, hide the RC and RC Badge, clear active module
        if (!eligibleModules || !eligibleModules.length) {
            var isBadgeActivated = resourceCenter.launchMethod.indexOf('badge') !== -1;
            var isElementActivated = resourceCenter.launchMethod.indexOf('dom') !== -1;
    
            resourceCenter.hasResourceCenterContent = false;
    
            // If the RC is badge activated, hide it from the dom completely. Otherwise, leave it alone
            // This is important for element-activated RC, which should still display with an empty state
            // even if it has no content
            if (isBadgeActivated) {
                if (resourceCenter.isShown()) resourceCenter.hide();
                if (RCBadge) RCBadge.hide();
                resourceCenter.badgeHidden = true;
                delete resourceCenter.activeModule;
            } else if (isElementActivated) {
                resourceCenter.showEmptyState = true;
            }
        }
    
        // Show the badge if it was hidden but now has content
        if (resourceCenter.badgeHidden && resourceCenter.hasResourceCenterContent) {
            if (RCBadge) RCBadge.show();
            resourceCenter.badgeHidden = false;
        }
    
        // Skip directly to the one eligible module
        if(eligibleModules.length === 1) {
            resourceCenter.skipResourceCenterHomeView = true;
            resourceCenter.moduleIdToReplaceHomeViewWith = eligibleModules[0].id;
    
            var noActiveModule = !resourceCenter.activeModule && reEvaluateHomeViewContent;
            var differentActiveModule = resourceCenter.activeModule && resourceCenter.activeModule.id !== eligibleModules[0].id;
    
            // If the one module is different or content needs to be reevaluated, reload
            // or if we are on the home view and the modules on the home view have changed
            if (noActiveModule || differentActiveModule || reEvaluateModuleContent) {
                BuildingBlockResourceCenter.replaceResourceCenterContent(resourceCenter.moduleIdToReplaceHomeViewWith, undefined, true);
            }
        }
    
        // Ensure the active module is still eligible and re-evaluate its content if need be.
        // Go to Home View if active module is no longer eligible
        var activeModuleisEligible;
        if (resourceCenter.activeModule) {
            activeModuleisEligible = _.find(eligibleModules, function(module) {
                return module.id === resourceCenter.activeModule.id;
            });
            if (activeModuleisEligible && reEvaluateModuleContent) {
                BuildingBlockResourceCenter.replaceResourceCenterContent(resourceCenter.activeModule.id, undefined, true);
            }
            if (!activeModuleisEligible) {
                BuildingBlockResourceCenter.replaceResourceCenterContent(resourceCenter.id);
            }
        }
    
        // Place Element Activated Notification Badge
        if(resourceCenter.launchMethod === 'dom') {
            BuildingBlockResourceCenter.updateNotificationBubbles();
        }
    }
    
    var noGuideShowingProc = function(guidesList) {
        if (Permalink.tryDisplay(pendo)) return;
    
        // check for in-progress walkthroughs
        var walkthrough = _.find(guidesList, function(guide) {
            return guide.isContinuation(lastGuideStepSeen);
        });
    
        var shouldNotResume = walkthrough && walkthrough.attributes && walkthrough.attributes.doNotResume;
        
        if (walkthrough && !shouldNotResume) {
            walkthrough.show('continue');
            return;
        }
    
        AutoDisplay.tryDisplay(guidesList, pendo);
    };
    
    var CrossFrame = (function() {
        var frameId = pendo.randomString(32);
        var FRAME_REPLY = 'frame:reply';
        var responsePromises;
        var unsubscribeReply;
    
        return {
            'post':      post,
            'request':   request,
            'subscribe': subscribe,
            'stop':      stop
        };
    
        function replyHandler(message) {
            var deferred = responsePromises[message.responseId];
            if (deferred) {
                delete responsePromises[message.responseId];
                deferred.resolve(message);
            }
        }
    
        function listenForReplies() {
            if (!responsePromises) {
                responsePromises = {};
                unsubscribeReply = subscribe(FRAME_REPLY, replyHandler);
            }
        }
    
        function handles(messageType, fn) {
            return function(event) {
                try {
                    var message = parseMessageEvent(event);
                    if (message && message.apiKey === pendo.apiKey && message.type === messageType) {
                        fn.call(this, message);
                    }
                } catch (e) {
                    writeException(e);
                }
            };
        }
    
        /**
         * Subscribes to a type of message
         * @param  {String}   messageType
         * @param  {Function} fn          Function to execute when this message type is received
         * @return {Function}             A function that unsubscribes when executed
         */
        function subscribe(messageType, fn) {
            var messageHandler = handles(messageType, fn);
    
            if (_.isFunction(window.addEventListener)) {
                window.addEventListener('message', messageHandler, false);
            }
            return _.partial(unsubscribe, messageHandler);
        }
    
        function unsubscribe(fn) {
            if (_.isFunction(window.removeEventListener)) {
                window.removeEventListener('message', fn, false);
            }
        }
    
        function parseMessageEvent(event) {
            try {
                var message = JSON.parse(event.data);
                message.window = function() {
                    return event.source;
                };
                message.reply = function(responseMessage) {
                    post(event.source, _.extend({
                        'type':       FRAME_REPLY,
                        'responseId': message.guid
                    }, responseMessage));
                };
                return message;
            } catch (e) {
                // Ignore messages that we can't parse
            }
        }
    
        /**
         * Stops the reply message handler.
         */
        function stop() {
            if (_.isFunction(unsubscribeReply)) {
                unsubscribeReply();
            }
            responsePromises = null;
        }
    
        /**
         * Send a message to another frame/window
         * @param  {Window} destinationWindow Window that will receive the message
         * @param  {Object} message
         * @return {String} message id
         */
        function post(destinationWindow, message) {
            return tellMaster(destinationWindow, _.extend({
                'apiKey':  pendo.apiKey,
                'frameId': frameId
            }, message), '*');
        }
    
        /**
         * Wraps post with request/reply semantics.
         * @param  {Window} destinationWindow
         * @param  {Object} message
         * @param  {Number=} replyTimeout
         * @return {Promise}
         */
        function request(destinationWindow, message, replyTimeout) {
            listenForReplies(); // Start the reply listener, if needed
    
            var timer;
            var messageId = post(destinationWindow, message);
            var deferred = q.defer();
            responsePromises[messageId] = deferred;
    
            if (_.isNumber(replyTimeout)) {
                timer = setTimeout(function() {
                    if (responsePromises) {
                        delete responsePromises[messageId];
                    }
                    deferred.reject();
                }, replyTimeout);
            }
    
            deferred.promise.then(function() {
                clearTimeout(timer);
            });
    
            return deferred.promise;
        }
    })();
    
    var FrameController = (function() {
        var PAUSED_MODE = 'paused';
        var SLAVE_MODE = 'slave';
        var FRAME_LOAD = 'frame:load';
        var FRAME_UNLOAD = 'frame:unload';
        var FRAME_GUIDELIST = 'frame:guidelist';
        var FRAME_SHOWGUIDE = 'frame:showguide';
        var FRAME_GUIDESHOWN = 'frame:guideshown';
        var FRAME_GUIDEHIDDEN = 'frame:guidehidden';
        var FRAME_HIDEGUIDE = 'frame:hideguide';
        var FRAME_STARTPREVIEW = 'frame:startpreview';
        var FRAME_RESTARTPREVIEW = 'frame:restartpreview';
        var FRAME_STOPPREVIEW = 'frame:stoppreview';
        var PARENT_FRAME_LOAD = 'frame:parentloaded';
    
        var guidesInThisFrame = {};
        var guidesInFrames = {};
        var frames = {};
        var unsubscribe = {};
        var eligibleToPlaceRcBadge = false;
    
        return {
            'init':                      init,
            'stop':                      stop,
            'isInThisFrame':             isInThisFrame,
            'isInAnotherFrame':          isInAnotherFrame,
            'show':                      show,
            'showGuideById':             showGuideById,
            'shown':                     shown,
            'hide':                      hide,
            'loadingGuideList':          loadingGuideList,
            'updateGuideList':           updateGuideList,
            'getState':                  getState,
            'getFrameDepth':             getFrameDepth,
            'hasFrames':                 hasFrames,
            'updateFrameVisibility':     updateFrameVisibility,
            'isShownInAnotherFrame':     isShownInAnotherFrame,
            'isEligibleToPlaceRcBadge':  isEligibleToPlaceRcBadge,
            'hideRcBadgeFromInnerFrame': hideRcBadgeFromInnerFrame,
            'startPreview':              startPreview,
            'restartPreview':            restartPreview,
            'stopPreview':               stopPreview,
            'SLAVE_MODE':                SLAVE_MODE
        };
    
        function startPreview() {
            _.each(frames, function(frame, frameId) {
                CrossFrame.post(frame.window(), {
                    'type':          FRAME_STARTPREVIEW,
                    'pendo-preview': pendoLocalStorage.getItem(pendoPreview)
                });
            });
        }
    
        function restartPreview() {
            _.each(frames, function(frame, frameId) {
                CrossFrame.post(frame.window(), {
                    'type':          FRAME_RESTARTPREVIEW,
                    'pendo-preview': pendoLocalStorage.getItem(pendoPreview)
                });
            });
        }
    
        function stopPreview() {
            _.each(frames, function(frame, frameId) {
                CrossFrame.post(frame.window(), {
                    'type': FRAME_STOPPREVIEW
                });
            });
        }
    
        function frameStartPreview(message) {
            pendoLocalStorage.setItem(pendoPreview, message[pendoPreview]);
            forceGuideReload();
        }
    
        function frameRestartPreview(message) {
            pendoLocalStorage.setItem(pendoPreview, message[pendoPreview]);
            lastGuideStepSeen = restartPreview(pendoLocalStorage, activeGuides, lastGuideStepSeen);
        }
    
        function frameStopPreview() {
            exitPreviewMode();
        }
    
        function init() {
            CrossFrame.subscribe(PARENT_FRAME_LOAD, receiveFrameLoadedAndStop);
    
            if (detectMaster()) {
                tryConnectToTopFrame();
    
                pauseGuidesUntilConnect();
    
                attachEvent(window, 'unload', unload);
    
                unsubscribe.startPreview = CrossFrame.subscribe(FRAME_STARTPREVIEW, frameStartPreview);
                unsubscribe.restartPreview = CrossFrame.subscribe(FRAME_RESTARTPREVIEW, frameRestartPreview);
                unsubscribe.stopPreview = CrossFrame.subscribe(FRAME_STOPPREVIEW, frameStopPreview);
            } else {
                // When we drop in here - that means we're in the context of the window.top frame
                // and eligible to place RC badge
                eligibleToPlaceRcBadge = true;
    
                unsubscribe.load = CrossFrame.subscribe(FRAME_LOAD, frameLoad);
                unsubscribe.unload = CrossFrame.subscribe(FRAME_UNLOAD, frameUnload);
                unsubscribe.guideList = CrossFrame.subscribe(FRAME_GUIDELIST, frameGuideList);
                unsubscribe.guideShown = CrossFrame.subscribe(FRAME_GUIDESHOWN, frameGuideShown);
                unsubscribe.guideHidden = CrossFrame.subscribe(FRAME_GUIDEHIDDEN, frameGuideHidden);
                unsubscribe.showGuide = CrossFrame.subscribe(FRAME_SHOWGUIDE, topFrameShowGuide);
            }
        }
    
        function receiveFrameLoadedAndStop(message) {
            // Tear down inner frame RC badges and set eligibility to false
            var innerFrameRcBadge = _.first(Sizzle('[data-layout="badgeResourceCenter"]'));
            if (innerFrameRcBadge) innerFrameRcBadge.remove();
            eligibleToPlaceRcBadge = false;
        }
    
        function hideRcBadgeFromInnerFrame() {
            var iframesInContext = Sizzle('iframe, frame');
            _.each(iframesInContext, function(frame) {
                var frameWindow = frame.contentWindow;
                CrossFrame.post(frameWindow, {
                    'type': PARENT_FRAME_LOAD
                });
            });
        }
    
        function isEligibleToPlaceRcBadge() {
            return eligibleToPlaceRcBadge;
        }
    
        function isShownInAnotherFrame(step) {
            return _.any(frames, function(frame) {
                return frame.shown && frame.shown[step.id];
            });
        }
    
        // Computes how deeply nested a given frame is relative to the top window
        // In cases where pendo is not installed on the top frame, this is important to establish
        // what the "master" frame is
        function getFrameDepth() {
            var depth = 0;
            var pointer = window;
            for (depth; depth < 10; depth++) {
                if (pointer.parent === pointer) break;
    
                pointer = pointer.parent;
            }
    
            return depth;
        }
    
        /**
         * Attempts to connect with an agent running in the top frame.
         * Makes 5 attempts, starts with a 100ms timeout, and doubles
         * the timeout with each attempt, until it reaches 1000ms.
         * The guide loop will be paused until the first attempt succeeds
         * or fails, but will be re-enabled during subsequent attempts.
         */
        function tryConnectToTopFrame() {
            var connectTimeout = 100;
            var failedConnects = 0;
    
            sendFrameLoad();
    
            function sendFrameLoad() {
                CrossFrame.request(window.top, {
                    'type': FRAME_LOAD
                }, connectTimeout).then(frameConnect, frameConnectFailed);
            }
    
            function frameConnectFailed() {
                clearMode();
    
                connectTimeout = Math.min(connectTimeout + connectTimeout, 1000);
    
                if (failedConnects++ < 5) {
                    sendFrameLoad();
                } else {
                    // after timeout fails set eligibility true
                    // for inner frame to show RC badge
                    eligibleToPlaceRcBadge = true;
                }
            }
        }
    
        function hasFrames() {
            return !_.isEmpty(frames);
        }
    
        function getState(guide) {
            return _.chain(frames).filter(function(frame) {
                return frame && frame.state;
            }).filter(function(frame) {
                return frame.state[guide.id];
            }).filter(function(frame) {
                return frame.visibility !== 'hidden';
            }).map(function(frame) {
                return frame.state[guide.id];
            }).value();
        }
    
        function stop() {
            _.each(unsubscribe, function(unsub) {
                unsub();
            });
            clearMode();
    
            frames = {};
            unsubscribe = {};
            guidesInThisFrame = {};
            guidesInFrames = {};
            FrameController.isConnectedToMaster = false;
        }
    
        function isInThisFrame(guide) {
            return !!guidesInThisFrame[guide.id];
        }
    
        function isInAnotherFrame(guide) {
            return !!guidesInFrames[guide.id];
        }
    
        function unload() {
            CrossFrame.post(window.top, {
                'type': FRAME_UNLOAD
            });
        }
    
        function pauseGuidesUntilConnect() {
            registerMode(PAUSED_MODE, guidePausedRenderer);
            setMode(PAUSED_MODE);
        }
    
        /**
         * Replaces the default guide rendering loop when
         * this is not the top-most frame running an agent.
         * @param  {Array.<Guide>} guidesList The list of active guides
         */
        var lastLauncherHash;
        function guideSlaveRenderer(guidesList) {
            placeBadgesProc(guidesList);
    
            if (isGuideShown()) {
                guideShowingProc();
            }
    
            // Check for changes to what should display in the launcher
            var launchers = getLauncherGuideList(guidesList);
            var launcherHash = computeLauncherHash(launchers);
            if (pendo.doesExist(lastLauncherHash) && launcherHash !== lastLauncherHash) {
                publishGuideList(guidesList);
            }
            lastLauncherHash = launcherHash;
        }
    
        /**
         * Replaces the default guide rendering loop
         * while waiting for a connect message.
         */
        function guidePausedRenderer() {
        }
    
        /**
         * Called in the top frame when a child frame is loaded.
         * @param  {Object} message
         */
        function frameLoad(message) {
            frames[message.frameId] = frames[message.frameId] || {};
            frames[message.frameId].window = message.window;
            frames[message.frameId].depth = message.frameDepth;
            frames[message.frameId].shown = {};
            message.reply({
                'isDesignerActive': !!pendo.designer,
                'parentHostConfig': pendo.designerv2.hostConfig,
                'pendo-preview':    pendoLocalStorage.getItem(pendoPreview)
            });
        }
    
        /**
         * Called in the top frame when a child frame is destroyed.
         * @param  {Object} message
         */
        function frameUnload(message) {
            frameGuideList({
                'frameId': message.frameId,
                'guide':   []
            });
            delete frames[message.frameId];
        }
    
        /**
         * Called in a child frame when the top frame responds
         * to the child frame's load message
         * @param  {Object} message
         */
        function frameConnect(message) {
            eligibleToPlaceRcBadge = false;
            unsubscribe.showGuide = CrossFrame.subscribe(FRAME_SHOWGUIDE, frameShowGuide);
            unsubscribe.hideGuides = CrossFrame.subscribe(FRAME_HIDEGUIDE, frameHideGuide);
    
            stopGuides();
            registerMode(SLAVE_MODE, guideSlaveRenderer);
            setMode(SLAVE_MODE);
            FrameController.isConnectedToMaster = true;
    
            if(message && message.isDesignerActive) {
                var launchOptions = message.parentHostConfig;
                delete launchOptions.frameId;
                delete launchOptions.preloader;
    
                return pendo.designerv2.launchSelectionModeFromMessage({
                    'data': {
                        'destination': 'pendo-designer-agent',
                        'type':        'addSelectionCode',
                        'options':     launchOptions
                    }
                });
            }
    
            if (message && message[pendoPreview]) {
                frameStartPreview(message);
                return;
            }
    
            publishGuideList(getActiveGuides());
        }
    
        /**
         * Notifies the top frame that the child frame's guide list changed.
         * @param {Array.<Guide>} guidesList
         * @see frameGuideList
         */
        function publishGuideList(guidesList) {
            var guides = cloneGuideList(guidesList);
    
            CrossFrame.post(window.top, {
                'type':              FRAME_GUIDELIST,
                'lastGuideStepSeen': pendo.lastGuideStepSeen,
                'guides':            guides,
                'state':             _.chain(guidesList)
                    .filter(isNotLauncherGuide)
                    .map(guideState)
                    .value()
            });
        }
    
        function loadingGuideList() {
            guidesInThisFrame = {};
        }
    
        /**
         * Called in the top frame when a child (or the top) frame's
         * guide list changes.
         * @see publishGuideList
         * @param  {Object} message
         */
        function frameGuideList(message) {
            var frameId = message.frameId;
            frames[frameId] = frames[frameId] || {};
            frames[frameId].window = frames[frameId].window || message.window;
            frames[frameId].shown = frames[frameId].shown || {};
            frames[frameId].lastGuideStepSeen = message.lastGuideStepSeen;
    
            _.each(frames[frameId].guides, function(guide, guideId) {
                if (guidesInFrames[guideId] && !(--guidesInFrames[guideId])) {
                    delete guidesInFrames[guideId];
                }
            });
    
            // Clone the received list again, to ensure nothing naughty (like content related stuff)
            // ends up the guide list
            frames[frameId].guides = _.indexBy(cloneGuideList(message.guides), 'id');
            frames[frameId].state = _.indexBy(message.state, 'id');
    
            // TODO clear the shown list? "hidden" messages should have fired off, anyway
    
            _.each(frames[frameId].guides, function(guide, guideId) {
                if (!guidesInFrames[guideId]) {
                    guidesInFrames[guideId] = 0;
                }
                guidesInFrames[guideId]++;
            });
    
            updateMasterGuideList();
        }
    
        /**
         * Called by child frames to notify the top frame that a guide was displayed.
         * @see frameGuideShown
         */
        function shown(step) {
            if (step && detectMaster()) {
                CrossFrame.post(window.top, {
                    'type':    FRAME_GUIDESHOWN,
                    'guideId': step.guideId,
                    'stepId':  step.id
                });
            }
        }
    
        /**
         * Called in the top frame whenever a step is shown in a child
         * frame. In most cases, the top frame probably initiated the
         * show operation, but steps might be shown in child frames
         * without the top frame's knowledge, when:
         * - launched from badges
         * - steps in a group are auto-launched based on target element visibility
         * The other notable difference between this and the response to
         * the show message is that the show message may return true for a
         * provisional display, whereas this will only be called when the
         * guide is visible in the frame.
         * @see shown
         * @param  {Object} message
         */
        function frameGuideShown(message) {
            // Hide the step in other frames
            _.each(frames, function(frame, frameId) {
                if (frameId !== message.frameId) {
                    CrossFrame.post(frame.window(), {
                        'type':    FRAME_HIDEGUIDE,
                        'guideId': message.guideId,
                        'stepId':  message.stepId
                    });
                }
            });
    
            // Hide any other guides that don't contain this step
            _.each(getActiveGuides(), function(guide) {
                if (guide.isShown()) {
                    var step = guide.findStepById(message.stepId);
                    if (step) {
                        step.hide({
                            'onlyThisFrame': true
                        });
                    } else {
                        guide.hide();
                    }
                }
            });
    
            var frame = frames[message.frameId] = frames[message.frameId] || {};
            frame.shown = frame.shown || {};
            frame.shown[message.stepId] = true;
        }
    
        /**
         * If called in a child frame, it notifies the top frame that the step is hidden.
         * If called in the top frame, it tells all child frames to hide the step.
         * @see frameGuideHidden
         * @see frameHideGuide
         * @param {GuideStep} step
         * @param {Object} hideOptions
         */
        function hide(step, hideOptions) {
            if (detectMaster()) {
                CrossFrame.post(window.top, {
                    'type':              FRAME_GUIDEHIDDEN,
                    'guideId':           step.guideId,
                    'stepId':            step.id,
                    'lastGuideStepSeen': lastGuideStepSeen,
                    'options':           hideOptions
                });
            } else {
                _.each(frames, function(frame) {
                    CrossFrame.post(frame.window(), {
                        'type':              FRAME_HIDEGUIDE,
                        'guideId':           step.guideId,
                        'stepId':            step.id,
                        'lastGuideStepSeen': lastGuideStepSeen,
                        // Make the frame NOT publish a frame:guidehidden message
                        'options':           _.extend({ 'onlyThisFrame': true }, hideOptions)
                    });
    
                    // Update the top frame's shown cache for this step(s)
                    frame.shown = frame.shown || {};
                    frame.shown[step.id] = false;
                });
            }
        }
    
        /**
         * Called in top frame whenever a guide/step is hidden in a child frame.
         * A step may be hidden because:
         * - guides reloaded
         * - another guide launched
         * - it was advanced, dismissed, etc.
         * - the targeted element became invisible
         * This will NOT be called when the top frame initiated the hide.
         * @see hide
         * @param  {Object} message
         */
        function frameGuideHidden(message) {
            // It should already be hidden (or not here at all), but we need to sync
            // the hide options for the stayHidden option
            var guide = pendo.findGuideById(message.guideId);
            var step = guide && guide.findStepById(message.stepId);
            if (step) {
                step.hide(_.extend({}, {
                    'onlyThisFrame': true
                }, message.options));
            }
    
            updateLastGuideStepSeen(message.lastGuideStepSeen);
    
            var frame = frames[message.frameId];
            if (frame) {
                frame.shown = frame.shown || {};
                frame.shown[message.stepId] = false;
            }
    
            startGuides();
        }
    
        /**
         * Called in a child frame when a step is hidden.
         * @see hide
         * @param  {Object} message
         */
        function frameHideGuide(message) {
            updateLastGuideStepSeen(message.lastGuideStepSeen);
    
            if (message.guideId && message.stepId) {
                var guide = pendo.findGuideById(message.guideId);
                var step = guide && guide.findStepById(message.stepId);
                if (step) {
                    step.hide(message.options);
                }
            } else {
                hideGuides(message.options);
            }
        }
    
        // TODO - move elsewhere
        function updateLastGuideStepSeen(updatedLastSeen) {
            // If we advanced/dismissed in a different frame, update state in this frame.
            // The cookie might already be set, unless the domains of the frames do not match.
            // Setting it again will just slightly extend the cookie's lifetime.
            if (!updatedLastSeen) return;
            if (updatedLastSeen.time <= lastGuideStepSeen.time) return;
            if (!updatedLastSeen.state) return;
            if (updatedLastSeen.visitorId !== pendo.get_visitor_id()) return;
            if (!lastGuideStepSeen) {
                lastGuideStepSeen = {};
            }
    
            _.extend(lastGuideStepSeen, updatedLastSeen);
            _updateGuideStepStatus(lastGuideStepSeen.guideId, lastGuideStepSeen.guideStepId, lastGuideStepSeen.state);
            writeLastStepSeenCache(lastGuideStepSeen);
        }
    
        function showGuideById(id, reason) {
            if (!FrameController.isConnectedToMaster) return false;
    
            CrossFrame.post(window.top, {
                'type':    FRAME_SHOWGUIDE,
                'guideId': id,
                'reason':  reason
            });
    
            return true;
        }
    
        function topFrameShowGuide(message) {
            pendo.showGuideById(message.guideId);
        }
    
        /**
         * Shows a step in a remote frame
         * @param  {GuideStep} step
         * @param  {String} reason
         * @return {Promise} Resolved when the guide is shown (or not)
         */
        function show(step, reason) {
            var frameList = _.chain(frames)
                .filter(function(frame) {
                    return frame.guides && frame.guides[step.guideId];
                })
                .filter(function(frame) {
                    return frame.visibility !== 'hidden';
                })
            .value();
    
            function tryShowInNextFrame() {
                var frame = frameList.shift();
                if (frame) {
                    return CrossFrame.request(frame.window(), {
                        'type':    FRAME_SHOWGUIDE,
                        'stepId':  step.id,
                        'guideId': step.guideId,
                        'reason':  reason
                    }).then(function(response) {
                        if (response.error) {
                            return q.reject(response.error);
                        }
                        if (!response.isShown) {
                            return tryShowInNextFrame();
                        }
                        return response;
                    });
                }
                return q.resolve({ 'isShown': false });
            }
    
            return tryShowInNextFrame().then(function(response) {
                var frame = frames[response.frameId];
                if (response.isShown && frame) {
                    frame.shown[step.id] = true;
                }
                return response;
            });
        }
    
        /**
         * Called in a child frame when the top frame wants to display a guide
         * in the child frame.
         * @see show
         * @param  {Object} message
         */
        function frameShowGuide(message) {
            var guide = findGuideById(message.guideId);
            var step = guide && guide.findStepById(message.stepId);
            if (step) {
                step.show(message.reason);
                /*
                If the step hasn't been shown before, this might lock this step
                (b/c the content needs to be fetched/validated/both), so isShown
                will be true. If after the async operation the guide is not
                shown, the lock should be released, the guide "hidden" by guideShowingProc,
                which will sync back to the top frame.
                */
                message.reply({
                    'isShown': step.isShown()
                });
            } else {
                message.reply({
                    'isShown': false
                });
            }
        }
    
        function cloneGuide(guide) {
            var clonedGuide = _.pick(guide, 'id', 'name', 'launchMethod', 'isMultiStep', 'steps', 'attributes');
            clonedGuide.eligibleInFrame = guide.shouldBeAddedToResourceCenter;
    
            clonedGuide.steps = _.map(guide.steps, function(step) {
                return _.pick(step, 'attributes', 'advanceMethod', 'id', 'guideId', 'elementPathRule', 'regexUrlRule', 'type', 'seenReason', 'seenState');
            });
            return clonedGuide;
        }
    
        function isNotLauncherGuide(guide) {
            return guide.steps && guide.steps.length && guide.steps[0].type !== 'launcher';
        }
    
        function cloneGuideList(guides) {
            return _.chain(guides).filter(isNotLauncherGuide).map(cloneGuide).value();
        }
    
        function guideState(guide) {
            return {
                'id':                            guide.id,
                'shouldBeAddedToLauncher':       guide.shouldBeAddedToLauncher(),
                'shouldBeAddedToResourceCenter': guide.shouldBeAddedToResourceCenter()
            };
        }
    
        function updateMasterGuideList() {
            var activeGuides = getActiveGuides();
    
            // Remove guides that shouldn't be there anymore
            for (var i = 0; i < activeGuides.length; ++i) {
                var id = activeGuides[i].id;
                if (!guidesInFrames[id] && !guidesInThisFrame[id]) {
                    activeGuides.splice(i--, 1);
                }
            }
    
            updateMasterLastGuideStepSeen(frames);
    
            // Re-make the master list of guides from all frames
            var updatedGuides = _.chain(frames)
                .map(function(frame) {
                    return _.toArray(frame.guides);
                })
                .flatten(true)
                .unique('id')
                .map(GuideFactory)
            .value();
    
            // Ensure that the master guide list is up to date with seenReason/seenState from all child frames
            _.each(updatedGuides, function(guide) {
                var activeGuide = _.find(activeGuides, function(singleGuide) {
                    return singleGuide.id === guide.id;
                });
    
                if(!activeGuide) {
                    activeGuides.push(guide);
                    return;
                }
            });
    
            sortGuidesByPriority(activeGuides);
            initializeResourceCenter(activeGuides);
    
            if (guidesInThisFrame.length === 0) {
                // the loop wasn't running
                startGuides();
            }
        }
    
        function updateGuideList(guidesList) {
            guidesInThisFrame = _.chain(guidesList).pluck('id').indexBy().value();
            guidesInThisFrame.length = guidesList.length;
            if (detectMaster()) {
                publishGuideList(guidesList);
            } else {
                updateMasterGuideList();
            }
        }
    
        // Coordinates the "last seen guide" between iframes.
        // In the case where an inner frame fetches a different set of guides, the
        // lastGuideStepSeen can differ between frames. This ensures that the true
        // master frame has all the information it needs to resume an inner frame
        // guide, if that guide is most recently seen but not present in the
        // payload of the time frame
        function updateMasterLastGuideStepSeen(frames) {
            var masterLastSeenGuideStep = _.reduce(frames, function(acc, frame) {
                var currentTime = get(acc, 'time', 0);
                var frameTime = get(frame, 'lastGuideStepSeen.time', 0);
                var frameVisitorId = get(frame, 'lastGuideStepSeen.visitorId');
    
                if (frameVisitorId !== pendo.get_visitor_id()) return acc;
                if (!get(frame, 'lastGuideStepSeen.state')) return acc;
    
                if(frameTime > currentTime) {
                    return frame.lastGuideStepSeen;
                }
    
                return acc;
            }, null);
    
            var existingTime = get(lastGuideStepSeen, 'time', 0);
            var latestFrameTime = get(masterLastSeenGuideStep, 'time', 0);
    
            if(latestFrameTime > existingTime) {
                lastGuideStepSeen = masterLastSeenGuideStep;
            }
        }
    
        /**
         * Called by the top frame periodically to check that
         * the iframes it knows about are still visible. It can
         * only check frames embedded in the top frame,
         * multi-level frame hierarchies not supported yet.
         */
        function updateFrameVisibility() {
            // O(N^2)... but there can't be *that* many frames, right? RIGHT?!?
            var iframes = Sizzle('iframe');
    
            _.each(frames, function(frame) {
                var iframe = _.find(iframes, function(f) {
                    return f.contentWindow == frame.window();
                });
    
                var visibility = isElementVisible(iframe) ? 'visible' : iframe ? 'hidden' : 'unknown';
    
                if (frame.visibility === 'visible' && visibility === 'hidden') {
                    // Hide everything in the frame
                    CrossFrame.post(frame.window(), {
                        'type': FRAME_HIDEGUIDE
                    });
                }
    
                frame.visibility = visibility;
            });
        }
    })();
    
    /*
    * Onboarding
    *
    * Handles the new mode for the agent of Onboarding.  This will be
    * responsible for determining if / when the agent should go into
    * onboarding mode or make it available.  Also, handle monitoring the
    * environment for changes relevant to OB experience.
    */
    
    // OBM = Onboarding Mode
    var OBM = 'onboarding';
    var all_ob_guides = [];
    
    var completedGuidesSet = [];
    var addCompletedGuides = function(guides) {
        guides = [].concat(guides);
        completedGuidesSet = _.union(completedGuidesSet, guides);
    };
    var wasGuideAlreadyCompleted = function(guide) {
        return _.contains(completedGuidesSet, guide);
    };
    
    // should be called post loadGuides
    var shouldSwitchToOBM = function(guides) {
        return false;
    };
    
    var startOBM = function() {
    
        resetPendoUI();
        removeLauncher();
    
        var widget = pendo.guideWidget;
        if (widget) {
            widget.hidePoweredBy = true;
            if (widget.data) {
                widget.data.enableSearch = false;
            }
        }
    
        var config = _.extend({
            'addHeight':    70,
            'addWidth':     -10,
            'addUISection': buildOBProgressUI
        }, pendo.guideWidget.data);
        createLauncher(config, false);
    
        dom(launcherBadge.element).addClass('onboarding');
        dom(launcherTooltipDiv).addClass('onboarding setup');
    
        autoShowLauncherList(getGuideStats());
    
        setMode(OBM);
    };
    
    var autoShowLauncherList = function(stats) {
        if (stats.percentComplete > 0) return;
    
        if (agentStorage.read('launcher-closed') == 'yes') return;
    };
    
    var buildOBProgressUI = function(div) {
        var html = [
            '<div class=\'_pendo-launcher-onboarding-progress_\'>',
            '<div class=\'_pendo-progress-area-inner_\'>',
            '<label class=\'percentComplete\'></label><label>% Complete</label>',
            '<div class=\'_pendo-progress-bar-outer_\'>',
            '<div class=\'_pendo-progress-bar-inner_\'></div>',
            '</div>',
            '</div>',
            '</div>'
        ].join('');
    
        dom('._pendo-launcher-footer_', div).append(dom(html));
    };
    
    var updateProgressUI = function(stats) {
        dom('._pendo-progress-area-inner_ label.percentComplete').html(stats.percentComplete);
        dom('._pendo-progress-bar-inner_').css('width: ' + stats.percentComplete + '%');
    };
    
    // this is for all ob guides regardless of current can be shown status
    var isOB = function(guide) {
        return guide && guide.attributes && !!guide.attributes.isOnboarding;
    };
    
    // this is ob guides that should be included in the launcher b/c
    // they can be shown now
    var isOBAndCanShow = function(guide) {
        return isOB(guide) && isLauncher(guide);
    };
    
    var isComplete   = function(guide) {
        if (wasGuideAlreadyCompleted(guide)) return true;
    
        var lastStep = _.last(guide.steps);
    
        // is the last step a lightbox?  if so, this is the
        // congratulations step and we should instead check the 2nd to
        // last step
    
        if (guide.steps.length > 1 && lastStep.type == 'lightbox')
            {lastStep = _.last(guide.steps, 2)[0];}
    
        return lastStep.seenState == 'advanced' || lastStep.seenState == 'dismissed';
    };
    var isSkipped    = function(guide) {
        return false;
    };
    var isInProgress = function(guide) {
        var seenStates = _.pluck(guide.steps, 'seenState');
        var isActive = _.any(seenStates, function(s) { return s == 'active'; });
        if (isActive) return true;
    
        // steps can be advanced and then followed by undefined(s)
        return _.size(_.uniq(seenStates)) == 2;
    };
    var isNotStarted = function(guide) {
        if (_.any(_.initial(_.pluck(guide.steps, 'seenState')), function(s) { return s == 'dismissed'; }))
            {return true;}
    
        return _.all(_.pluck(guide.steps, 'seenState'), function(s) {
            return typeof s === 'undefined';
        });
    };
    
    var getGuideStats = function(guides) {
        guides = guides || all_ob_guides;
    
        var completed  =  _.filter(guides, isComplete);
        var skipped    = _.filter(_.without.apply(_, [guides].concat(completed)), isSkipped);
        var inProgress = _.filter(_.without.apply(_, [guides].concat(completed, skipped)), isInProgress);
        var notStarted = _.filter(_.without.apply(_, [guides].concat(completed, skipped, inProgress)), isNotStarted);
    
        var stats = {
            'total':           guides.length,
            'isCompleted':     guides.length == (completed.length + skipped.length),
            'percentComplete': Math.round((completed.length + skipped.length) / guides.length * 100),
            'completed':       completed,
            'skipped':         skipped,
            'inProgress':      inProgress,
            'notStarted':      notStarted
        };
    
        return stats;
    };
    
    
    // THESE need to handle skipped + complete for overall OB Complete tracking
    
    var updateOnboardingState = function() {
        var stats = getGuideStats();
        var div = dom(launcherTooltipDiv);
        div.removeClass('setup');
    
        if (stats.isCompleted)
            {div.addClass('complete');}
        else
            {div.removeClass('complete');}
    };
    
    var isOnboardingCompleted = function() {
        var div = dom(launcherTooltipDiv);
        return div.hasClass('complete');
    };
    
    
    
    /*
     * Onboarding Loop processor
     *
     * This handles detecting progress and drawing Onboarding specific
     * rows into the Launcher.  Also behavior of the launcher to auto show
     * upon guides stop showing and show messages upon transitions from
     * in-progress to complete of guide experiences
     */
    var ob_proc = function(guides) {
    
        // ob guides that can be shown
        var obGuides = _.filter(guides, isOBAndCanShow);
    
        // guide stats
        var stats = getGuideStats();
        addCompletedGuides(stats.completed);
    
        updateProgressUI(stats);
        updateLauncherOnboardingContent(obGuides);
        updateLauncher = function() {return true;};
    
        defaultLoopProc(guides);
    
        if (!dom(launcherTooltipDiv).hasClass('setup') && !isOnboardingCompleted() && stats.isCompleted) {
            updateOnboardingState();
            //eslint-disable-next-line no-undef
            onboardingHasCompleted();
        }
    };
    
    // Add this as a alternative loop path
    registerMode(OBM, ob_proc);
    
    var updateLauncherOnboardingContent = function(guides) {
        // do these guides always get added?  do we monitor DOM like for
        // normal guides?
    
        var guideListDiv = Sizzle('._pendo-launcher_ ._pendo-launcher-guide-listing_');
        if (!guideListDiv.length) {
            log('missing luancher body', 'launcher', 'guides');
            return false;
        }
        guideListDiv = guideListDiv[0];
    
        _.map(guides, function(g) {
            addLauncherItem(guideListDiv, g);
        });
    
        return guides.length;
    };
    
    // won't be able to maintain early completed status across page loads
    var pickStatusToUse = function(currState, newState) {
        if (currState == 'complete') return 'complete';
        return newState;
    };
    
    var handleGuideStatusChanges = function(guide, currState, newState) {
        // did this guide just complete?
        if (newState != currState && newState == 'complete') {
            guideHasCompleted(guide);
        }
    
        if (newState != currState && newState == 'skipped') {
            guideWasSkipped(guide);
        }
    };
    
    var guideWasSkipped = function(guide) {
        guideDone(guide);
    };
    
    var guideHasCompleted = function(guide) {
        guideDone(guide);
    };
    
    var guideDone = function(guide) {
        expandLauncherList();
    };
    
    var addLauncherItem = function(targetDiv, guide) {
        var state = getOnboardingState(guide);
        var item;
    
        var check = Sizzle('#launcher-' + guide.id);
        if (check.length) {
            // check its status to see if that's changed
            item = check[0];
            var currState = getOnboardingClass(item);
    
            var pickedState = pickStatusToUse(currState, state);
    
            if (currState != pickedState) {
                var tmp = dom(item);
                tmp.removeClass(makeOBClass('bad')); // just incase, this should never happen
                tmp.removeClass(makeOBClass(currState));
                tmp.addClass(makeOBClass(pickedState));
            }
    
            handleGuideStatusChanges(guide, currState, state);
        } else {
            item = buildLauncherItem(guide);
    
            dom(item).addClass(makeOBClass(state));
            targetDiv.appendChild(item);
        }
    
        addItemState(guide, state, item);
        return item;
    };
    
    var addItemState = function(guide, state, parentEl) {
        var check = Sizzle('._pendo-launcher-item-status_', parentEl);
        var status;
        if (check.length) {
            status = check[0];
        } else {
            status = dom('<div class=\'_pendo-launcher-item-status_\'></div>')[0];
            parentEl.appendChild(status);
        }
    
        var msg;
        if (state == 'skipped') msg = 'Task Skipped';
        else if (state == 'in-progress') {
            msg = 'Task in Progress (' + renderStepPosition(null, guide) + ')';
        } else {
            msg = '';
        }
    
        dom(status).html(msg);
    };
    
    var makeOBClass = function(state) { return '_pendo-onboarding-status-' + state + '_'; };
    
    var getOnboardingState = function(guide) {
        if (isComplete(guide)) return 'complete';
        if (isSkipped(guide)) return 'skipped';
        if (isInProgress(guide)) return 'in-progress';
        if (isNotStarted(guide)) return 'not-started';
        return 'bad';
    };
    
    var getOnboardingClass = function(elm) {
        var states = ['complete', 'skipped', 'in-progress', 'not-started'];
        if (!elm) return null;
    
        return _.find(states, function(s) {
            return dom(elm).hasClass(makeOBClass(s));
        });
    };
    
    // CANDIDATES for behaviors to add to guides
    
    
    // Starting to expose some useful utilities from service experiences
    
    
    // TODO: this needs to be updated to support an array of steps
    var getActiveGuide = function() {
        var currentStep, currentSteps, stepIndex;
        var currentGuide = _.find(getActiveGuides(), function(guide) { return guide.isShown(); });
    
        if (!currentGuide) return null;
    
        currentStep = _.find(currentGuide.steps, function(step, idx) {
            stepIndex = idx;
            return step.isShown();
        });
    
        currentSteps = _.filter(currentGuide.steps, function(step, idx) {
            return step.isShown();
        });
    
        return {
            'guide':     currentGuide,
            'steps':     currentSteps,
            'step':      currentStep,
            'stepIndex': stepIndex
        };
    };
    
    var smartNextStep = function(delay) {
        // Test next step's element to see if it is present
        // if it's not, skip that step.
    
        // need to know:
        // -- this steps' index
        var activeObj = getActiveGuide();
        if (!activeObj) return;
    
        // var stepIndex = _.last(_.map(activeObj.steps, function(s){ return _.indexOf(activeObj.guide.steps, s); }));
        // var nextStep = activeObj.guide.steps[stepIndex + 1];
        var nextStep = activeObj.guide.steps[activeObj.stepIndex + 1];
    
        var checkNext = function() {
            var results = Sizzle(nextStep.elementPathRule);
            if (results.length === 0 || !pendo._.some(results, isElementVisible)) {
                pendo.onGuideAdvanced(nextStep);
            } else {
                pendo.onGuideAdvanced(activeObj.step);
            }
        };
    
        delay = delay || 0;
        setTimeout(checkNext, delay);
    };
    
    var advanceOn = function(eventType, elementPath) {
        var obj = getActiveGuide();
        elementPath = elementPath || obj.step.elementPathRule;
        var btn = Sizzle(elementPath)[0];
    
        var onEvent = function() {
            pendo.onGuideAdvanced();
            detachEvent(btn, eventType, onEvent, true);
        };
        attachEvent(btn, eventType, onEvent, true);
    };
    
    var smartFirstStep = function() {
        dom('._pendo-guide_').css('display:none;');
        // look through steps to see which are applicable for the current url.
    
        var url = pendo.getCurrentUrl();
        var activeObj = getActiveGuide();
    
        var steps = activeObj.guide.steps;
        var testSteps = _.filter(_.rest(steps), function(step) {
            return !!step.pageId;
        });
    
        var startingPoint = _.indexOf(steps, _.find(testSteps, function(step) {
            return pendo.testUrlForStep(step.regexUrlRule, url);
        }));
    
        log('startingPoint is ' + startingPoint);
    
        if (startingPoint == -1) {
            dom('._pendo-guide_').css('display:block;');
            return;
        }
    
        var prevStep = steps[Math.max(0, startingPoint - 1)];
    
        pendo.log('found starting step to be ' + prevStep.id);
    
        pendo.onGuideAdvanced(prevStep);
    };
    
    var renderStepPosition = function(template, guide, step) {
        if (!guide) {
            var currentGuide = getActiveGuide();
            if (!currentGuide) return;
            guide = currentGuide.guide;
            step  = currentGuide.step;
        } else if (!step) {
            var revArr = [].concat(guide.steps).reverse();
            step = _.findWhere(revArr, {'seenState': 'active'});
        }
    
        template = template || 'Step <%= currPos %> of <%= total %>';
        template = _.template(template);
    
        // NOTE: these functions on the GuideModel exist to help handle "Helper"
        // steps
        var posObj = {
            'currPos': guide.getPositionOfStep(step),
            'total':   guide.getTotalSteps()
        };
    
        return template(posObj);
    };
    
    pendo.guideDev = {
        'getActiveGuide': getActiveGuide,
        'smartNextStep':  smartNextStep, // junxure test next step
        'smartFirstStep': smartFirstStep, // junxure router
        'advanceOn':      advanceOn,
    
        'renderStepPosition': renderStepPosition
    };
    
    pendo.badgesShown = {};
    
    var BADGE_CSS_NAME = '_pendo-badge_';
    
    var getElementForBadge = getElementForTargeting;
    
    function Badge(guide, step) {
        var target = getElementForBadge(step);
        var element;
        if (guide.attributes.type === 'building-block') {
            var badgeElem = pendo.buildNodeFromJSON(this.domJson)[0];
            element = badgeElem.parentNode.removeChild(badgeElem);
            element.className.indexOf('_pendo-badge_') === -1 && (element.className += ' _pendo-badge_');
            this.isP2Badge = true;
        } else { // Legacy guides
            element = document.createElement('img');
            element.src = replaceWithContentHost(this.imageUrl);
            element.className = '_pendo-badge ' + BADGE_CSS_NAME;
    
            var width = this.width || 13;
            var height = this.height || 13;
    
            var BADGE_BASE_STYLE = 'width:' + width + 'px;height:' + height + 'px;';
    
            setStyle(element, BADGE_BASE_STYLE);
        }
    
        element.id = '_pendo-badge_' + step.id;
    
        this.activate = function() {
            var guide = _.isFunction(step.getGuide) && step.getGuide();
            var isResourceCenter = guide && guide.attributes && guide.attributes.resourceCenter;
    
            if (!guide.isShown()) {
                showGuide(step, 'badge');
            } else if(isResourceCenter) {
                step.eventRouter.eventable.trigger('pendoEvent', { 'step': step, 'action': 'dismissGuide' });
            } else {
                var displayedStep = _.find(guide.steps, function(step) {
                    return step.isShown();
                });
                pendo.onGuideDismissed(displayedStep);
            }
        };
    
        this.show = function() {
        };
    
        this.hide = function() {
            if (element && element.parentNode) {
                element.parentNode.removeChild(element);
            }
        };
    
        this.step = _.constant(step);
        this.target = _.constant(target);
        this.element = _.constant(element);
    
        return this;
    }
    
    Badge.create = function(guide) {
        var step = Badge.findStep(guide);
    
        if (step) {
            return _.reduce(Badge.behaviors, function(badge, behavior) {
                return behavior.call(badge, guide, step);
            }, guide.attributes.badge);
        }
    };
    
    Badge.findStep = function(guide) {
        var step = _.find(guide.steps, function(step) {
            return !!step.elementPathRule;
        });
    
        if (step && guide.attributes && guide.attributes.badge) {
            return step;
        }
    };
    
    Badge.behaviors = [
        Wrappable,
        Badge,
        InlinePosition,
        AbsolutePosition,
        ClickActivation,
        HoverActivation,
        ShowOnHover
    ];
    
    function InlinePosition() {
        if (this.position === 'inline') {
            this.before('show', function() {
                var targetElem = this.target();
                var badgeElem = this.element();
                if(this.isP2Badge) {
                    setStyle(badgeElem, 'display:inline-block;vertical-align:text-bottom;');
                }
    
                if (this.css) {
                    setStyle(badgeElem, this.css);
                }
    
                if (targetElem && targetElem.tagName) {
                    var tagName = targetElem.tagName.toLowerCase();
                    if (/br|input|img|select|textarea/.test(tagName)) {
                        if (badgeElem.parentNode === targetElem.parentNode) return;
                        // Insert after if targetElem cannot have children
                        targetElem.parentNode.insertBefore(badgeElem, targetElem.nextSibling);
                    } else if (badgeElem.parentNode !== targetElem) {
                        targetElem.appendChild(badgeElem);
                    }
                }
            });
        }
    
        return this;
    }
    
    function AbsolutePosition() {
        if (!this.position || this.position === 'top-right' || this.position === 'top-left') {
            this.before('show', function() {
                var badgeElem = this.element();
                var elemPos = getOffsetPosition(this.target());
                var topIdx = 0, right = 0, left = 0;
                if (this.offsets) {
                    topIdx = this.offsets.top || 0;
                    right = this.offsets.right || 0;
                    left = this.offsets.left || 0;
                }
    
                var badgePosition = 'position:' + (elemPos.fixed ? 'fixed' : 'absolute') + ';top:' + (elemPos.top + topIdx) + 'px;';
                //eslint-disable-next-line default-case
                switch(this.position) {
                case 'top-right':
                    badgePosition += 'left:' + (elemPos.left + elemPos.width - right) + 'px';
                    break;
                case 'top-left':
                    badgePosition += 'left:' + (elemPos.left + left) + 'px';
                    break;
                }
    
                setStyle(badgeElem, badgePosition);
                if (!badgeElem.parentNode) { getGuideAttachPoint().appendChild(badgeElem); }
            });
        }
    
        return this;
    }
    
    function ClickActivation() {
        var badge = this;
        var badgeElem = badge.element();
        var attached = false;
    
        var click = function(evt) {
            badge.activate();
            stopEvent(evt);
        };
    
        badge.after('show', function() {
            if (!attached) {
                attachEvent(badgeElem, 'click', click);
                attached = true;
            }
        });
    
        badge.after('hide', function() {
            detachEvent(badgeElem, 'click', click);
            attached = false;
        });
    
        return badge;
    }
    
    // Used to determine if a badge can be hovered to display its guide
    function HoverActivation() {
        var badge = this;
        var badgeElem = badge.element();
        var step = badge.step();
        var attached = false;
    
        if (badge.useHover === 'yes' || badge.showGuideOnBadgeHover) {
            var isInGuideElement = function(element) {
                while (element) {
                    if (/_pendo-guide_|_pendo-guide-tt_|_pendo-backdrop_|_pendo-badge_/.test(element.className)) {
                        return true;
                    }
                    if (/pendo-guide-container/.test(element.id)) {
                        return true;
                    }
                    element = element.parentNode;
                }
                return false;
            };
    
            var mousemove = _.throttle(function(e) {
                if (getTarget(e) !== badgeElem && !isInGuideElement(getTarget(e))) {
                    mouseout();
                }
            }, 50, {'trailing': false});
    
            var mouseover = function(evt) {
                if (!step.isShown()) {
                    showGuide(step, 'badge');
                }
                attachEvent(document, 'mousemove', mousemove);
                stopEvent(evt);
            };
    
            var mouseout = function(evt) {
                detachEvent(document, 'mousemove', mousemove);
                if (!isPreviewing()) {
                    pendo.onGuideDismissed(step);
                }
            };
    
            badge.after('show', function() {
                if (!attached) {
                    attachEvent(badgeElem, 'mouseover', mouseover);
                    attached = true;
                }
            });
    
            badge.after('hide', function() {
                detachEvent(badgeElem, 'mouseover', mouseover);
                detachEvent(document, 'mousemove', mousemove);
                attached = false;
            });
        }
    
        return badge;
    }
    
    // Determines if the badge should appear when hovering on its target element
    function ShowOnHover() {
        var badge = this;
        var badgeElem = badge.element();
        var target = badge.target();
        var attached = false;
    
        var shouldShowOnHover = badge.showBadgeOnlyOnElementHover || /hover/.test(badge.showOnEvent);
        if (shouldShowOnHover && !isPreviewing()) {
            var showStyle = badge.position === 'inline' ? 'visibility:visible;' : 'display:inline;';
            var hideStyle = badge.position === 'inline' ? 'visibility:hidden;' : 'display:none;';
    
            var containsPoint = function(x, y) {
                var rect1 = getClientRect(target),
                    rect2 = getClientRect(badgeElem),
                    boundingRect = {
                        'left':   Math.min(rect1.left, rect2.left),
                        'top':    Math.min(rect1.top, rect2.top),
                        'right':  Math.max(rect1.right, rect2.right),
                        'bottom': Math.max(rect1.bottom, rect2.bottom)
                    };
    
                var yAdjustedForScroll = y + document.documentElement.scrollTop;
    
                return x >= boundingRect.left &&
                    x <= boundingRect.right &&
                    yAdjustedForScroll >= boundingRect.top &&
                    yAdjustedForScroll <= boundingRect.bottom;
            };
    
            var mousemove = _.throttle(function(e) {
                if (getTarget(e) !== target &&
                    getTarget(e) !== badgeElem &&
                    !_hasClass(badgeElem, 'triggered') &&
                    !containsPoint(e.clientX, e.clientY)) {
                    mouseout();
                }
            }, 50, {'trailing': false});
    
            var mouseover = function() {
                setStyle(badgeElem, showStyle);
                attachEvent(document, 'mousemove', mousemove);
            };
    
            var mouseout = function() {
                detachEvent(document, 'mousemove', mousemove);
                setStyle(badgeElem, hideStyle);
            };
    
            badge.after('show', function() {
                if (!attached) {
                    attachEvent(target, 'mouseover', mouseover);
                    attached = true;
                    mouseout();
                }
            });
    
            badge.after('hide', function() {
                if (attached) {
                    detachEvent(target, 'mouseover', mouseover);
                    attached = false;
                }
                mouseout();
            });
        }
    
        return badge;
    }
    
    /*
     * Maintains the DOM presence of the badge for the specified guide
     * where in the badge is either added or removed depending on if
     * the appropiate DOM element is found.
     *
     * For this reason, when Badges are in the play the setTimeout to
     * keep showing the startGuides needs to also continue running.
     *
     * input: guide obj, and Map of ids to badges being shown currently
     */
    var placeBadge = function(guide, badgesShown) {
        badgesShown = badgesShown || pendo.badgesShown;
        var badge = badgesShown[guide.id];
        var step = badge ? badge.step() : Badge.findStep(guide);
        if (!step) return;
        var target = badge ? badge.target() : getElementForBadge(step);
        var isRcBadge = get(guide, 'attributes.resourceCenter');
    
        if(isRcBadge && !FrameController.isEligibleToPlaceRcBadge()) return;
    
        // Don't render the resource center badge if the resource center itself has nothing to show
        if(isRcBadge && !guide.hasResourceCenterContent) return;
        BuildingBlockResourceCenter.updateNotificationBubbles();
    
        if (step.elementPathRule && // Somehow this gets deleted or set to a non-string in some customer sites
            pendo.isElementVisible(target) &&
            pendo.Sizzle.matchesSelector(target, step.elementPathRule)) {
            if (!badge) {
                badge = Badge.create(guide);
            }
    
            if (!detectMaster() && isRcBadge && badgesShown[guide.id]) {
                // If top frame comes in late and RC badge showing in inner frame bc of delay
                // Post message down to child frames to remove their RC badge
                // Otherwise there will be duplicate badges in inner frame & top frame
                FrameController.hideRcBadgeFromInnerFrame();
            } 
            badge.show();
            badgesShown[guide.id] = badge;
        } else if (badge) {
            // if the step is being show for this badge then
            // don't remove it.
    
            if (!step.isShown()) {
                // 3. If the element is not found, remove it if it's currently shown.
                step.overrideElement = undefined;
                badgesShown[guide.id] = undefined;
                badge.hide();
            }
        }
    };
    
    var removeAllBadges = function() {
        _.map(pendo.badgesShown, removeBadge);
        pendo.badgesShown = {};
    };
    
    var removeBadge = function(badge) {
        if (badge && _.isFunction(badge.hide)) {
            badge.hide();
        }
    };
    
    var removeBadgeForGuide = function(guideGroup) {
        var badge = pendo.badgesShown[guideGroup.id];
        if (badge)
            {removeBadge(badge);}
    };
    
    var adjustBadgesForResize = function(badges) {
        debug('adjustBadgesForResize firing');
    
        _.map(pendo.badgesShown, function(badge) {
            if (badge) {
                badge.show();
            }
        });
    };
    
    attachEvent(window, 'resize', _.debounce(adjustBadgesForResize, 50));
    
    pendo.TOOLTIP_DEFAULT_WIDTH = 430;
    pendo.TOOLTIP_DEFAULT_HEIGHT = 200;
    pendo.TOOLTIP_ARROW_SIZE = 15;
    var TOOLTIP_CSS_NAME = '_pendo-guide-tt_';
    var MOBILE_TOOLTIP_CSS_NAME = '_pendo-guide-mobile-tt_';
    var lastElementPos = null;
    
    var buildTooltipCSSName = function() {
        return isMobileUserAgent() ? MOBILE_TOOLTIP_CSS_NAME : TOOLTIP_CSS_NAME;
    };
    var buildTooltipCSSSelector = function(step) {
        return '#_pendo_g_' + step.id;
    };
    
    /**
     * _createTooltip -- creates a tooltip div and returns it.
     *
     * @param element -- the element to position it near
     * @param config -- height, width, content
     */
    var createTooltipGuide = function(element, step) {
        lastElementPos = null;
        var elementPos = getOffsetPosition(element);
    
        // RETURN IF THE FOUND ELEMENT IS NOT VISIBLE ON THE SCREEN.
        if(elementPos.height === 0 && elementPos.width === 0) {
            return null;
        }
    
        var tooltipDiv = step.guideElement,
            height = step.attributes.height,
            width = step.attributes.width,
            layoutDir = step.attributes.layoutDir;
    
        tooltipDiv.addClass(buildTooltipCSSName());
    
        var dim = getTooltipDimensions(elementPos, height, width, layoutDir);
        if (step) {
            step.dim = dim;
        }
    
        //
        // styles for OUTER Guide
        //
        tooltipDiv.css({
            'width':  dim.width,
            'height': dim.height,
            'left':   dim.left,
            'top':    dim.top
        });
    
        if (elementPos.fixed) {
            // If the target is fixed, fix the tooltip as well
            tooltipDiv.css({ 'position': 'fixed' });
        }
    
        //
        // styles for container
        //
        dom('._pendo-guide-container_', tooltipDiv)
            .addClass(dim.arrowPosition)
            .css({
                'top':    dim.content.top,
                'left':   dim.content.left,
                'width':  dim.content.width,
                'height': dim.content.height
            });
    
        buildAndAppendArrow(tooltipDiv[0], dim);
    
        return tooltipDiv[0];
    };
    
    var buildAndAppendArrow = function(tooltipDiv, dim) {
        var directions = ['top', 'right', 'bottom', 'left'],
            arrowPrefix = '_pendo-guide-arrow-',
            borderPrefix = arrowPrefix + 'border-',
            newPosition = dim.arrowPosition;
    
        var ARROW_BASE_STYLE = _.chain(directions)
            .filter(function(direction) {
                return direction !== newPosition;
            }).map(function(direction) {
                return 'border-' + direction + '-width:' + pendo.TOOLTIP_ARROW_SIZE + 'px;';
            }).value().join('');
    
        var arrowDiv = dom('div._pendo-guide-arrow_', tooltipDiv).remove()
            .findOrCreate('<div class=\'_pendo-guide-arrow_\'></div>');
    
        var arrowBorder = dom('div._pendo-guide-arrow-border_ ', tooltipDiv).remove()
            .findOrCreate('<div class=\'_pendo-guide-arrow-border_\'></div>');
    
        _.each(directions, function(direction) {
            arrowDiv.removeClass(arrowPrefix + direction + '_').removeClass(direction);
            arrowBorder.removeClass(borderPrefix + direction + '_').removeClass(direction);
        });
    
        arrowDiv
            .addClass(arrowPrefix + newPosition + '_')
            // delete newPosition class after notifying customers
            .addClass(newPosition)
            .css(ARROW_BASE_STYLE + 'top:' + dim.arrow.top + 'px;left:' + dim.arrow.left + 'px;');
    
        arrowBorder
            .addClass(borderPrefix + newPosition + '_')
            // delete newPosition class after notifying customers
            .addClass(newPosition)
            .css(ARROW_BASE_STYLE + 'top:' + dim.arrow.border.top + 'px;left:' + dim.arrow.border.left + 'px;');
    
        dom(tooltipDiv)
            .append(arrowDiv)
            .append(arrowBorder);
    };
    
    /**
     *
     */
    function canTooltipStepBeShown(step) {
        return canStepBeRendered(step) || wouldBeVisibleAfterAutoScroll(getElementForGuideStep(step));
    }
    
    function scrollToTooltip(targetElement, tooltipElement, tooltipLayoutDir) {
        var elementPos = getOffsetPosition(targetElement);
        var toolTipPos = getOffsetPosition(tooltipElement);
    
        var combinedPos = function(firstPos, secondPos) {
            var top = Math.min(firstPos.top, secondPos.top),
                left = Math.min(firstPos.left, secondPos.left),
                bottom = Math.max(firstPos.top + firstPos.height, secondPos.top + secondPos.height),
                right = Math.max(firstPos.left + firstPos.width, secondPos.left + secondPos.width);
            return {
                'height': Math.abs(bottom - top),
                'width':  Math.abs(right - left),
                'top':    top,
                'left':   left
            };
        }(elementPos, toolTipPos);
        if(_isInViewport(combinedPos) === false && !toolTipPos.fixed) {
            // Move it
            var screenDim = getScreenDimensions();
            var yScrollAmt;
            var xScrollAmt;
            switch (tooltipLayoutDir) {
            case 'top':
                yScrollAmt = combinedPos.top;
                xScrollAmt = (combinedPos.left + combinedPos.width) - screenDim.width;
                break;
            case 'bottom':
                yScrollAmt = (combinedPos.top + combinedPos.height) - screenDim.height;
                xScrollAmt = (combinedPos.left + combinedPos.width) - screenDim.width;
                break;
            default:
                yScrollAmt = (combinedPos.top + combinedPos.height) - screenDim.height;
                xScrollAmt = (combinedPos.left + combinedPos.width) - screenDim.width;
                break;
            }
            yScrollAmt = (yScrollAmt < 0) ? 0 : yScrollAmt;
            xScrollAmt = (xScrollAmt < 0) ? 0 : xScrollAmt;
            window.scrollTo(xScrollAmt, yScrollAmt);
        }
    }
    
    /**
     * Show the Element-based Guide.
     * @param guide  the guide object. must have elementPathRule and content
     * @param elements  this elements array to add the guide elements to
     * @returns the element that the guide was attached to.
     */
    var showTooltipGuide = function(step, elementsTracker) {
    
        if (!canTooltipStepBeShown(step))
            {return null;}
    
        if (elementsTracker === undefined) {
            elementsTracker = activeElements;
        }
    
        step.element = getElementForGuideStep(step);
        var element = step.element;
    
        if (!element) {
            log('No element found for step: ' + step.id);
            return null;
        }
    
        scrollIntoView(element);
    
        var tooltipDiv = createTooltipGuide(element, step);
    
        if(tooltipDiv === null) {
            return null;
        }
    
        tooltipDiv.id = pendo.getTooltipDivId(step);
    
        addCloseButton(tooltipDiv, function() {
            var guide = step.getGuide();
            //eslint-disable-next-line no-alert
            if (!guide.isOnboarding() || confirm('Are you sure you want to stop this tutorial?'))
                {pendo.onGuideDismissed(step);}
        });
    
        if (!step.hideCredits) {
            pendo._addCredits(tooltipDiv);
        }
    
        // XXX candidate for using offsetParent instead of just putting on
        // the body
        dom(tooltipDiv).appendTo(getGuideAttachPoint());
        elementsTracker.push(tooltipDiv);
    
        attachEvent(tooltipDiv, 'mouseover', pendo._.partial(dom.addClass, tooltipDiv, 'mouseover'));
        attachEvent(tooltipDiv, 'mouseout', pendo._.partial(dom.removeClass, tooltipDiv, 'mouseover'));
    
        scrollToTooltip(element, tooltipDiv);
    
        addBlockOutUI(step);
    
        return element;
    };
    
    var isLessThan    = function(x,y) { return x < y; };
    var isGreaterThan = _.negate(isLessThan);
    
    var lastBlockBox = null;
    var hasBlockBoxChanged = function(box) {
        var hasChanged = !_.isEqual(box, lastBlockBox);
        lastBlockBox = box;
        return hasChanged;
    };
    
    var lastBodySize = null;
    var hasBodyDimensionsChanged = function(size) {
        var hasChanged = !_.isEqual(size, lastBodySize);
        lastBodySize = size;
        return hasChanged;
    };
    
    /**
     * Computes the size/position of the four blockout overlay regions.
     * @param  {Rect} bodySize
     * @param  {Rect} box
     * @param  {Number} padding
     * @return {Object} Object with CSS positioning info for the north, east, south, and west regions
     */
    function computeBlockOutOverlayPositions(bodySize, box, padding) {
        var coords = {};
    
        var adjustedTop = box.top - bodySize.top;
        var adjustedLeft = box.left - bodySize.left;
    
        coords.top = adjustedTop - padding;
        coords.left = adjustedLeft - padding;
    
        coords.height = box.height + 2 * padding;
        coords.width = box.width + 2 * padding;
    
        var offset = { 'left': 0, 'top': 0 };
        if (positionFixedActsLikePositionAbsolute()) {
            offset = bodyOffset();
            coords.left += documentScrollLeft();
            coords.top += documentScrollTop();
        }
    
        coords.bottom = coords.top + coords.height;
        coords.right = coords.left + coords.width;
    
        return {
            'north': {
                'height': Math.max(coords.top, 0),
                'left':   -offset.left,
                'top':    -offset.top,
                'right':  0
            },
            'east': {
                'top':    coords.top - offset.top,
                'bottom': 0,
                'right':  0,
                'left':   coords.right - offset.left
            },
            'south': {
                'top':    coords.bottom - offset.top,
                'width':  Math.max(coords.right, 0),
                'bottom': 0,
                'left':   -offset.left
            },
            'west': {
                'top':    coords.top - offset.top,
                'height': Math.max(coords.height, 0),
                'left':   -offset.left,
                'width':  Math.max(coords.left, 0)
            }
        };
    }
    
    var lastScreenCoords = null;
    var haveScreenCoordsChanged = function(coords) {
        var hasChanged = !_.isEqual(coords, lastScreenCoords);
        lastScreenCoords = coords;
        return hasChanged;
    };
    
    /**
     * Computes the bounding box for the given elements.
     * @param  {HTMLElement[]} elements
     * @return {Rect}
     */
    function computeBlockOutBoundingBox(elements) {
        var box = _.reduce(elements, function(box, elem) {
            if (!isElementVisible(elem)) return box;
    
            var rect = getClientRect(elem);
    
            box.fixed = box.fixed && rect.fixed;
    
            _.each([
                ['top', isLessThan],
                ['right', isGreaterThan],
                ['bottom', isGreaterThan],
                ['left', isLessThan]
            ], function(dirTup) {
                var dir = dirTup[0];
                var op = dirTup[1];
    
                if (!box[dir] || op(rect[dir], box[dir]))
                    {box[dir] = rect[dir];}
            });
    
            return box;
        }, {
            'fixed': true
        });
    
        box.height = box.bottom - box.top;
        box.width = box.right - box.left;
    
        // Undo the body offset, if not fixed
        var offset = bodyOffset();
        if (!box.fixed) {
            box.left += offset.left;
            box.right += offset.left;
            box.top += offset.top;
            box.bottom += offset.top;
        }
    
        box.fixed = !!box.fixed;
    
        return box;
    }
    
    var addBlockOutUI = function(step) {
        try {
            // should we add?
            if (!step.attributes || !step.attributes.blockOutUI || !step.attributes.blockOutUI.enabled) {
                return;
            }
    
            // get step's target area elements
            // compute the TargetArea boundaries
            var config = step.attributes.blockOutUI;
            var targetAreaElements = [];
            targetAreaElements.push(step.element);
            targetAreaElements = targetAreaElements.concat(
                _.compact(
                    _.flatten(
                        _.map([].concat(config.additionalElements),
                            function(sel) { return Sizzle(sel); }
                        )
                    )
                )
            );
    
            var box = computeBlockOutBoundingBox(targetAreaElements);
    
            var padding = config.padding || 0;
    
            var bodySize = getClientRect(getBody());
    
            if (box.fixed) {
                bodySize.top = 0;
                bodySize.bottom = bodySize.height;
                bodySize.left = 0;
                bodySize.right = bodySize.width;
            }
    
            // build the block out regions for North, South, West, East
            var coords = computeBlockOutOverlayPositions(bodySize, box, padding);
    
            // has box specs changed?  if not, don't redraw
            if (!hasBlockBoxChanged(box) &&
                !hasBodyDimensionsChanged(bodySize) &&
                !haveScreenCoordsChanged(coords))
                {return;}
    
            var defaults = {
                'z-index':  config.zindex || 10000,
                'position': 'fixed'
            };
    
            if (config.bgColor) {
                defaults['background-color'] = config.bgColor;
            }
            if (config.opacity) {
                defaults.opacity = config.opacity;
            }
    
            var body = dom('body');
            _.each(coords, function(overlay, direction) {
                body.append(buildBackdropDiv(direction, _.extend({}, overlay, defaults)));
            });
        } catch (e) {
            log('Failed to add BlockOut ui', 'error');
        }
    };
    
    var buildBackdropDiv = function(cls, styles) {
        var div = dom('div._pendo-guide-tt-region-block_._pendo-region-' + cls + '_');
        if (div.length > 0)
            {div = div[0];}
        else
            {div = dom('<div class="_pendo-guide-tt-region-block_ _pendo-region-' + cls + '_"></div>');}
    
        dom(div).css(styles);
    
        return div;
    };
    
    var checkPlacementChanged = function(elPos) {
        var isE = _.isEqual(elPos, lastElementPos);
        lastElementPos = elPos;
        return !isE;
    };
    
    var placeTooltip = function(step) {
        var element = getElementForGuideStep(step);
        var elPos = getOffsetPosition(element);
    
        addBlockOutUI(step);
    
        // has the elPos changed?
        if (!checkPlacementChanged(elPos)) return;
    
        var height    = step.attributes.height;
        var width     = step.attributes.width;
        var layoutDir = step.attributes.layoutDir;
    
        var dim = getTooltipDimensions(elPos, height, width, layoutDir);
    
        // we can update the dim.top and dim.left now
        var ttdiv = dom(buildTooltipCSSSelector(step));
        ttdiv.css({
            'top':      dim.top,
            'left':     dim.left,
            'position': elPos.fixed ? 'fixed' : ''
        });
    
        buildAndAppendArrow(ttdiv, dim);
    };
    
    /**
     * Determines if the element would be visible after scrolling
     * it into view.
     * @param  {HTMLElement} element
     * @return {Boolean} True if the element would be visible after scrolling
     */
    function wouldBeVisibleAfterAutoScroll(element) {
        var scrollRect;
        var yScrollAmount;
        var xScrollAmount;
        var diff;
        var direction;
        var overflowScroll = /(auto|scroll)/;
        var overflowAny = /(auto|scroll|hidden)/;
        var pbody = getBody();
        var clientRect = getClientRect(element);
        var scrollParent = getScrollParent(element, overflowAny);
    
        if (!isElementVisibleInBody(element)) {
            return false;
        }
    
        while (scrollParent && scrollParent !== pbody) {
            scrollRect = getClientRect(scrollParent);
    
            direction = getOverflowDirection(scrollParent, overflowScroll);
    
            if (direction !== OverflowDirection.NONE) {
                yScrollAmount = 0;
                xScrollAmount = 0;
    
                if (direction === OverflowDirection.Y || direction === OverflowDirection.BOTH) {
                    if (clientRect.bottom > scrollRect.bottom) {
                        yScrollAmount += clientRect.bottom - scrollRect.bottom;
                        clientRect.top -= yScrollAmount;
                        clientRect.bottom -= yScrollAmount;
                    }
                    if (clientRect.top < scrollRect.top) {
                        diff = scrollRect.top - clientRect.top;
                        yScrollAmount -= diff;
                        clientRect.top += diff;
                        clientRect.bottom += diff;
                    }
                }
    
                if (direction === OverflowDirection.X || direction === OverflowDirection.BOTH) {
                    if (clientRect.right > scrollRect.right) {
                        xScrollAmount += clientRect.right - scrollRect.right;
                        clientRect.left -= xScrollAmount;
                        clientRect.right -= xScrollAmount;
                    }
                    if (clientRect.left < scrollRect.left) {
                        diff = scrollRect.left - clientRect.left;
                        xScrollAmount -= diff;
                        clientRect.left += diff;
                        clientRect.right += diff;
                    }
                }
            }
    
            if (!isVisibleInScrollParent(clientRect, scrollParent, overflowAny)) {
                return false;
            }
    
            scrollParent = getScrollParent(scrollParent, overflowAny);
        }
    
        return true;
    }
    
    var getTooltipDimensions = function(elementPos, height, width, layoutDir) {
    
        var arrowSize = pendo.TOOLTIP_ARROW_SIZE;
        var dim = {
            'arrow':   { 'border': {} },
            'content': {
                'top':  arrowSize,
                'left': arrowSize
            }
        };
        var screenDim = pendo._get_screen_dim();
    
        dim.width = Math.min(width, screenDim.width); //Do not bust out of the horizontal space (mobile)
        dim.height = height; //... but okay to have to scroll vertically a bit
        dim.content.width = dim.width - (2 * arrowSize);
        dim.content.height = dim.height - (2 * arrowSize);
    
        if (!layoutDir) layoutDir = 'auto';
    
        dim = determineHorizontalBias(dim, elementPos, screenDim, layoutDir);
        dim = determineArrowPosition(dim, elementPos, screenDim, layoutDir);
        dim = buildArrowDimensions(dim, elementPos, screenDim);
    
        return dim;
    };
    
    var determineHorizontalBias = function(dim, elementPos, screenDim, layoutDir) {
        if (layoutDir == 'right' || layoutDir == 'left') {
            pendo.log('Setting layout position to ' + layoutDir);
            dim.arrow.hbias = layoutDir;
            return dim;
        }
    
        // if elementPos is in center column of screen
        // x(0) is width / 3;  x(1) is x(0) * 2;
        // if x(0) < elementPos.left < x(1)
        var colSize = screenDim.width / 3;
        var centerCol = [
            colSize,
            colSize * 2
        ];
    
    
        if (centerCol[0] < elementPos.left && elementPos.left < centerCol[1])
            {dim.arrow.hbias = 'center';}
        else if (elementPos.left < (screenDim.width / 2))
            {dim.arrow.hbias = 'left';}
        else
            {dim.arrow.hbias = 'right';}
    
        return dim;
    };
    
    var determineArrowPosition = function(dim, elementPos, screenDim, layoutDir) {
        if (!!layoutDir && layoutDir != 'DEFAULT' && layoutDir != 'auto')
            {dim.arrowPosition = layoutDir;}
    
        if (!dim.arrowPosition) {
            var top = elementPos.top - documentScrollTop(),
                left = elementPos.left - documentScrollLeft(),
                right = left + elementPos.width;
    
            // determine it organically
            if (top < (screenDim.height / 3)) {
                //Upper third of viewport, put arrow on top of guide
                dim.arrowPosition = 'top';
            } else if (top > (2 * screenDim.height / 3) || dim.arrow.hbias == 'center') {
                //Bottom third of viewport
                dim.arrowPosition = 'bottom';
            } else if (left < dim.width && screenDim.width - right < dim.width) {
                //Not enough horizontal space for the hbias default, so just position it below the element
                dim.arrowPosition = 'top';
            } else {
                //Finally, just whatever the arrow's hbias is (left/right/center)
                dim.arrowPosition = dim.arrow.hbias;
            }
        }
    
        return dim;
    };
    
    
    var buildArrowDimensions = function(dim, elementPos, screenDim) {
    
        var height = dim.height,
            width = dim.width;
    
        if (isBrowserInQuirksmode()) {
            return buildArrowDimensionsQM(dim, elementPos, screenDim);
        }
    
        if (dim.arrowPosition == 'top' || dim.arrowPosition == 'bottom') {
            var TOOLTIP_ARROW_OFFSET = 10;
            var adjustment = 0;
    
            if (dim.arrowPosition == 'top') {
                dim.top = elementPos.top + elementPos.height; // + (isOldIE(9) ? 10 : 0);
                dim.arrow.top = isOldIE(9, 6) ? 1 + 5 : 2; // NOTE: 5 is the filter size
                adjustment = -1;
            } else if (dim.arrowPosition == 'bottom') {
                dim.top = elementPos.top - height;
                dim.arrow.top = height - pendo.TOOLTIP_ARROW_SIZE - 1;
                dim.arrow.top += isOldIE(9,6) ? 6 : 0;
                dim.arrow.top += (msie == 8) ? -1 : 0;
                adjustment = 1;
            }
    
            var minArrowLeft = TOOLTIP_ARROW_OFFSET + pendo.TOOLTIP_ARROW_SIZE,
                maxArrowLeft = width - (3 * pendo.TOOLTIP_ARROW_SIZE) - TOOLTIP_ARROW_OFFSET;
    
            if(dim.arrow.hbias == 'left') {
                dim.left = elementPos.left + (elementPos.width / 2) - (TOOLTIP_ARROW_OFFSET + (2 * pendo.TOOLTIP_ARROW_SIZE));
                dim.arrow.left = minArrowLeft;
            } else if(dim.arrow.hbias == 'right') {
                dim.left = elementPos.left - width + (elementPos.width / 2) + (TOOLTIP_ARROW_OFFSET + (2 * pendo.TOOLTIP_ARROW_SIZE));
                dim.arrow.left = maxArrowLeft;
            } else {
                // ASSUME CENTER
                dim.left = elementPos.left + (elementPos.width / 2) - (width / 2);
                dim.arrow.left = (width / 2) - pendo.TOOLTIP_ARROW_SIZE;
            }
    
            //Adjust position of guide and arrow if we're busting out of the horizontal area,
            //but only allow the arrow to float up to the minimum/maximum constraints
            //NOTE: not done in quirks mode, b/c quirksmode has no business on mobile AFAIK
            //      can also be explicitly disabled to force arrow to left/right (e.g. for launcher)
            if (dim.arrow.floating !== false) {
                var leftOffset = (dim.left + width) - screenDim.width;
                leftOffset -= Math.max(0, (dim.arrow.left + leftOffset) - maxArrowLeft);
                if (leftOffset > 0) {
                    dim.left -= leftOffset;
                    dim.arrow.left += leftOffset;
                }
                var rightOffset = -dim.left;
                rightOffset -= Math.max(0, minArrowLeft - (dim.arrow.left - rightOffset));
                if (rightOffset > 0) {
                    dim.left += rightOffset;
                    dim.arrow.left -= rightOffset;
                }
            }
    
            dim.arrow.border.top  = dim.arrow.top + adjustment;
            dim.arrow.border.left = dim.arrow.left;
    
            return dim;
        }
    
        // else left or right
    
        if (dim.arrow.hbias == 'left') {
            dim.left = elementPos.left + elementPos.width;
            dim.arrow.left = 1;
            dim.arrow.left += isOldIE(10,6) ? 5 : 0;
            dim.arrow.border.left = dim.arrow.left - 1;
        } else if (dim.arrow.hbias == 'right') {
    
            // this keeps the guide visible.
            dim.left = Math.max(0, elementPos.left - width);
            dim.arrow.left = width - pendo.TOOLTIP_ARROW_SIZE - 1;
            dim.arrow.left += isOldIE(10,6) ? 5 : 0;
    
            // hack for ie 10 & 11 in compat mode
            dim.arrow.left += (msie == 7 && trident >= 6) ? 1 : 0;
    
            dim.arrow.border.left = dim.arrow.left + 1;
        }
    
        dim.top = elementPos.top - (height / 2) + (elementPos.height / 2);
        dim.arrow.top = (height / 2) - pendo.TOOLTIP_ARROW_SIZE;
        dim.arrow.border.top  = dim.arrow.top;
    
        return dim;
    };
    
    pendo.LB_DEFAULT_WIDTH = 500;
    pendo.LB_DEFAULT_HEIGHT = 500;
    
    var LIGHTBOX_CSS_NAME = '_pendo-guide-lb_';
    
    var canLightboxStepBeShown = function(step) {
        return canStepBeRendered(step);
    };
    
    var addOverlay = function(isOnboarding, step) {
        var overlayExistsOnPage = !!pendo.dom('._pendo-backdrop_')[0];
        if (!get(step, 'overlayDiv[0]')) {
            step.overlayDiv = dom('<div/>').addClass('_pendo-backdrop_');
        }
    
        if (overlayExistsOnPage === false) {
            step.elements.push(step.overlayDiv[0]);
            step.overlayDiv.appendTo(getGuideAttachPoint());
        }
    
        if (isBrowserInQuirksmode()) {
            step.overlayDiv.css({
                'height':   '100%',
                'width':    '100%',
                'position': 'absolute'
            });
        }
    
        if (isOnboarding)
            {dom(step.overlayDiv).addClass('_pendo-onboarding_');}
    
        return step.overlayDiv;
    };
    
    var renderLightboxGuide = function(step) {
        var guideElement = step.guideElement,
            arrowSize = pendo.TOOLTIP_ARROW_SIZE,
            height = step.attributes.height,
            width = step.attributes.width,
            lMargin = Math.floor((width / 2)),
            tMargin = Math.floor((height / 2));
    
        guideElement.addClass(LIGHTBOX_CSS_NAME).css({
            'top':         '50%',
            'left':        '50%',
            'margin-top':  -tMargin,
            'margin-left': -lMargin
        });
    
        dom('._pendo-guide-container_', guideElement).css({
            'bottom': arrowSize,
            'right':  arrowSize
        });
    
        if (isBrowserInQuirksmode()) {
            guideElement.css({
                'position': 'absolute'
            });
        }
    };
    
    var showLightboxGuide = function(step, elements) {
    
        if (!canLightboxStepBeShown(step))
            {return null;}
    
        if (elements === undefined) {
            elements = activeElements;
        }
    
        step.element = getElementForGuideStep(step);
    
        renderLightboxGuide(step);
    
        var isOnboarding = step.getGuide() ? step.getGuide().isOnboarding() : false;
        addOverlay(isOnboarding, step);
    
        var lbDiv = step.guideElement;
        elements.push(lbDiv[0]);//Remove the dom wrapper
        lbDiv.appendTo(getGuideAttachPoint());
    };
    
    var MOBILE_LIGHTBOX_CSS_NAME = '_pendo-guide-mobile-lb_';
    
    var renderMobileLightboxGuide = function(step) {
        var lbDiv = step.guideElement;
        lbDiv.addClass(MOBILE_LIGHTBOX_CSS_NAME);
    };
    
    var showMobileLightboxGuide = function(step, elements) {
    
        if (!canLightboxStepBeShown(step))
            {return null;}
    
        if (elements === undefined) {
            elements = activeElements;
        }
    
        step.element = getElementForGuideStep(step);
    
        renderMobileLightboxGuide(step);
    
        var isOnboarding = step.getGuide() ? step.getGuide().isOnboarding() : false;
        var overlay = addOverlay(isOnboarding, step);
    
        var lbDiv = step.guideElement,
            arrowSize = pendo.TOOLTIP_ARROW_SIZE;
        lbDiv.css({
            'width':  '',
            'height': ''
        });
        var container = dom('._pendo-guide-container_', lbDiv).css({
            'bottom': arrowSize,
            'right':  arrowSize
        });
    
        //Make sure the close button is the first thing in the container
        dom('._pendo-close-guide_', lbDiv).remove().prependTo(container);
    
        lbDiv.appendTo(getGuideAttachPoint());
        elements.push(lbDiv[0]);
    
        function preventScroll(e) {
            e.preventDefault();
        }
    
        attachEvent(overlay[0], 'touchmove', preventScroll);
        attachEvent(lbDiv[0], 'touchmove', preventScroll);
    };
    
    var LAUNCHER_SEARCHING_CLASS = '_pendo-launcher-searching_';
    
    function LauncherSearch() {
        var self = this;
        var search = {
            'text':      '',
            'highlight': highlight,
            'clear':     clear
        };
    
        if (self.data && self.data.enableSearch && self.data.enableSearch) {
            self.data.search = search;
    
            if(!pendo.disableGuideCenterContentSearch) {
                self.before('update', prefetchGuideContentForSearch);
            }
    
            self.before('update', function() {
                search.text = getLauncherSearchText().join(' ');
    
                var launcherElem = dom('._pendo-launcher_');
                if (search.text) {
                    launcherElem.addClass(LAUNCHER_SEARCHING_CLASS);
                } else {
                    launcherElem.removeClass(LAUNCHER_SEARCHING_CLASS);
                }
            });
        }
    
        return self;
    
        function highlight(word) {
            if (!search.text) {
                return word;
            }
            return (word || '').replace(new RegExp(search.text, 'gi'), '<strong>$&</strong>');
        }
    
        function clear() {
            dom(SEARCHBOX_CSS_SELECTOR).each(function() {
                this.value = '';
            });
        }
    }
    
    function isSearchEnabled() {
        if (!pendo.guideWidget) return false;
    
        var config = pendo.guideWidget.data;
        return (!!config && !!config.enableSearch);
    }
    
    function launcherHasActiveSearch() {
        return getLauncherSearchText().length > 0;
    }
    
    function getLauncherSearchText() {
        if (!isSearchEnabled()) return [];
    
        var searchbox = dom(SEARCHBOX_CSS_SELECTOR)[0];
        if (!searchbox) return []; // shouldn't happen but is b/c of a bug
        // somewhere in onboarding mode :(
    
        var searchText = searchbox.value;
    
        if (searchText.length > 0) {
            searchText = trim.call(searchText);
            return [].concat(_.compact(searchText.split(' ')));
        }
        return [];
    }
    
    function prefetchGuideContentForSearch(guides) {
        return q.all(_.map(guides, function(guide) {
            return guide.fetchContent();
        }));
    }
    
    function applySearch(guides) {
        var searchTerms = getLauncherSearchText();
        if (searchTerms.length === 0) return guides;
    
        var results = _.map(searchTerms, _.partial(doSearch, guides));
        results = _.union.apply(_, results);
    
        return results;
    }
    
    function doSearch(guides, srchTxt) {
        log('doing search on ' + srchTxt, 'launcher', 'search', 'guides');
    
        guides = guides || getActiveGuides();
    
        if (!srchTxt || srchTxt.length === 0) return guides;
    
        function guideSearchResults(guide) {
            return guide.searchFor(srchTxt);
        }
    
        function tagNameAndContent(obj) {
            var priorityOrder = ['tag', 'name', 'content'];
            return _.indexOf(priorityOrder, obj.field);
        }
    
        return _.chain(guides)
            .filter(isLauncher)
            .map(guideSearchResults)
            .compact()
            .sortBy(tagNameAndContent)
            .pluck('guide')
            .value();
    }
    
    var SEARCHBOX_CSS_NAME = '_pendo-launcher-search-box_';
    var SEARCHBOX_CSS_SELECTOR = '.' + SEARCHBOX_CSS_NAME + ' input';
    var LAUNCHER_DEFAULT_WIDTH = 330;
    var LAUNCHER_DEFAULT_HEIGHT = 310;
    var launcherBadge = null;
    var launcherTooltipDiv = null;
    var isPreventLauncher = false;
    //eslint-disable-next-line no-unused-vars
    var launcherHash = null;
    var launcherActiveClass = '_pendo-launcher-active_';
    var launcherElement = null;
    
    var defaultLauncherTemplate = function() { return ''; };
    
    pendo.defaultLauncher = function defaultLauncher(content, template) {
        defaultLauncherTemplate = template;
    };
    
    function getLauncherGuideList(guideList) {
        var launchers = _.filter(guideList || getActiveGuides(), isLauncher);
        return applySearch(launchers);
    }
    
    function computeLauncherHash(launcherGuideList) {
        return crc32(_.map(launcherGuideList, function(guide) {
            // don't re-evaluate the launcher template when the seen states of what's new guides change
            var seenState = guide.isWhatsNew() ? [] : _.pluck(guide.steps, 'seenState');
            return {
                'id':        guide.id,
                'seenState': seenState
            };
        }));
    }
    
    function LauncherBadge(config) {
        var self = this;
        var launchType = config.launchType ? config.launchType : 'badge';
    
        _.extend(self, {
            'show':      show,
            'hide':      hide,
            'wrap':      wrap,
            'dispose':   dispose,
            'setActive': setActive
        });
    
        create(config);
    
        function create(config) {
            var position = config.position || 'bottom-right';
    
            var element = document.createElement('img');
            self.element = element;
            dom(element).addClass('_pendo-launcher-badge_')
                .addClass('_pendo-launcher-badge-' + position + '_');
    
            if (config.launcherBadgeUrl) {
                element.src = replaceWithContentHost(config.launcherBadgeUrl);
            }
    
            element.onerror = function(e) {
                pendo.log('[Agent] Error! Unable to load guide center image ' + config.launcherBadgeUrl);
                writeException({ 'imgSrc': config.launcherBadgeUrl }, 'ERROR in when attempting to render guide center badge image');
            };
    
            if (isBrowserInQuirksmode()) {
                attachEvent(element, 'mouseover', function(evt) {
                    dom(element).addClass('_pendo-launcher-badge-active_');
                });
    
                attachEvent(element, 'mouseout', function(evt) {
                    dom(element).removeClass('_pendo-launcher-badge-active_');
                });
    
                dom(element).css({ 'position': 'absolute' });
            }
    
            getGuideAttachPoint().appendChild(element);
        }
    
        function show() {
            if (launchType === 'badge') {
                dom(self.element).css('display: ;');
            }
        }
    
        function hide() {
            dom(self.element).css('display: none;');
        }
    
        function wrap() {
            var element = self.element;
            if (element && /^img$/i.test(element.nodeName)) {
                var badgeWrapper = dom('<div>')
                    .addClass(element.className)
                    .append(element)
                    .appendTo(getGuideAttachPoint());
                element.className = '';
                self.element = badgeWrapper[0];
            }
        }
    
        function dispose() {
            dom.removeNode(self.element);
        }
    
        function setActive(isActive) {
            if (isActive) {
                dom(self.element).addClass(launcherActiveClass);
            } else {
                dom(self.element).removeClass(launcherActiveClass);
            }
        }
    }
    
    function LauncherElement(config) {
        var self = this;
    
        pendo.guideWidget.removeCountBadge = function() {
            dom('._pendo-launcher-whatsnew-count_').remove();
        };
    
        if (config && config.elementMatch) {
            config.launchElement = config.elementMatch.selection;
        }
    
        _.extend(self, {
            'getLauncherTarget': getLauncherTarget,
            'dispose':           dispose
        });
    
        create(config);
    
        function getLauncherTarget() {
            return dom(getSelector())[0];
        }
    
        function getSelector() {
            if (config.launchType === 'element' && config.launchElement) {
                return config.launchElement;
            } else {
                return '._pendo-launcher-badge_';
            }
        }
    
        function create(config) {
            attachEvent(document, 'click', click);
        }
    
        function click(e) {
            var target = getTarget(e);
            var selector = getSelector();
            var element = dom(target).closest(selector);
            if (element.length) {
                if (isLauncherVisible()) {
                    agentStorage.write('launcher-closed', 'yes', 10 * 24 * 60 * 60 * 1000);
                } else {
                    pendo.guideWidget.position(target);
                }
    
                toggleLauncher();
            }
        }
    
        function dispose() {
            detachEvent(document, 'click', click);
            if (config && config.whatsnew && config.whatsnew.enabled) {
                removeCountBadge();
            }
        }
    }
    
    function Launcher() {
        var BOTTOM_RIGHT = 'bottom-right';
        var BOTTOM_LEFT = 'bottom-left';
        var TOP_LEFT = 'top-left';
        var TOP_RIGHT = 'top-right';
        var launcherHash;
    
        this.update = function(guides, prefiltered) {
            var launcherGuides;
            if (!prefiltered) {
                launcherGuides = getLauncherGuideList(guides);
            } else {
                launcherGuides = guides;
            }
    
            var hash = computeLauncherHash(launcherGuides) + crc32(getLauncherSearchText());
    
            if (hash !== launcherHash) { // Only update if the list of launcher guides changed
                launcherHash = hash;
    
                this.updateLauncherContent(launcherGuides);
            }
    
            showHideLauncher();
    
            return launcherGuides.length > 0;
        };
    
        this.updateLauncherContent = updateLauncherContent;
    
        this.guideStatus = function(guide) {
            if (guide.isComplete()) {
                return 'complete';
            } else if (guide.isInProgress()) {
                return 'in-progress';
            } else {
                return 'not-started';
            }
        };
    
        this.render = function() {
            var config = this.data || {};
    
            // FIXME - would prefer this didn't happen in launcher.render
            launcherBadge = new LauncherBadge(config);
    
            var height = config.height || LAUNCHER_DEFAULT_HEIGHT;
            if (config.enableSearch) height += (isBrowserInQuirksmode() ? 50 : 39);
            if (this && !this.hidePoweredBy) height += 40;
    
            if (config.addHeight) height += config.addHeight;
            this.height = height;
    
            var width = config.width || LAUNCHER_DEFAULT_WIDTH;
            if (config.addWidth) width += config.addWidth;
            this.width = width;
    
            var launcherElement = dom('<div>')
                .addClass('_pendo-launcher_');
            launcherTooltipDiv = launcherElement[0];
    
            var elementPos = getOffsetPosition(launcherBadge.element);
            var dim = getTooltipDimensions(elementPos, height, width);
    
            launcherElement.css({
                'width':  width,
                'height': height
            });
    
            var gutterSize = pendo.TOOLTIP_ARROW_SIZE;
            var tooltipContainerDiv = dom('<div/>')
                .addClass('_pendo-guide-container_ ' + dim.arrowPosition)
                .addClass('_pendo-guide-container-' + dim.arrowPosition + '_')
                .css({
                    'top':    gutterSize,
                    'left':   gutterSize,
                    'width':  width - gutterSize * 2,
                    'height': height - gutterSize * 2
                })
                .appendTo(launcherElement);
    
            var context = getLauncherContext();
            var content = replaceWithContentHost(replaceInlineStyles(this.template(context)));
            var tooltipContentDiv = dom('<div/>')
                .addClass('_pendo-guide-content_')
                .html(content)
                .appendTo(tooltipContainerDiv);
    
            if (config.addUISection) {
                config.addUISection(launcherElement[0]);
            }
    
            pendo._addCloseButton(launcherElement[0], function() {
                toggleLauncher();
                agentStorage.write('launcher-closed', 'yes', 8 * 60 * 60 * 1000);
            });
    
            tooltipContentDiv.on('click', function(e) {
                var item = dom(getTarget(e)).closest('._pendo-launcher-item_');
                if (item && item.length) {
                    var idMatch = /^launcher-(.+)$/.exec(trim.call(item.attr('id'))),
                        id = idMatch && idMatch[1],
                        guide = findGuideById(id);
                    if (guide && !guide.isWhatsNew()) {
                        showGuide(guide.steps[0], 'launcher');
                        toggleLauncher();
                        stopEvent(e);
                    }
                }
            });
    
            if (isBrowserInQuirksmode()) {
                dom('._pendo-launcher-header_', launcherElement).css({
                    'padding':      '10px',
                    'margin-right': '10px',
                    'margin-left':  '10px'
                });
    
                dom('._pendo-launcher-footer_', launcherElement).css({
                    'border-top': '1px solid #bbb'
                });
    
                launcherElement.css({ 'position': 'absolute' });
            }
    
            // Eval pendo-style directives
            // FIXME - move elsewhere?
            launcherElement.find('[pendo-style]').each(function() {
                var style = this.getAttribute('pendo-style');
                dom(this).css(style);
            });
    
            launcherElement.appendTo(getGuideAttachPoint());
    
            if (_.isFunction(this.script)) {
                this.script(this);
            }
    
            // config.autoHeight adds responsive height to launcher
            // only supported in ie9+ due to calc() - front end will warn users of this
            if (config.autoHeight && config.autoHeight.enabled && !isOldIE(9, 6)) {
                var offsetHeight = config.autoHeight.offset || 100;
    
                launcherElement.css({
                    'height':    'calc(100% - ' + offsetHeight + 'px)',
                    'maxHeight': config.height,
                    'minHeight': config.height / 2
                });
    
                dom('._pendo-guide-container_.' + dim.arrowPosition).css({
                    'maxHeight': config.height - 30,
                    'minHeight': (config.height / 2) - 30,
                    'height':    'calc(100% - 30px)'
                });
            }
        };
    
        this.position = function(target) {
            if (!target) {
                return;
            }
            var config = this.data;
            var elementPos = getOffsetPosition(target);
            var dim = getTooltipDimensions(elementPos, this.height, this.width);
            var launcherElement = dom(launcherTooltipDiv);
            var launchType = config.launchType ? config.launchType : 'badge';
    
            if (launchType === 'badge') {
                var position = config.position;
                var allPositions = [BOTTOM_RIGHT, BOTTOM_LEFT, TOP_LEFT, TOP_RIGHT];
                if (_.indexOf(allPositions, config.position) < 0) {
                    // Default position
                    position = BOTTOM_RIGHT;
                }
    
                _.each(allPositions, function(positionToRemove) {
                    launcherElement.removeClass('_pendo-launcher-' + positionToRemove + '_');
                });
                launcherElement.addClass('_pendo-launcher-' + position + '_');
    
                // Force arrow position
                dim.arrow = dim.arrow || {};
                dim.arrowPosition = _.contains([BOTTOM_RIGHT, BOTTOM_LEFT], position) ? 'bottom' : 'top';
                dim.arrow.hbias = _.contains([BOTTOM_LEFT, TOP_LEFT], position) ? 'left' : 'right';
                dim.arrow.floating = false;
            } else if (launchType === 'element') {
                launcherElement.css({
                    'top':      dim.top,
                    'left':     dim.left,
                    'height':   dim.height,
                    'width':    dim.width,
                    'position': elementPos.fixed ? 'fixed' : 'absolute'
                });
            }
    
            dom('._pendo-guide-arrow_,._pendo-guide-arrow-border_', launcherElement).remove();
            buildArrowDimensions(dim, elementPos, { 'width': Infinity, 'height': Infinity });
            buildAndAppendArrow(launcherElement[0], dim);
            launcherElement.find('._pendo-guide-container_')
                .removeClass('top left bottom right')
                .addClass(dim.arrowPosition);
        };
    
        this.toggle = toggleLauncher;
    
        return this;
    }
    
    Launcher.create = function(guideWidget) {
        return _.reduce(Launcher.behaviors, function(guideWidget, behavior) {
            return behavior.call(guideWidget);
        }, guideWidget);
    };
    
    Launcher.behaviors = [
        Wrappable,
        Launcher,
        ContentValidation.Launcher,
        LauncherSearch,
        Onboarding,
        WhatsNewList
    ];
    
    function Onboarding() {
        var self = this;
    
        if (self.data && self.data.onboarding) {
            var onboarding = self.onboarding = self.onboarding || {};
    
            self.before('update', function(guides) {
                var onboardingGuides = _.filter(guides, isOB);
                var completedGuides = _.filter(onboardingGuides, function(guide) {
                    return self.guideStatus(guide) == 'complete';
                });
                var total = onboarding.total = onboardingGuides.length;
                onboarding.percentComplete = total > 0 ? Math.round((completedGuides.length / total) * 100) : 0;
    
                var badgeAndLauncher = dom('._pendo-launcher_,._pendo-launcher-badge_');
                if (total) {
                    badgeAndLauncher.addClass('onboarding');
                    badgeAndLauncher.addClass('_pendo-launcher-onboarding_');
                } else {
                    badgeAndLauncher.removeClass('onboarding');
                    badgeAndLauncher.removeClass('_pendo-launcher-onboarding_');
                }
            });
    
            // For easy support of "pendo-style" onboarding status
            self.getOnboardingState = function(guide) {
                if (guide.isComplete()) return 'complete';
                if (guide.isInProgress()) return 'in-progress';
                if (guide.isNotStarted()) return 'not-started';
                return null;
            };
        }
    
        return self;
    }
    
    function WhatsNewList() {
        var self = this;
    
        var unseenCountElem = dom('<div>').addClass('_pendo-launcher-whatsnew-count_');
    
        if (self.data && self.data.whatsnew && self.data.whatsnew.enabled) {
            self.before('updateLauncherContent', function(guides) {
                var whatsNewGuides = _.filter(guides, function(guide) {
                    return guide.isWhatsNew();
                });
    
                whatsNewGuides.sort(compareGuides);
                self.data.whatsnew.total = whatsNewGuides.length;
                self.data.whatsnew.guides = whatsNewGuides;
            });
    
            self.after('update', function(guides) {
                var whatsNewGuides = self.data.whatsnew.guides;
    
                _.each(whatsNewGuides, function(guide) {
                    guide.show(); // fetch, validate, and render the guide
                });
    
                // add all guides (in order) that have finished loading content into the launcher
                _.find(whatsNewGuides, function(guide) {
                    if (!guide.isReady()) return true;
                    guide.addToLauncher();
                });
    
                var unseenCount = _.filter(whatsNewGuides, function(guide) {
                    return guide.steps[0].seenState !== 'active';
                }).length;
    
                if (unseenCount !== self.data.whatsnew.unseenCount) {
                    unseenCountElem.html(unseenCount).css({ 'display': unseenCount ? '' : 'none' });
                    self.data.whatsnew.unseenCount = unseenCount;
                    dom('span._pendo-launcher-whatsnew-count_').text(self.data.whatsnew.unseenCount);
                }
            });
    
            self.after('render', function() {
                if (isLauncherOnElement()) {
                    unseenCountElem.appendTo(this.data.launchElement);
                } else {
                    launcherBadge.wrap();
                    unseenCountElem.appendTo(launcherBadge.element);
                }
            });
        }
    
        return self;
    
        function compareGuides(guide1, guide2) {
            var comparison = compareStartDates(guide1, guide2);
            if (comparison === 0) {
                return compareNames(guide1, guide2);
            }
            return comparison;
        }
    
        function compareStartDates(guide1, guide2) {
            var startDate1 = guide1.showsAfter || guide1.publishedAt || 0;
            var startDate2 = guide2.showsAfter || guide2.publishedAt || 0;
            return startDate2 - startDate1;
        }
    
        function compareNames(guide1, guide2) {
            var name1 = guide1.name.toLowerCase();
            var name2 = guide2.name.toLowerCase();
            if (name1 > name2) {
                return 1;
            } else if (name1 < name2) {
                return -1;
            } else {
                return 0;
            }
        }
    }
    
    /**
     * Replace style attributes with pendo-style attributes.
     * Workaround for CSP restrictions.
     * @param  {String} content
     * @return {String}
     */
    function replaceInlineStyles(content) {
        if (_.isString(content)) {
            content = content.replace(/\s+(style)=/gi, ' pendo-style=');
        }
        return content;
    }
    
    /**
     * Looks for a guide of type "launcher" and overrides
     * launcher properties with values from the guide.
     * @param {Launcher} launcher
     * @param {Guide[]} guides
     */
    function upgradeLauncher(launcher, guides) {
        var launcherConfig = launcher && launcher.data;
        var launcherGuide = _.find(guides, function(guide) {
            var step = _.first(guide.steps);
            return step && step.type === 'launcher';
        });
        if (launcherGuide && launcherConfig) {
            var launcherStep = _.first(launcherGuide.steps);
            launcherConfig.id = launcherStep.guideId + launcherStep.id;
            _.extend(launcherConfig,
                _.pick(launcherStep, 'contentUrl', 'contentUrlCss', 'contentUrlJs'),
                launcherStep.attributes);
        }
        return launcher;
    }
    
    /**
     * Loads the launcher content, if it is stored externally.
     * @param {Launcher} launcher
     * @see upgradeLauncher
     * @return {Promise} Resolved when the launcher content is loaded
     */
    function loadLauncherContent(launcher) {
        var config = launcher && launcher.data || {};
        if (getPendoConfigValue('preventCodeInjection') === true) {
            return q.resolve();
        }
        if (config.contentUrlJs || config.contentUrl) {
            return ContentVerifier.verify(config).then(function() {
                return ContentLoader.load(config);
            }).then(function(content) {
                config.template = content.content; // for content validation purposes
                return _.extend(launcher, content);
            });
        }
        return q.resolve();
    }
    
    function fixContentHostUrl(contentHostUrl, location) {
        var contentHostSetting = getOption('contentHost');
        if (!contentHostSetting) return contentHostUrl;
        // replace the server-provided contentHostUrl with the agent-configured contentHost
        contentHostUrl = contentHostUrl.replace(/^pendo-static-\d+\.storage\.googleapis\.com$/, contentHostSetting)
            .replace(/^pendo-\w+-static\.storage\.googleapis\.com$/, contentHostSetting)
            .replace(/^cdn\.pendo\.io$/, contentHostSetting);
        // strip the protocol (or leading //), if it was provided in the agent-configured contentHost
        contentHostUrl = contentHostUrl.replace(/^https?:/, '').replace(/^\/\//, '');
        if (/\./.test(contentHostUrl) || /^localhost/.test(contentHostUrl)) {
            // it "looks" like it contains a host already
            return contentHostUrl;
        }
        if (/^\//.test(contentHostUrl)) {
            // it is a host relative path
            return location.host + contentHostUrl;
        }
        // it is just a host
        return contentHostUrl;
    }
    
    function createLauncher(config, isOpen) {
        if (isPreventLauncher) return;
    
        if (config.contentHostUrl) {
            // not actually a url, just hostname. the contentHost config option
            // might just be a path, so we need to fill in the host in that case
            config.contentHostUrl = fixContentHostUrl(config.contentHostUrl, location);
        }
    
        launcherElement = new LauncherElement(config);
        var launcher = Launcher.create(pendo.guideWidget);
    
        if (!_.isFunction(launcher.template)) {
            launcher.template = config.template ? _.template(config.template) : defaultLauncherTemplate;
        }
    
        launcher.render();
        launcher.position(launcherElement.getLauncherTarget());
    
        if (isOpen) {
            launcher.toggle();
        }
    
        return launcher;
    }
    
    var removeLauncher = function() {
        // remove the launcher if it's currently added
        if (launcherTooltipDiv) {
            dom.removeNode(launcherTooltipDiv);
            launcherTooltipDiv = null;
        }
    
        if (launcherElement) {
            launcherElement.dispose();
            launcherElement = null;
        }
    
        if (launcherBadge) {
            launcherBadge.dispose();
            launcherBadge = null;
        }
    };
    
    // THIS is really just the badge icon in the corner
    var showHideLauncher = function() {
        if ((!isLauncherOnElement()) && (doesLauncherHaveGuides() || launcherHasActiveSearch())) {
            showLauncher();
        } else {
            hideLauncher();
        }
    };
    
    var showLauncher = function() {
        launcherBadge && launcherBadge.show();
    };
    var hideLauncher = function() {
        if (!isLauncherOnElement()) {
            collapseLauncherList();
        }
        launcherBadge && launcherBadge.hide();
    };
    
    var isLauncher = function(guide) {
        if (guide && _.isFunction(guide.shouldBeAddedToLauncher)) {
            return guide.shouldBeAddedToLauncher();
        } else {
            return guide && guide.launchMethod && guide.launchMethod.indexOf('launcher') >= 0;
        }
    };
    
    var isLauncherOnElement = function() {
        if (pendo.guideWidget && pendo.guideWidget.data && pendo.guideWidget.data.launchType === 'element') {
            return true;
        } else {
            return false;
        }
    };
    
    /**
     *
     */
    var updateLauncher = function(guides, prefiltered) {
        if (pendo.guideWidget && _.isFunction(pendo.guideWidget.update)) {
            return pendo.guideWidget.update(guides, prefiltered);
        }
    };
    
    var getLauncherContext = function(guides) {
        var metadata = getMetadata();
        if (!_.isObject(metadata)) metadata = prepareOptions();
    
        var context = _.extend({
            'hidePoweredBy': false,
            'guides':        [],
            // the script wrapper in the template assumes there's a guide and step variable on the context
            // this doesn't matter in a "live" launcher scenario, but can be a problem in the guide designer
            'guide':         {},
            'step':          {},
            'metadata':      escapeStringsInObject(metadata)
        }, pendo.guideWidget);
        context.data = _.extend({}, context.data);
        if (guides) {
            context.guides = guides;
        }
    
        return context;
    };
    
    function updateLauncherContent(guides) {
        var launcher = pendo.guideWidget;
        var templateFn = launcher.template || defaultLauncherTemplate;
        var context = getLauncherContext(guides);
        var newContent = dom('<div>').html(replaceInlineStyles(templateFn(context)));
        var newListing = newContent.find('._pendo-launcher-guide-listing_');
        var newFooter = newContent.find('._pendo-launcher-footer_').html();
        var newSearchResults = newContent.find('._pendo-launcher-search-results_').html();
        // Only updates the guide listing(s), search results, and footer, everything else in the launcher template is
        // only evaluated when the launcher is first created.
        dom('._pendo-launcher_ ._pendo-launcher-guide-listing_').each(function(oldListing, i) {
            dom(oldListing).html(newListing.eq(i).html());
        });
        dom('._pendo-launcher_ ._pendo-launcher-footer_').html(newFooter);
        dom('._pendo-launcher_ ._pendo-launcher-search-results_').html(newSearchResults);
    }
    
    var buildLauncherItem = function(guide) {
        var guideContainer = document.createElement('div');
        dom(guideContainer).addClass('_pendo-launcher-item_');
        dom(guideContainer).attr('id', 'launcher-' + guide.id);
        var guideLink = document.createElement('a');
        guideLink.href = '#';
        guideLink.innerHTML = guide.name;
        guideContainer.appendChild(guideLink);
    
        return guideContainer;
    };
    
    // FIXME - get rid of this, the selection module still uses it, maybe just move it there?
    var addGuideToLauncher = _.compose(
        showHideLauncher,
        function(guide, idx) {
            if (!isLauncher(guide)) return;
    
            var guideListDiv = Sizzle('._pendo-launcher_ ._pendo-launcher-guide-listing_')[0];
            if (!guideListDiv) {
                return;
            }
    
            var guideContainer;
    
            var check = Sizzle('#launcher-' + guide.id);
            if (check.length) {
                guideContainer = check[0];
            } else {
                guideContainer = buildLauncherItem(guide);
            }
    
            check = check.length > 0;
    
            if (_.isNumber(idx)) {
                // get element at idx
                var items = Sizzle('._pendo-launcher-item_');
    
                if (items[idx]) {
                    if (guideContainer.id != items[idx].id) {
                        guideListDiv.insertBefore(guideContainer, items[idx]);
                    }
                } else {
                    guideListDiv.appendChild(guideContainer);
                }
            } else {
                guideListDiv.appendChild(guideContainer);
            }
        }
    );
    
    var isLauncherAvailable = function() {
        return !!launcherTooltipDiv && !isPreventLauncher;
    };
    
    var isLauncherVisible = function() {
        var launcher = dom(launcherTooltipDiv);
        return launcher.hasClass(launcherActiveClass);
    };
    
    var doesLauncherHaveGuides = function() {
        return Sizzle('._pendo-launcher-item_').length > 0;
    };
    
    var collapseLauncherList = function() {
        var launcher = dom(launcherTooltipDiv);
        if (launcher.hasClass(launcherActiveClass)) {
            launcher.removeClass(launcherActiveClass);
            launcherBadge && launcherBadge.setActive(false);
        }
    };
    
    var expandLauncherList = function() {
        var launcher = dom(launcherTooltipDiv);
        if (!launcher.hasClass(launcherActiveClass)) {
            launcher.addClass(launcherActiveClass);
            launcherBadge && launcherBadge.setActive(true);
        }
    };
    
    // This is for the List toggling
    var toggleLauncher = function() {
        if (isLauncherAvailable()) {
            if (isLauncherVisible()) {
                collapseLauncherList();
            } else {
                expandLauncherList();
            }
        }
    };
    
    function removeCountBadge() {
        dom('._pendo-launcher-whatsnew-count_').remove();
    }
    
    var initLauncher = function() {
        try {
            var guideWidget = pendo.guideWidget || {},
                config = guideWidget.data || {},
                device = config.device || { 'desktop': true, 'mobile': false, 'iframe': false };
    
            removeLauncher();
    
            if (!isMobileUserAgent() && !device.desktop) {
                return;
            }
    
            if (isMobileUserAgent() && !device.mobile) {
                return;
            }
    
            if (detectMaster() && !device.iframe) {
                return;
            }
    
            if (guideWidget.enabled) {
                createLauncher(config);
                hideLauncher();
    
                if (shouldSwitchToOBM()) {
                    startOBM();
                }
            }
        } catch (e) {
            writeException(e, 'ERROR while initializing launcher');
        }
    };
    
    function base32Encode(uint8array) {
        var alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    
        var length = uint8array.length;
    
        var bits = 0;
        var value = 0;
        var output = '';
    
        for (var i = 0; i < length; i++) {
            value = (value << 8) | uint8array[i];
            bits += 8;
    
            while (bits >= 5) {
                output += alphabet[(value >>> (bits - 5)) & 31];
                bits -= 5;
            }
        }
    
        if (bits > 0) {
            output += alphabet[(value << (5 - bits)) & 31];
        }
    
        return output;
    }
    
    var JWT = (function() {
        function parseJwt(token) {
            try {
                return JSON.parse(atob(token.split('.')[1]));
            } catch (e) {
                return null;
            }
        }
    
        function isJwt(jwt) {
            if (!_.isString(jwt)) {
                return false;
            }
            return /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/.test(jwt);
        }
    
        function canInitializeJwt(options, logPrefix) {
            logPrefix = logPrefix ? logPrefix + ': ' : '';
    
            if(!options.jwt && !options.signingKeyName) {
                debug(logPrefix + 'Missing jwt and signingKeyName.');
                return false;
            }
    
            if(options.jwt && !options.signingKeyName) {
                debug(logPrefix + 'The jwt is supplied but missing signingKeyName.');
                return false;
            }
    
            if(options.signingKeyName && !options.jwt) {
                debug(logPrefix + 'The signingKeyName is supplied but missing jwt.');
                return false;
            }
    
            if(!isJwt(options.jwt)) {
                debug(logPrefix + 'The jwt is invalid.');
                return false;
            }
    
            return true;
        }
    
        function getJwtOptions(options, logPrefix) {
            logPrefix = logPrefix || '';
    
            if(!getPendoConfigValue('enableSignedMetadata')) return false;
    
            var canUseJwt = canInitializeJwt(options, logPrefix);
    
            if(getPendoConfigValue('requireSignedMetadata') && !canUseJwt) {
                debug('Pendo will not ' + logPrefix + '.');
                return false;
            }
    
            if(!canUseJwt) {
                debug('JWT is enabled but not being used, falling back to unsigned metadata.');
            } else {
                return parseJwt(options.jwt);
            }
        }
    
        return {
            'getJwtOptions': getJwtOptions
        };
    })();
    
    /** @license zlib.js 2012 - imaya [ https://github.com/imaya/zlib.js ] The MIT License */(function() {'use strict';var n=void 0,w=!0,aa=this;function ba(f,d){var c=f.split("."),e=aa;!(c[0]in e)&&e.execScript&&e.execScript("var "+c[0]);for(var b;c.length&&(b=c.shift());)!c.length&&d!==n?e[b]=d:e=e[b]?e[b]:e[b]={}};var C="undefined"!==typeof Uint8Array&&"undefined"!==typeof Uint16Array&&"undefined"!==typeof Uint32Array;function K(f,d){this.index="number"===typeof d?d:0;this.e=0;this.buffer=f instanceof(C?Uint8Array:Array)?f:new (C?Uint8Array:Array)(32768);if(2*this.buffer.length<=this.index)throw Error("invalid index");this.buffer.length<=this.index&&ca(this)}function ca(f){var d=f.buffer,c,e=d.length,b=new (C?Uint8Array:Array)(e<<1);if(C)b.set(d);else for(c=0;c<e;++c)b[c]=d[c];return f.buffer=b}
    K.prototype.b=function(f,d,c){var e=this.buffer,b=this.index,a=this.e,g=e[b],m;c&&1<d&&(f=8<d?(L[f&255]<<24|L[f>>>8&255]<<16|L[f>>>16&255]<<8|L[f>>>24&255])>>32-d:L[f]>>8-d);if(8>d+a)g=g<<d|f,a+=d;else for(m=0;m<d;++m)g=g<<1|f>>d-m-1&1,8===++a&&(a=0,e[b++]=L[g],g=0,b===e.length&&(e=ca(this)));e[b]=g;this.buffer=e;this.e=a;this.index=b};K.prototype.finish=function(){var f=this.buffer,d=this.index,c;0<this.e&&(f[d]<<=8-this.e,f[d]=L[f[d]],d++);C?c=f.subarray(0,d):(f.length=d,c=f);return c};
    var da=new (C?Uint8Array:Array)(256),M;for(M=0;256>M;++M){for(var N=M,S=N,ea=7,N=N>>>1;N;N>>>=1)S<<=1,S|=N&1,--ea;da[M]=(S<<ea&255)>>>0}var L=da;function ia(f){this.buffer=new (C?Uint16Array:Array)(2*f);this.length=0}ia.prototype.getParent=function(f){return 2*((f-2)/4|0)};ia.prototype.push=function(f,d){var c,e,b=this.buffer,a;c=this.length;b[this.length++]=d;for(b[this.length++]=f;0<c;)if(e=this.getParent(c),b[c]>b[e])a=b[c],b[c]=b[e],b[e]=a,a=b[c+1],b[c+1]=b[e+1],b[e+1]=a,c=e;else break;return this.length};
    ia.prototype.pop=function(){var f,d,c=this.buffer,e,b,a;d=c[0];f=c[1];this.length-=2;c[0]=c[this.length];c[1]=c[this.length+1];for(a=0;;){b=2*a+2;if(b>=this.length)break;b+2<this.length&&c[b+2]>c[b]&&(b+=2);if(c[b]>c[a])e=c[a],c[a]=c[b],c[b]=e,e=c[a+1],c[a+1]=c[b+1],c[b+1]=e;else break;a=b}return{index:f,value:d,length:this.length}};function ka(f,d){this.d=la;this.i=0;this.input=C&&f instanceof Array?new Uint8Array(f):f;this.c=0;d&&(d.lazy&&(this.i=d.lazy),"number"===typeof d.compressionType&&(this.d=d.compressionType),d.outputBuffer&&(this.a=C&&d.outputBuffer instanceof Array?new Uint8Array(d.outputBuffer):d.outputBuffer),"number"===typeof d.outputIndex&&(this.c=d.outputIndex));this.a||(this.a=new (C?Uint8Array:Array)(32768))}var la=2,na={NONE:0,h:1,g:la,n:3},T=[],U;
    for(U=0;288>U;U++)switch(w){case 143>=U:T.push([U+48,8]);break;case 255>=U:T.push([U-144+400,9]);break;case 279>=U:T.push([U-256+0,7]);break;case 287>=U:T.push([U-280+192,8]);break;default:throw"invalid literal: "+U;}
    ka.prototype.f=function(){var f,d,c,e,b=this.input;switch(this.d){case 0:c=0;for(e=b.length;c<e;){d=C?b.subarray(c,c+65535):b.slice(c,c+65535);c+=d.length;var a=d,g=c===e,m=n,k=n,p=n,t=n,u=n,l=this.a,h=this.c;if(C){for(l=new Uint8Array(this.a.buffer);l.length<=h+a.length+5;)l=new Uint8Array(l.length<<1);l.set(this.a)}m=g?1:0;l[h++]=m|0;k=a.length;p=~k+65536&65535;l[h++]=k&255;l[h++]=k>>>8&255;l[h++]=p&255;l[h++]=p>>>8&255;if(C)l.set(a,h),h+=a.length,l=l.subarray(0,h);else{t=0;for(u=a.length;t<u;++t)l[h++]=
    a[t];l.length=h}this.c=h;this.a=l}break;case 1:var q=new K(C?new Uint8Array(this.a.buffer):this.a,this.c);q.b(1,1,w);q.b(1,2,w);var s=oa(this,b),x,fa,z;x=0;for(fa=s.length;x<fa;x++)if(z=s[x],K.prototype.b.apply(q,T[z]),256<z)q.b(s[++x],s[++x],w),q.b(s[++x],5),q.b(s[++x],s[++x],w);else if(256===z)break;this.a=q.finish();this.c=this.a.length;break;case la:var B=new K(C?new Uint8Array(this.a.buffer):this.a,this.c),ta,J,O,P,Q,La=[16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15],X,ua,Y,va,ga,ja=Array(19),
    wa,R,ha,y,xa;ta=la;B.b(1,1,w);B.b(ta,2,w);J=oa(this,b);X=pa(this.m,15);ua=qa(X);Y=pa(this.l,7);va=qa(Y);for(O=286;257<O&&0===X[O-1];O--);for(P=30;1<P&&0===Y[P-1];P--);var ya=O,za=P,F=new (C?Uint32Array:Array)(ya+za),r,G,v,Z,E=new (C?Uint32Array:Array)(316),D,A,H=new (C?Uint8Array:Array)(19);for(r=G=0;r<ya;r++)F[G++]=X[r];for(r=0;r<za;r++)F[G++]=Y[r];if(!C){r=0;for(Z=H.length;r<Z;++r)H[r]=0}r=D=0;for(Z=F.length;r<Z;r+=G){for(G=1;r+G<Z&&F[r+G]===F[r];++G);v=G;if(0===F[r])if(3>v)for(;0<v--;)E[D++]=0,
    H[0]++;else for(;0<v;)A=138>v?v:138,A>v-3&&A<v&&(A=v-3),10>=A?(E[D++]=17,E[D++]=A-3,H[17]++):(E[D++]=18,E[D++]=A-11,H[18]++),v-=A;else if(E[D++]=F[r],H[F[r]]++,v--,3>v)for(;0<v--;)E[D++]=F[r],H[F[r]]++;else for(;0<v;)A=6>v?v:6,A>v-3&&A<v&&(A=v-3),E[D++]=16,E[D++]=A-3,H[16]++,v-=A}f=C?E.subarray(0,D):E.slice(0,D);ga=pa(H,7);for(y=0;19>y;y++)ja[y]=ga[La[y]];for(Q=19;4<Q&&0===ja[Q-1];Q--);wa=qa(ga);B.b(O-257,5,w);B.b(P-1,5,w);B.b(Q-4,4,w);for(y=0;y<Q;y++)B.b(ja[y],3,w);y=0;for(xa=f.length;y<xa;y++)if(R=
    f[y],B.b(wa[R],ga[R],w),16<=R){y++;switch(R){case 16:ha=2;break;case 17:ha=3;break;case 18:ha=7;break;default:throw"invalid code: "+R;}B.b(f[y],ha,w)}var Aa=[ua,X],Ba=[va,Y],I,Ca,$,ma,Da,Ea,Fa,Ga;Da=Aa[0];Ea=Aa[1];Fa=Ba[0];Ga=Ba[1];I=0;for(Ca=J.length;I<Ca;++I)if($=J[I],B.b(Da[$],Ea[$],w),256<$)B.b(J[++I],J[++I],w),ma=J[++I],B.b(Fa[ma],Ga[ma],w),B.b(J[++I],J[++I],w);else if(256===$)break;this.a=B.finish();this.c=this.a.length;break;default:throw"invalid compression type";}return this.a};
    function ra(f,d){this.length=f;this.k=d}
    var sa=function(){function f(b){switch(w){case 3===b:return[257,b-3,0];case 4===b:return[258,b-4,0];case 5===b:return[259,b-5,0];case 6===b:return[260,b-6,0];case 7===b:return[261,b-7,0];case 8===b:return[262,b-8,0];case 9===b:return[263,b-9,0];case 10===b:return[264,b-10,0];case 12>=b:return[265,b-11,1];case 14>=b:return[266,b-13,1];case 16>=b:return[267,b-15,1];case 18>=b:return[268,b-17,1];case 22>=b:return[269,b-19,2];case 26>=b:return[270,b-23,2];case 30>=b:return[271,b-27,2];case 34>=b:return[272,
    b-31,2];case 42>=b:return[273,b-35,3];case 50>=b:return[274,b-43,3];case 58>=b:return[275,b-51,3];case 66>=b:return[276,b-59,3];case 82>=b:return[277,b-67,4];case 98>=b:return[278,b-83,4];case 114>=b:return[279,b-99,4];case 130>=b:return[280,b-115,4];case 162>=b:return[281,b-131,5];case 194>=b:return[282,b-163,5];case 226>=b:return[283,b-195,5];case 257>=b:return[284,b-227,5];case 258===b:return[285,b-258,0];default:throw"invalid length: "+b;}}var d=[],c,e;for(c=3;258>=c;c++)e=f(c),d[c]=e[2]<<24|
    e[1]<<16|e[0];return d}(),Ha=C?new Uint32Array(sa):sa;
    function oa(f,d){function c(b,c){var a=b.k,d=[],e=0,f;f=Ha[b.length];d[e++]=f&65535;d[e++]=f>>16&255;d[e++]=f>>24;var g;switch(w){case 1===a:g=[0,a-1,0];break;case 2===a:g=[1,a-2,0];break;case 3===a:g=[2,a-3,0];break;case 4===a:g=[3,a-4,0];break;case 6>=a:g=[4,a-5,1];break;case 8>=a:g=[5,a-7,1];break;case 12>=a:g=[6,a-9,2];break;case 16>=a:g=[7,a-13,2];break;case 24>=a:g=[8,a-17,3];break;case 32>=a:g=[9,a-25,3];break;case 48>=a:g=[10,a-33,4];break;case 64>=a:g=[11,a-49,4];break;case 96>=a:g=[12,a-
    65,5];break;case 128>=a:g=[13,a-97,5];break;case 192>=a:g=[14,a-129,6];break;case 256>=a:g=[15,a-193,6];break;case 384>=a:g=[16,a-257,7];break;case 512>=a:g=[17,a-385,7];break;case 768>=a:g=[18,a-513,8];break;case 1024>=a:g=[19,a-769,8];break;case 1536>=a:g=[20,a-1025,9];break;case 2048>=a:g=[21,a-1537,9];break;case 3072>=a:g=[22,a-2049,10];break;case 4096>=a:g=[23,a-3073,10];break;case 6144>=a:g=[24,a-4097,11];break;case 8192>=a:g=[25,a-6145,11];break;case 12288>=a:g=[26,a-8193,12];break;case 16384>=
    a:g=[27,a-12289,12];break;case 24576>=a:g=[28,a-16385,13];break;case 32768>=a:g=[29,a-24577,13];break;default:throw"invalid distance";}f=g;d[e++]=f[0];d[e++]=f[1];d[e++]=f[2];var k,m;k=0;for(m=d.length;k<m;++k)l[h++]=d[k];s[d[0]]++;x[d[3]]++;q=b.length+c-1;u=null}var e,b,a,g,m,k={},p,t,u,l=C?new Uint16Array(2*d.length):[],h=0,q=0,s=new (C?Uint32Array:Array)(286),x=new (C?Uint32Array:Array)(30),fa=f.i,z;if(!C){for(a=0;285>=a;)s[a++]=0;for(a=0;29>=a;)x[a++]=0}s[256]=1;e=0;for(b=d.length;e<b;++e){a=
    m=0;for(g=3;a<g&&e+a!==b;++a)m=m<<8|d[e+a];k[m]===n&&(k[m]=[]);p=k[m];if(!(0<q--)){for(;0<p.length&&32768<e-p[0];)p.shift();if(e+3>=b){u&&c(u,-1);a=0;for(g=b-e;a<g;++a)z=d[e+a],l[h++]=z,++s[z];break}0<p.length?(t=Ia(d,e,p),u?u.length<t.length?(z=d[e-1],l[h++]=z,++s[z],c(t,0)):c(u,-1):t.length<fa?u=t:c(t,0)):u?c(u,-1):(z=d[e],l[h++]=z,++s[z])}p.push(e)}l[h++]=256;s[256]++;f.m=s;f.l=x;return C?l.subarray(0,h):l}
    function Ia(f,d,c){var e,b,a=0,g,m,k,p,t=f.length;m=0;p=c.length;a:for(;m<p;m++){e=c[p-m-1];g=3;if(3<a){for(k=a;3<k;k--)if(f[e+k-1]!==f[d+k-1])continue a;g=a}for(;258>g&&d+g<t&&f[e+g]===f[d+g];)++g;g>a&&(b=e,a=g);if(258===g)break}return new ra(a,d-b)}
    function pa(f,d){var c=f.length,e=new ia(572),b=new (C?Uint8Array:Array)(c),a,g,m,k,p;if(!C)for(k=0;k<c;k++)b[k]=0;for(k=0;k<c;++k)0<f[k]&&e.push(k,f[k]);a=Array(e.length/2);g=new (C?Uint32Array:Array)(e.length/2);if(1===a.length)return b[e.pop().index]=1,b;k=0;for(p=e.length/2;k<p;++k)a[k]=e.pop(),g[k]=a[k].value;m=Ja(g,g.length,d);k=0;for(p=a.length;k<p;++k)b[a[k].index]=m[k];return b}
    function Ja(f,d,c){function e(a){var b=k[a][p[a]];b===d?(e(a+1),e(a+1)):--g[b];++p[a]}var b=new (C?Uint16Array:Array)(c),a=new (C?Uint8Array:Array)(c),g=new (C?Uint8Array:Array)(d),m=Array(c),k=Array(c),p=Array(c),t=(1<<c)-d,u=1<<c-1,l,h,q,s,x;b[c-1]=d;for(h=0;h<c;++h)t<u?a[h]=0:(a[h]=1,t-=u),t<<=1,b[c-2-h]=(b[c-1-h]/2|0)+d;b[0]=a[0];m[0]=Array(b[0]);k[0]=Array(b[0]);for(h=1;h<c;++h)b[h]>2*b[h-1]+a[h]&&(b[h]=2*b[h-1]+a[h]),m[h]=Array(b[h]),k[h]=Array(b[h]);for(l=0;l<d;++l)g[l]=c;for(q=0;q<b[c-1];++q)m[c-
    1][q]=f[q],k[c-1][q]=q;for(l=0;l<c;++l)p[l]=0;1===a[c-1]&&(--g[0],++p[c-1]);for(h=c-2;0<=h;--h){s=l=0;x=p[h+1];for(q=0;q<b[h];q++)s=m[h+1][x]+m[h+1][x+1],s>f[l]?(m[h][q]=s,k[h][q]=d,x+=2):(m[h][q]=f[l],k[h][q]=l,++l);p[h]=0;1===a[h]&&e(h)}return g}
    function qa(f){var d=new (C?Uint16Array:Array)(f.length),c=[],e=[],b=0,a,g,m,k;a=0;for(g=f.length;a<g;a++)c[f[a]]=(c[f[a]]|0)+1;a=1;for(g=16;a<=g;a++)e[a]=b,b+=c[a]|0,b<<=1;a=0;for(g=f.length;a<g;a++){b=e[f[a]];e[f[a]]+=1;m=d[a]=0;for(k=f[a];m<k;m++)d[a]=d[a]<<1|b&1,b>>>=1}return d};function Ka(f,d){this.input=f;this.a=new (C?Uint8Array:Array)(32768);this.d=V.g;var c={},e;if((d||!(d={}))&&"number"===typeof d.compressionType)this.d=d.compressionType;for(e in d)c[e]=d[e];c.outputBuffer=this.a;this.j=new ka(this.input,c)}var V=na;
    Ka.prototype.f=function(){var f,d,c,e,b,a,g=0;a=this.a;switch(8){case 8:f=Math.LOG2E*Math.log(32768)-8;break;default:throw Error("invalid compression method");}d=f<<4|8;a[g++]=d;switch(8){case 8:switch(this.d){case V.NONE:e=0;break;case V.h:e=1;break;case V.g:e=2;break;default:throw Error("unsupported compression type");}break;default:throw Error("invalid compression method");}c=e<<6|0;a[g++]=c|31-(256*d+c)%31;var m=this.input;if("string"===typeof m){var k=m.split(""),p,t;p=0;for(t=k.length;p<t;p++)k[p]=
    (k[p].charCodeAt(0)&255)>>>0;m=k}for(var u=1,l=0,h=m.length,q,s=0;0<h;){q=1024<h?1024:h;h-=q;do u+=m[s++],l+=u;while(--q);u%=65521;l%=65521}b=(l<<16|u)>>>0;this.j.c=g;a=this.j.f();g=a.length;C&&(a=new Uint8Array(a.buffer),a.length<=g+4&&(this.a=new Uint8Array(a.length+4),this.a.set(a),a=this.a),a=a.subarray(0,g+4));a[g++]=b>>24&255;a[g++]=b>>16&255;a[g++]=b>>8&255;a[g++]=b&255;return a};ba("Zlib.Deflate",Ka);ba("Zlib.Deflate.compress",function(f,d){return(new Ka(f,d)).f()});ba("Zlib.Deflate.prototype.compress",Ka.prototype.f);var Ma={NONE:V.NONE,FIXED:V.h,DYNAMIC:V.g},Na,Oa,W,Pa;if(Object.keys)Na=Object.keys(Ma);else for(Oa in Na=[],W=0,Ma)Na[W++]=Oa;W=0;for(Pa=Na.length;W<Pa;++W)Oa=Na[W],ba("Zlib.Deflate.CompressionType."+Oa,Ma[Oa]);}).call(pendo);
    
    /** @license zlib.js 2012 - imaya [ https://github.com/imaya/zlib.js ] The MIT License */(function() {'use strict';var f=this;function h(c,a){var b=c.split("."),e=f;!(b[0]in e)&&e.execScript&&e.execScript("var "+b[0]);for(var d;b.length&&(d=b.shift());)!b.length&&void 0!==a?e[d]=a:e=e[d]?e[d]:e[d]={}};var l={c:function(c,a,b){return l.update(c,0,a,b)},update:function(c,a,b,e){var d=l.a,g="number"===typeof b?b:b=0,k="number"===typeof e?e:c.length;a^=4294967295;for(g=k&7;g--;++b)a=a>>>8^d[(a^c[b])&255];for(g=k>>3;g--;b+=8)a=a>>>8^d[(a^c[b])&255],a=a>>>8^d[(a^c[b+1])&255],a=a>>>8^d[(a^c[b+2])&255],a=a>>>8^d[(a^c[b+3])&255],a=a>>>8^d[(a^c[b+4])&255],a=a>>>8^d[(a^c[b+5])&255],a=a>>>8^d[(a^c[b+6])&255],a=a>>>8^d[(a^c[b+7])&255];return(a^4294967295)>>>0},d:function(c,a){return(l.a[(c^a)&255]^c>>>8)>>>
    0},b:[0,1996959894,3993919788,2567524794,124634137,1886057615,3915621685,2657392035,249268274,2044508324,3772115230,2547177864,162941995,2125561021,3887607047,2428444049,498536548,1789927666,4089016648,2227061214,450548861,1843258603,4107580753,2211677639,325883990,1684777152,4251122042,2321926636,335633487,1661365465,4195302755,2366115317,997073096,1281953886,3579855332,2724688242,1006888145,1258607687,3524101629,2768942443,901097722,1119000684,3686517206,2898065728,853044451,1172266101,3705015759,
    2882616665,651767980,1373503546,3369554304,3218104598,565507253,1454621731,3485111705,3099436303,671266974,1594198024,3322730930,2970347812,795835527,1483230225,3244367275,3060149565,1994146192,31158534,2563907772,4023717930,1907459465,112637215,2680153253,3904427059,2013776290,251722036,2517215374,3775830040,2137656763,141376813,2439277719,3865271297,1802195444,476864866,2238001368,4066508878,1812370925,453092731,2181625025,4111451223,1706088902,314042704,2344532202,4240017532,1658658271,366619977,
    2362670323,4224994405,1303535960,984961486,2747007092,3569037538,1256170817,1037604311,2765210733,3554079995,1131014506,879679996,2909243462,3663771856,1141124467,855842277,2852801631,3708648649,1342533948,654459306,3188396048,3373015174,1466479909,544179635,3110523913,3462522015,1591671054,702138776,2966460450,3352799412,1504918807,783551873,3082640443,3233442989,3988292384,2596254646,62317068,1957810842,3939845945,2647816111,81470997,1943803523,3814918930,2489596804,225274430,2053790376,3826175755,
    2466906013,167816743,2097651377,4027552580,2265490386,503444072,1762050814,4150417245,2154129355,426522225,1852507879,4275313526,2312317920,282753626,1742555852,4189708143,2394877945,397917763,1622183637,3604390888,2714866558,953729732,1340076626,3518719985,2797360999,1068828381,1219638859,3624741850,2936675148,906185462,1090812512,3747672003,2825379669,829329135,1181335161,3412177804,3160834842,628085408,1382605366,3423369109,3138078467,570562233,1426400815,3317316542,2998733608,733239954,1555261956,
    3268935591,3050360625,752459403,1541320221,2607071920,3965973030,1969922972,40735498,2617837225,3943577151,1913087877,83908371,2512341634,3803740692,2075208622,213261112,2463272603,3855990285,2094854071,198958881,2262029012,4057260610,1759359992,534414190,2176718541,4139329115,1873836001,414664567,2282248934,4279200368,1711684554,285281116,2405801727,4167216745,1634467795,376229701,2685067896,3608007406,1308918612,956543938,2808555105,3495958263,1231636301,1047427035,2932959818,3654703836,1088359270,
    936918E3,2847714899,3736837829,1202900863,817233897,3183342108,3401237130,1404277552,615818150,3134207493,3453421203,1423857449,601450431,3009837614,3294710456,1567103746,711928724,3020668471,3272380065,1510334235,755167117]};l.a="undefined"!==typeof Uint8Array&&"undefined"!==typeof Uint16Array&&"undefined"!==typeof Uint32Array?new Uint32Array(l.b):l.b;h("Zlib.CRC32",l);h("Zlib.CRC32.calc",l.c);h("Zlib.CRC32.update",l.update);}).call(pendo);
    
    /*!
        json2.js
        2015-05-03
    
        Public Domain.
    
        NO WARRANTY EXPRESSED OR IMPLIED. USE AT YOUR OWN RISK.
    
        See http://www.JSON.org/js.html
    */
    var JSON=window.JSON;if(!JSON){JSON={}}(function(){function f(n){return n<10?"0"+n:n}if(typeof Date.prototype.toJSON!=="function"){Date.prototype.toJSON=function(key){return isFinite(this.valueOf())?this.getUTCFullYear()+"-"+f(this.getUTCMonth()+1)+"-"+f(this.getUTCDate())+"T"+f(this.getUTCHours())+":"+f(this.getUTCMinutes())+":"+f(this.getUTCSeconds())+"Z":null};String.prototype.toJSON=Number.prototype.toJSON=Boolean.prototype.toJSON=function(key){return this.valueOf()}}var cx=/[\u0000\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g,escapable=/[\\\"\x00-\x1f\x7f-\x9f\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g,gap,indent,meta={"\b":"\\b","\t":"\\t","\n":"\\n","\f":"\\f","\r":"\\r",'"':'\\"',"\\":"\\\\"},rep;function quote(string){escapable.lastIndex=0;return escapable.test(string)?'"'+string.replace(escapable,function(a){var c=meta[a];return typeof c==="string"?c:"\\u"+("0000"+a.charCodeAt(0).toString(16)).slice(-4)})+'"':'"'+string+'"'}function str(key,holder){var i,k,v,length,mind=gap,partial,value=holder[key];if(value&&typeof value==="object"&&typeof value.toJSON==="function"){value=value.toJSON(key)}if(typeof rep==="function"){value=rep.call(holder,key,value)}switch(typeof value){case"string":return quote(value);case"number":return isFinite(value)?String(value):"null";case"boolean":case"null":return String(value);case"object":if(!value){return"null"}gap+=indent;partial=[];if(Object.prototype.toString.apply(value)==="[object Array]"){length=value.length;for(i=0;i<length;i+=1){partial[i]=str(i,value)||"null"}v=partial.length===0?"[]":gap?"[\n"+gap+partial.join(",\n"+gap)+"\n"+mind+"]":"["+partial.join(",")+"]";gap=mind;return v}if(rep&&typeof rep==="object"){length=rep.length;for(i=0;i<length;i+=1){if(typeof rep[i]==="string"){k=rep[i];v=str(k,value);if(v){partial.push(quote(k)+(gap?": ":":")+v)}}}}else{for(k in value){if(Object.prototype.hasOwnProperty.call(value,k)){v=str(k,value);if(v){partial.push(quote(k)+(gap?": ":":")+v)}}}}v=partial.length===0?"{}":gap?"{\n"+gap+partial.join(",\n"+gap)+"\n"+mind+"}":"{"+partial.join(",")+"}";gap=mind;return v}}if(typeof JSON.stringify!=="function"){JSON.stringify=function(value,replacer,space){var i;gap="";indent="";if(typeof space==="number"){for(i=0;i<space;i+=1){indent+=" "}}else{if(typeof space==="string"){indent=space}}rep=replacer;if(replacer&&typeof replacer!=="function"&&(typeof replacer!=="object"||typeof replacer.length!=="number")){throw new Error("JSON.stringify")}return str("",{"":value})}}if(typeof JSON.parse!=="function"){JSON.parse=function(text,reviver){var j;function walk(holder,key){var k,v,value=holder[key];if(value&&typeof value==="object"){for(k in value){if(Object.prototype.hasOwnProperty.call(value,k)){v=walk(value,k);if(v!==undefined){value[k]=v}else{delete value[k]}}}}return reviver.call(holder,key,value)}text=String(text);cx.lastIndex=0;if(cx.test(text)){text=text.replace(cx,function(a){return"\\u"+("0000"+a.charCodeAt(0).toString(16)).slice(-4)})}if(/^[\],:{}\s]*$/.test(text.replace(/\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4})/g,"@").replace(/"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g,"]").replace(/(?:^|:|,)(?:\s*\[)+/g,""))){j=eval("("+text+")");return typeof reviver==="function"?walk({"":j},""):j}throw new SyntaxError("JSON.parse")}}}());
    
    /*!
        cycle.js
        2013-02-19
    
        Public Domain.
    
        NO WARRANTY EXPRESSED OR IMPLIED. USE AT YOUR OWN RISK.
    
        This code should be minified before deployment.
        See http://javascript.crockford.com/jsmin.html
    
        USE YOUR OWN COPY. IT IS EXTREMELY UNWISE TO LOAD CODE FROM SERVERS YOU DO
        NOT CONTROL.
    */
    
    /*jslint evil: true, regexp: true */
    
    /*members $ref, apply, call, decycle, hasOwnProperty, length, prototype, push,
        retrocycle, stringify, test, toString
    */
    
    if (typeof JSON.decycle !== 'function') {
    (function(){
    
        /**
         * Allows stringifing DOM elements.
         *
         * This is done in hope to identify the node when dumping.
         *
         * @param {Element} node DOM Node (works best for DOM Elements).
         * @returns {String}
         */
        function stringifyNode(node) {
            var text = "";
            switch (node.nodeType) {
                case node.ELEMENT_NODE:
                    text = node.nodeName.toLowerCase();
                    if (node.id.length) {
                        text += '#' + node.id;
                    }
                    else {
                        if (node.className.length) {
                            text += '.' + node.className.replace(/ /, '.');
                        }
                        if ('textContent' in node) {
                            text += '{textContent:'
                                    + (node.textContent.length < 20 ? node.textContent : node.textContent.substr(0, 20) + '...')
                                + '}'
                            ;
                        }
                    }
                break;
                // info on values: http://www.w3.org/TR/DOM-Level-2-Core/core.html#ID-1841493061
                default:
                    text = node.nodeName;
                    if (node.nodeValue !== null) {
                        text += '{value:'
                                    + (node.nodeValue.length < 20 ? node.nodeValue : node.nodeValue.substr(0, 20) + '...')
                            + '}'
                        ;
                    }
                break;
            }
            return text;
        }
    
        JSON.decycle = function decycle(object, stringifyNodes) {
    // Make a deep copy of an object or array, assuring that there is at most
    // one instance of each object or array in the resulting structure. The
    // duplicate references (which might be forming cycles) are replaced with
    // an object of the form
    //      {$ref: PATH}
    // where the PATH is a JSONPath string that locates the first occurance.
    // So,
    //      var a = [];
    //      a[0] = a;
    //      return JSON.stringify(JSON.decycle(a));
    // produces the string '[{"$ref":"$"}]'.
    
    // NOTE! If your object contains DOM Nodes you might want to use `stringifyNodes` option
    // This will dump e.g. `div` with id="some-id" to string: `div#some-id`.
    // You will avoid some problems, but you won't to be able to fully retro-cycle.
    // To dump almost any variable use: `alert(JSON.stringify(JSON.decycle(variable, true)));`
    
    // JSONPath is used to locate the unique object. $ indicates the top level of
    // the object or array. [NUMBER] or [STRING] indicates a child member or
    // property.
    
            var objects = [],   // Keep a reference to each unique object or array
                stringifyNodes = typeof(stringifyNodes) === 'undefined' ? false : stringifyNodes,
                paths = [];     // Keep the path to each unique object or array
    
            return (function derez(value, path) {
    
    // The derez recurses through the object, producing the deep copy.
    
                var i,          // The loop counter
                    name,       // Property name
                    nu;         // The new object or array
    
    // if we have a DOM Element/Node convert it to textual info.
    
                if (stringifyNodes && typeof value === 'object' && value !== null && 'nodeType' in value) {
                    return stringifyNode(value);
                }
    
    // typeof null === 'object', so go on if this value is really an object but not
    // one of the weird builtin objects.
    
                if (typeof value === 'object' && value !== null &&
                        !(value instanceof Boolean) &&
                        !(value instanceof Date)    &&
                        !(value instanceof Number)  &&
                        !(value instanceof RegExp)  &&
                        !(value instanceof String)) {
    
    // If the value is an object or array, look to see if we have already
    // encountered it. If so, return a $ref/path object. This is a hard way,
    // linear search that will get slower as the number of unique objects grows.
    
                    for (i = 0; i < objects.length; i += 1) {
                        if (objects[i] === value) {
                            return {$ref: paths[i]};
                        }
                    }
    
    // Otherwise, accumulate the unique value and its path.
    
                    objects.push(value);
                    paths.push(path);
    
    // If it is an array, replicate the array.
    
                    if (Object.prototype.toString.apply(value) === '[object Array]') {
                        nu = [];
                        for (i = 0; i < value.length; i += 1) {
                            nu[i] = derez(value[i], path + '[' + i + ']');
                        }
                    } else {
    
    // If it is an object, replicate the object.
    
                        nu = {};
                        for (name in value) {
                            if (Object.prototype.hasOwnProperty.call(value, name)) {
                                nu[name] = derez(value[name],
                                    path + '[' + JSON.stringify(name) + ']');
                            }
                        }
                    }
                    return nu;
                }
                return value;
            }(object, '$'));
        };
    })();
    }
    
    
    if (typeof JSON.retrocycle !== 'function') {
        JSON.retrocycle = function retrocycle($) {
    // Restore an object that was reduced by decycle. Members whose values are
    // objects of the form
    //      {$ref: PATH}
    // are replaced with references to the value found by the PATH. This will
    // restore cycles. The object will be mutated.
    
    // The eval function is used to locate the values described by a PATH. The
    // root object is kept in a $ variable. A regular expression is used to
    // assure that the PATH is extremely well formed. The regexp contains nested
    // * quantifiers. That has been known to have extremely bad performance
    // problems on some browsers for very long strings. A PATH is expected to be
    // reasonably short. A PATH is allowed to belong to a very restricted subset of
    // Goessner's JSONPath.
    
    // So,
    //      var s = '[{"$ref":"$"}]';
    //      return JSON.retrocycle(JSON.parse(s));
    // produces an array containing a single element which is the array itself.
    
            var px =
                /^\$(?:\[(?:\d+|\"(?:[^\\\"\u0000-\u001f]|\\([\\\"\/bfnrt]|u[0-9a-zA-Z]{4}))*\")\])*$/;
    
            (function rez(value) {
    
    // The rez function walks recursively through the object looking for $ref
    // properties. When it finds one that has a value that is a path, then it
    // replaces the $ref object with a reference to the value that is found by
    // the path.
    
                var i, item, name, path;
    
                if (value && typeof value === 'object') {
                    if (Object.prototype.toString.apply(value) === '[object Array]') {
                        for (i = 0; i < value.length; i += 1) {
                            item = value[i];
                            if (item && typeof item === 'object') {
                                path = item.$ref;
                                if (typeof path === 'string' && px.test(path)) {
                                    value[i] = eval(path);
                                } else {
                                    rez(item);
                                }
                            }
                        }
                    } else {
                        for (name in value) {
                            if (typeof value[name] === 'object') {
                                item = value[name];
                                if (item) {
                                    path = item.$ref;
                                    if (typeof path === 'string' && px.test(path)) {
                                        value[name] = eval(path);
                                    } else {
                                        rez(item);
                                    }
                                }
                            }
                        }
                    }
                }
            }($));
            return $;
        };
    }
    
    var memoizedWarnDep = _.memoize(function warnDep(name, nextSteps) {
        name = name || 'Function';
    
        nextSteps = nextSteps
            ? ' and ' + nextSteps
            : '';
    
        var message = name + ' deprecated' + nextSteps;
    
        pendo.log(message);
    
        return message;
    });
    
    /**
     * @param {Function?} fn to deprecate or {_.noop} if omitted
     * @param {string} name of public function being deprecated
     * @param {string} nextSteps conveying level of deprecation
     * @return {Function} suitable for public API
     */
    function deprecateFn(fn, name, nextSteps) {
        return function deprecated() {
            memoizedWarnDep(name, nextSteps);
    
            return (fn || _.noop).apply(null, arguments);
        };
    }
    
    pendo.SHADOW_STYLE = '';//Deprecated
    
    _.extend(pendo, {
    
        '_showElementGuide': deprecateFn(showTooltipGuide, '_showElementGuide', 'is going away'),
    
        'flushNow':        deprecateFn(flushNow, 'pendo.flushNow', 'is going away'),
        'flushEventCache': deprecateFn(null, 'pendo.flushEventCache', 'is gone'),
    
        'HOST':           HOST,
        'MAX_LENGTH':     ENCODED_EVENT_MAX_LENGTH,
        'MAX_NUM_EVENTS': MAX_NUM_EVENTS,
    
        '_createToolTip':          deprecateFn(createTooltipGuide, 'pendo._createToolTip', 'is going away'),
        '_get_tooltip_dimensions': deprecateFn(getTooltipDimensions, 'pendo._get_tooltip_dimensions', 'is going away'),
        '_isOldIE':                deprecateFn(isOldIE, 'pendo._isOldIE', 'is going away'),
    
        '_logMessage':       deprecateFn(writeMessage, 'pendo._logMessage', 'is going away'),
        '_sendEvent':        deprecateFn(null, 'pendo._sendEvent', 'is gone'),
        '_sendGuideEvent':   deprecateFn(writeGuideEvent, 'pendo._sendGuideEvent', 'is going away'),
        '_stopEvents':       locked,
        '_storeInCache':     deprecateFn(null, 'pendo._storeInCache', 'is gone'),
        '_writeEventImgTag': deprecateFn(writeEvent, 'pendo._writeEventImgTag', 'is going away'),
        '_writeImgTag':      deprecateFn(writeImgTag, 'pendo._writeImgTag', 'is going away'),
        'attachEvent':       deprecateFn(attachEvent, 'pendo.attachEvent', 'is going away'),
        'detachEvent':       deprecateFn(detachEvent, 'pendo.detachEvent', 'is going away'),
        'getText':           deprecateFn(getText, 'pendo.getText', 'is going away'),
        'getUA':             deprecateFn(getUA, 'pendo.getUA', 'is going away'),
        'ifDebugThen':       deprecateFn(null, 'pendo.ifDebugThen', 'is gone'),
        'send_event':        deprecateFn(collectEvent, 'pendo.send_event', 'has changed to pendo.cache.createEvent'),
    
        'wire_page': deprecateFn(wirePage, 'pendo.wire_page', 'is going away'),
    
        // and here's where I got lazy / late
    
        'findGuideBy':            findGuideBy,
        'findGuideById':          findGuideById,
        'findStepInGuide':        findStepInGuide,
        '_updateGuideStepStatus': _updateGuideStepStatus,
        '_addCloseButton':        addCloseButton,
        'initialize':             initialize,
    
        'getEventCache':     getGuideEventCache, // this guides event cache.  fuuuu
        'processEventCache': processGuideEventCache, // also guide event related
    
        'isGuideShown':            isGuideShown,
        '_getNextStepInMultistep': getNextStepInMultistep,
        'badgeDiv':                launcherBadge && launcherBadge.element,
        'launcherToolTipDiv':      launcherTooltipDiv, // note the capital 2nd T
    
        'updateOptions': updateOptions,
    
        'createLauncher':      createLauncher,
        'initLauncher':        initLauncher,
        '_addGuideToLauncher': addGuideToLauncher,
    
        'isAnonymousVisitor':   isAnonymousVisitor,
        'DEFAULT_VISITOR_ID':   DEFAULT_VISITOR_ID,
        'shouldIdentityChange': shouldIdentityChange,
        'read':                 agentStorage.read,
        'write':                agentStorage.write,
        '_delete_cookie':       agentStorage.clear,
        '_set_cookie':          setCookie,
        '_get_cookie':          getCookie,
        'get_cookie_key':       getPendoCookieKey,
    
        'ENV':        ENV,
        'eventCache': eventCache,
    
        '_getOpacityStyles': deprecateFn(function() {}, 'pendo._getOpacityStyles', 'is going away'),
        'setStyle':          setStyle,
    
        '_createGuideEvent': createGuideEvent,
        'seenGuide':         seenGuide,
        'dismissedGuide':    dismissedGuide,
        'advancedGuide':     advancedGuide,
        'seenTime':          seenTime,
    
        'placeBadge':             placeBadge,
        'isBadge':                isBadge,
        'showPreview':            deprecateFn(showPreview, 'pendo.showPreview', 'is going away'),
        'removeAllBadges':        removeAllBadges,
        'tellMaster':             tellMaster,
        'DEFAULT_TIMER_LENGTH':   DEFAULT_TIMER_LENGTH,
        'registerMessageHandler': registerMessageHandler,
    
        '_get_offset':             getOffsetPosition,
        '_shouldAutoDisplayGuide': shouldAutoDisplayGuide,
        'removeBadge':             removeBadge,
        '_showLightboxGuide':      showLightboxGuide,
        '_showGuide':              showGuide,
        'getElementForGuideStep':  getElementForGuideStep,
        'isElementVisible':        isElementVisible,
        'getTooltipDivId':         getStepDivId,
        'setupWatchOnTooltip':     setupWatchOnElement,
    
        'detectMaster':   detectMaster,
        'listenToMaster': listenToMaster,
    
        'start':         whenLoadedCall,
        'SEND_INTERVAL': SEND_INTERVAL,
    
        'stageGuideEvent':  stageGuideEvent,
        'startStagedTimer': startStagedTimer,
    
        'isURLValid': isURLValid,
        'getURL':     getURL,
    
        '_get_screen_dim': getScreenDimensions,
        '_isInViewport':   _isInViewport,
        '_getCss3Prop':    _getCss3Prop,
    
        'waitThenStartGuides': waitThenLoop
    });
    
    var debugging = {
        'getEventCache':      function() { return [].concat(eventCache); },
        'getAllGuides':       function() { return [].concat(getActiveGuides()); },
        'getAutoGuides':      function() { return AutoDisplay.sortAndFilter(getActiveGuides(), pendo.autoOrdering); },
        'getBadgeGuides':     function() { return _.filter(getActiveGuides(), isBadge); },
        'getLauncherGuides':  function() { return _.filter(getActiveGuides(), isLauncher); },
        'getEventHistory':    function() { return []; },
        'getOriginalOptions': function() { return originalOptions; },
        'setActiveGuides':    setActiveGuides,
        'getBody':            dom.getBody,
        'isMobileUserAgent':  isMobileUserAgent,
        'areGuidesDelayed':   areGuidesDelayed,
        'getMetadata':        function() {
            // because the function ref changes...
            return getMetadata();
        },
        'isStagingServer': function() {
            if (typeof PendoConfig === 'undefined') return false;
            return shouldLoadStagingAgent(PendoConfig);
        },
        'AutoDisplay': AutoDisplay
    };
    
    function isDebuggingEnabled(asBoolean) {
        asBoolean = asBoolean || false;
        var isEnabled = agentStorage.read('debug-enabled', true) === 'true';
        if (asBoolean)
            {return isEnabled;}
        else
            {return isEnabled ? 'Yes' : 'No';}
    }
    
    function startDebuggingModuleIfEnabled() {
        if (isDebuggingEnabled(true) && !detectMaster()) {
            addDebuggingFunctions();
            pendo.loadResource(getAssetHost() + '/debugger/pendo-client-debugger.js', function() {
                log('Debug module loaded');
            });
        }
    }
    
    function addDebuggingFunctions() {
        pendo.debugging = debugging;
    }
    
    function enableDebugging(andChain) {
        if (isDebuggingEnabled(true)) {
            if (andChain)
                {return debugging;}
            return 'debugging already enabled';
        }
    
        agentStorage.write('debug-enabled', 'true', null, true);
    
    
        startDebuggingModuleIfEnabled();
    
        if (andChain) {
            return debugging;
        }
    
        return 'debugging enabled';
    }
    
    function disableDebugging() {
        if (!isDebuggingEnabled(true))
            {return 'debugging already disabled';}
    
        agentStorage.write('debug-enabled', 'false', null, true);
    
        pendo.debugging = null;
        delete pendo.debugging;
    
        return 'debugging disabled';
    }
    
    function debug(msg) {
        log(msg, 'debug');
    }
    
    _.extend(debug, debugging);
    
    var ExtensionService = {};
    
    (function setupExtensionService(ExtService) {
        var pending = [];
        var extensions = [];
        var uses = {};
    
        pendo.addExtension = function(obj) {
            obj = [].concat(obj);
            var validExtensions = _.filter(obj, validateExtension);
    
            if (!validExtensions.length) {
                return;
            }
            pending = status(pending.concat(validExtensions));
        };
    
        function status(pending) {
            if (!pending.length) {
                return pending;
            }
            var added = _.filter(pending, addExtension);
    
            if (added.length) {
                return status(_.difference(pending, added));
            }
            return pending;
        }
    
        function validateExtension(extension) {
            var requiredKeys = ['name', 'version', 'use', 'type', 'uri'];
            if (!_.every(requiredKeys, _.partial(_.has, extension))) {
                // validation failed, missing one of the required keys
                return false;
            }
    
            var validators = findRegisteredValidators(extension.use);
            return _.every(_.map(validators, function(validator) {
                return validator(extension);
            }));
        }
    
        function findRegisteredHandler(use) {
            return uses[use] ? uses[use].handler || _.identity : null;
        }
    
        function findRegisteredValidators(use) {
            return uses[use] ? uses[use].validators : [];
        }
    
        function addExtension(ext) {
            if (ext.use === 'behavior') {
                var behavior = ext.uri(ExtService, ExtensionAPI);
                if (!behavior) {
                    return false;
                }
    
                extensions.push(ext);
                return true;
            }
    
            var handler = findRegisteredHandler(ext.use);
            if (!handler) {
                return false;
            }
    
            var extension = handler(ext);
            if (extension) {
                extensions.push(extension);
            }
    
            return !!extension;
        }
    
        ExtService.tagExtension = function(name, tag) {
            var extension = ExtService.findExtensionByName(name);
            extension.tags = [].concat(extension.tags || [], tag);
        };
    
        ExtService.findExtensionByTag = function(tag) {
            return _.find(extensions, function(extension) {
                return _.contains(extension.tags, tag);
            });
        };
    
        ExtService.findExtensionByName = function(name) {
            return _.findWhere(extensions, {'name': name});
        };
    
        ExtService.filterExtensionsByUse = function(use) {
            return _.filter(extensions, function(extension) {
                return extension.use === use;
            });
        };
    
        ExtService.findExtensionByNameAndProvider = function(name, provider) {
            return _.find(extensions, function(extension) {
                var data = extension.data;
                if(!data) return false;
    
                return data.name === name && data.provider && data.provider.name === provider;
            });
        };
    
        ExtService.registerExtensionsByUse = function(use, handler, validators) {
            validators = validators ? [].concat(validators) : []; // optional, but must assert this is an array
            uses[use] = {
                'handler':    handler,
                'validators': validators
            };
        };
    })(ExtensionService);
    
    /*
    * Extension API
    *
    * This is used to exposed a very specific set of internal functions to be available to external
    * code for the purpose of allow extensions to access core agent functionality.
    */
    
    var ExtensionAPI = {
        'Launcher': {
            'addBehavior': function(behavior) {
                Launcher.behaviors.push(behavior);
            }
        },
        // note: changing this function to `getMetadata: getMetadata` returns undefined
        'Metadata': {
            'getMetadata': function() {
                return getMetadata();
            }
        },
        'Util': {
            'documentScrollTop':  documentScrollTop,
            'documentScrollLeft': documentScrollLeft,
            'getOffsetPosition':  getOffsetPosition
        }
    };
    
    var FlexboxPolyfill = (function() {
        return {
            'calculateTotalOffsetWidth':          calculateTotalOffsetWidth,
            'center':                             center,
            'createFlexContainer':                createFlexContainer,
            'createFlexRow':                      createFlexRow,
            'findMaxChildHeight':                 findMaxChildHeight,
            'flexEnd':                            flexEnd,
            'flexStart':                          flexStart,
            'formatPseudoRow':                    formatPseudoRow,
            'getPendoInlineUIElements':           getPendoInlineUIElements,
            'getPendoVisualElements':             getPendoVisualElements,
            'initializeFlexboxContainer':         initializeFlexboxContainer,
            'isPendoInlineUIElement':             isPendoInlineUIElement,
            'justifyContent':                     justifyContent,
            'setElementAlignment':                setElementAlignment,
            'spaceAround':                        spaceAround,
            'spaceBetween':                       spaceBetween,
            'spaceEvenly':                        spaceEvenly,
            'wrapElementInMockFlexboxContainer':  wrapElementInMockFlexboxContainer,
            'wrapMockFlexElementsInMockFlexRows': wrapMockFlexElementsInMockFlexRows
        };
    
        // Wraps each child in an inline-block div, so we can preserve margin when flexing the row
        function initializeFlexboxContainer(container) {
            var newContainer = container.cloneNode();
            var visualElements = FlexboxPolyfill.getPendoVisualElements(container.children);
            var inlineElements = FlexboxPolyfill.getPendoInlineUIElements(container.children);
            var isFlexRow = visualElements[0] && visualElements[0].className === 'pendo-mock-flexbox-row';
    
            if (isFlexRow) return container;
    
            newContainer.innerHTML = '';
    
            for (var i = 0; i < visualElements.length; i++) {
                if (!pendo.BuildingBlocks.BuildingBlockGuides.isElementHiddenInGuide(visualElements[i])) {
                    newContainer.appendChild(FlexboxPolyfill.wrapElementInMockFlexboxContainer(visualElements[i]));
                } else {
                    newContainer.appendChild(visualElements[i]);
                }
            }
    
            for (var j = 0; j < inlineElements.length; j++) {
                newContainer.appendChild(inlineElements[j]);
            }
    
            container.parentNode.replaceChild(newContainer, container);
            return newContainer;
        }
    
        // Applies justify-content-like behavior to a row of elements
        // This fn assumes flex-wrap: wrap
        function justifyContent(container, justifyContent) {
            var containerWidth = parseInt(container.offsetWidth, 10) - parseInt(container.style.paddingLeft, 10) - parseInt(container.style.paddingRight, 10);
            var visualElements = FlexboxPolyfill.getPendoVisualElements(container.children);
            var idx = 0;
    
            if(!visualElements.length) return;
    
            var itrCounter = 0;
            while(idx < visualElements.length) {
                if(itrCounter > 50) break;
                if(!pendo.BuildingBlocks.BuildingBlockGuides.isElementHiddenInGuide(visualElements[idx])) {
                    idx = FlexboxPolyfill.formatPseudoRow(containerWidth, visualElements, idx, justifyContent, container);
                } else {
                    idx++;
                }
                itrCounter++;
            }
        }
    
        // Break down a single row into flex-wrap-like rows, based on the width of each child
        // in the container. justify-content rules are then applied to each row
        function formatPseudoRow(containerWidth, children, startingIndex, justifyContent, container) {
            var totalWidthUsed = 0;
            var idx = startingIndex;
            var childrenToStyle = [];
    
            if(!children.length) return;
    
            var itrCounter = 0;
            while(totalWidthUsed <= containerWidth && idx < children.length) {
                if(itrCounter > 50) break;
    
                var childWidth = parseInt(children[idx].offsetWidth, 10);
    
                totalWidthUsed += childWidth;
    
                if(totalWidthUsed > containerWidth && childrenToStyle.length > 1) {
                    totalWidthUsed -= childWidth;
                    idx--;
                    break;
                }
    
                childrenToStyle.push(children[idx]);
                idx++;
                itrCounter++;
            }
    
            var endingIndex = Math.min(children.length - 1, idx);
            var spaceRemaining = containerWidth - totalWidthUsed;
            FlexboxPolyfill.setElementAlignment(childrenToStyle, spaceRemaining, justifyContent, container);
    
            return endingIndex + 1;
        }
    
        function setElementAlignment(children, spaceRemaining, justifyContent, container) {
            if(children.length < 1) return;
    
            FlexboxPolyfill.wrapMockFlexElementsInMockFlexRows(container, children);
    
            //eslint-disable-next-line default-case
            switch(justifyContent) {
            case 'space-between': {
                FlexboxPolyfill.spaceBetween(children, spaceRemaining);
                break;
            }
            case 'space-around': {
                FlexboxPolyfill.spaceAround(children, spaceRemaining);
                break;
            }
            case 'space-evenly': {
                FlexboxPolyfill.spaceEvenly(children, spaceRemaining);
                break;
            }
            case 'center': {
                FlexboxPolyfill.center(children, spaceRemaining);
                break;
            }
            case 'flex-start': {
                FlexboxPolyfill.flexStart(children);
                break;
            }
            case 'flex-end': {
                FlexboxPolyfill.flexEnd(children, spaceRemaining);
                break;
            }
            }
        }
    
        function isPendoInlineUIElement(ele) {
            var classes = ele.getAttribute('class');
            return !!(classes && classes.indexOf('pendo-inline-ui') > -1);
        }
    
        function getPendoVisualElements(elements) {
            return _.filter(elements, function(element) {
                return !isPendoInlineUIElement(element);
            });
        }
    
        function getPendoInlineUIElements(elements) {
            return _.filter(elements, function(element) {
                return isPendoInlineUIElement(element);
            });
        }
    
        function createFlexContainer(isElementPosAbsolute) {
            var container = document.createElement('div');
            container.style.display = 'inline-block';
    
            if (!isElementPosAbsolute) {
                container.style.position = 'absolute';
            }
    
            // Sibling inline-block elements will attempt to align with a common baseline (think about it like a horizontal line)
            // By default, vertical-align is "baseline", which in most cases means all sibling elements line up vertically to the bottom of the
            // element with the largest height. We'll set all flexbox wrappers to "top", which is the behavior you'd expect from flex elements by default
            container.style['vertical-align'] = 'top';
            container.setAttribute('class', 'pendo-mock-flexbox-element');
            return container;
        }
    
        function createFlexRow() {
            var row = document.createElement('div');
            row.setAttribute('class', 'pendo-mock-flexbox-row');
            row.style.display = 'block';
            row.style.position = 'relative';
            row.style.width = '100%';
    
            return row;
        }
    
        function wrapElementInMockFlexboxContainer(ele) {
            var classes = ele.getAttribute('class') || '';
            var isWrapper = classes.indexOf('pendo-block-wrapper') !== -1;
            var isElementPosAbsolute = ele.style && ele.style.position === 'absolute';
            var actualElementWidth = get(ele.style, 'width', '');
            var computedEleWidth = getComputedStyle_safe(ele).width;
            var isPercentageWidth = actualElementWidth.indexOf('%') > -1;
    
            if (isWrapper) {
                // if the wrapper has a defined width, use it over the image width
                var existingWrapperWidth = actualElementWidth ? computedEleWidth : null;
                if(existingWrapperWidth) {
                    actualElementWidth = existingWrapperWidth;
                } else {
                    actualElementWidth = ele.children[0].offsetWidth + 'px';
                }
            }
    
            if(!classes || classes.indexOf('pendo-mock-flexbox-element') < 0) {
                var container = FlexboxPolyfill.createFlexContainer(isElementPosAbsolute);
                container.appendChild(ele);
    
                if (isWrapper && !ele.style.width) {
                    container.children[0].children[0].style.width = actualElementWidth;
                }
    
                if(isWrapper && ele.style.width) {
                    container.style.width = actualElementWidth;
                } if(isPercentageWidth) {
                    container.style.width = computedEleWidth;
                } else {
                    container.style.width = ele.style.width;
                }
    
                return container;
            }
    
            return ele;
        }
    
        function wrapMockFlexElementsInMockFlexRows(container, flexElements) {
            var newRow = FlexboxPolyfill.createFlexRow();
            var isFlexRow = flexElements[0].className === 'pendo-mock-flexbox-row';
            var maxChildHeight = FlexboxPolyfill.findMaxChildHeight(flexElements, isFlexRow);
    
            if (isFlexRow) {
                flexElements[0].style['min-height'] = maxChildHeight + 'px';
                return container;
            }
    
            for(var i = 0; i < flexElements.length; i++) {
                newRow.appendChild(flexElements[i]);
            }
    
            container.appendChild(newRow);
            newRow.style['min-height'] = maxChildHeight + 'px';
    
            return container;
        }
    
        function findMaxChildHeight(children, isFlexRow) {
            var childrenOffsetHeight = [];
    
            for (var i = 0; i < children.length; i++) {
    
                if (isFlexRow) {
                    var classes = children[i].children[0].children[0].getAttribute('class') || '';
                    var isWrapper = classes.indexOf('pendo-block-wrapper') !== -1;
    
                    if (isWrapper) {
                        var actualElementHeight = children[i].children[0].offsetHeight + 'px';
                        children[i].style.height = actualElementHeight;
                    }
                }
    
                childrenOffsetHeight.push(children[i].offsetHeight);
            }
    
            return _.reduce(childrenOffsetHeight, function(a, b) {
                return Math.max(a, b);
            }, 20);
        }
    
        function calculateTotalOffsetWidth(totalChildren, index) {
            var precedingElements = totalChildren.slice(0, index);
            var totalOffsetWidth = 0;
    
            for (var i = 0; i < precedingElements.length; i++) {
                var individualOffset = precedingElements[i].offsetWidth;
                totalOffsetWidth = totalOffsetWidth + individualOffset;
            }
    
            return totalOffsetWidth;
        }
    
        function spaceBetween(children, spaceRemaining) {
            var marginSpace = spaceRemaining / Math.max(children.length - 1, 1);
            var firstChild = children[0];
            var lastChild = children[children.length - 1];
    
            for(var i = 1; i < children.length - 1; i++) {
                var childElmOffsetWidth = calculateTotalOffsetWidth(children, i);
                children[i].style.left = marginSpace + childElmOffsetWidth + 'px';
            }
    
            firstChild.style.left = '0px';
            lastChild.style.right = '0px';
        }
    
        function spaceAround(children, spaceRemaining) {
            var marginSpace = spaceRemaining / (children.length * 2);
            var firstChild = children[0];
            var lastChild = children[children.length - 1];
    
            for(var i = 1; i < children.length - 1; i++) {
                var childElmOffsetWidth = calculateTotalOffsetWidth(children, i);
                children[i].style.left = (marginSpace * 2) + childElmOffsetWidth + 'px';
            }
    
            firstChild.style.left = marginSpace + 'px';
            lastChild.style.right = marginSpace + 'px';
        }
    
        function spaceEvenly(children, spaceRemaining) {
            var marginSpace = spaceRemaining / (children.length + 1);
            var firstChild = children[0];
            var lastChild = children[children.length - 1];
    
            for(var i = 1; i < children.length - 1; i++) {
                var childElmOffsetWidth = calculateTotalOffsetWidth(children, i);
                children[i].style.left = marginSpace + childElmOffsetWidth + 'px';
            }
    
            firstChild.style.left = marginSpace + 'px';
            lastChild.style.right = marginSpace + 'px';
        }
    
        function center(children, spaceRemaining) {
            var marginSpace = spaceRemaining / 2;
            var firstChild = children[0];
            var lastChild = children[children.length - 1];
    
            for(var i = 1; i < children.length - 1; i++) {
                var childElmOffsetWidth = calculateTotalOffsetWidth(children, i);
                children[i].style.left = marginSpace + childElmOffsetWidth + 'px';
            }
    
            if (children.length > 1) {
                lastChild.style.right = marginSpace + 'px';
            }
    
            firstChild.style.left = marginSpace + 'px';
        }
    
        function flexStart(children) {
            var firstChild = children[0];
            firstChild.style.left = '0px';
    
            for(var i = 1; i < children.length; i++) {
                var childElmOffsetWidth = calculateTotalOffsetWidth(children, i);
                children[i].style.left = childElmOffsetWidth + 'px';
            }
        }
    
        function flexEnd(children, spaceRemaining) {
            var marginSpace = spaceRemaining;
            var firstChild = children[0];
            var lastChild = children[children.length - 1];
    
            for(var i = 1; i < children.length - 1; i++) {
                var childElmOffsetWidth = calculateTotalOffsetWidth(children, i);
                children[i].style.left = marginSpace + childElmOffsetWidth + 'px';
            }
    
            if (children.length > 1) {
                firstChild.style.left = marginSpace + 'px';
            }
    
            lastChild.style.right = '0px';
        }
    })();
    
    var BuildingBlockTemplates = (function() {
        return {
            'buildNodesFromTemplate':               buildNodesFromTemplate,
            'generateUnreadAnnouncementMiniBubble': generateUnreadAnnouncementMiniBubble
        };
    
        function buildNodesFromTemplate(templateName, templateJson, step, guides) {
            var guideList = guides || getActiveGuides();
            switch (templateName) {
            case 'pendo_resource_center_module_list_item':
                return generateResourceCenterModuleList(templateJson, step, guideList);
            case 'pendo_resource_center_guide_list_item':
                return generateResourceCenterGuideList(templateJson, step, guideList);
            case 'pendo_resource_center_onboarding_item':
                return generateResourceCenterOnboardingList(templateJson, step, guideList);
            case 'pendo_resource_center_onboarding_progress_bar':
                return generateResourceCenterOnboardingProgressBar(templateJson, step, guideList);
            case 'pendo_resource_center_announcement_item':
                return generateResourceCenterAnnouncements(templateJson, step, guideList);
            case 'pendo_guide_data_text_block':
                return generateGuideDataTextBlock(templateJson, step, guideList);
            default:
                return [];
            }
        }
    
        function replaceTemplateStrings(content, variables) {
            var variableRegex = /<%=\s*([A-Za-z_0-9$]+)\s*%>/gi;
            return content.replace(variableRegex, function(fullMatch, variableName) {
                if (_.isNull(variables[variableName]) || _.isUndefined(variables[variableName])) return fullMatch;
    
                return variables[variableName];
            });
        }
    
        function recursivelyEvaluateTemplatesForBlock(templateJson, variables) {
            if(templateJson.content) {
                templateJson.content = replaceTemplateStrings(templateJson.content, variables);
            }
    
            if(templateJson.children) {
                for(var i = 0; i < templateJson.children.length; i++) {
                    recursivelyEvaluateTemplatesForBlock(templateJson.children[i], variables);
                }
            }
    
            return templateJson;
        }
    
        function generateResourceCenterModuleList(templateJson, step, guides) {
            var children = templateJson.templateChildren;
            return _.reduce(children, function(acc, childConfig, index) {
                var homeView = BuildingBlockResourceCenter.findResourceCenterHomeView(guides);
                var guide = _.find(guides, function(singleGuide) {
                    return singleGuide.id === childConfig.id;
                });
                // if using the designer, show all guides
                if(pendo.designer) {
                    guide = childConfig;
                    homeView = _.find(guides, function(guideA) {
                        return get(guideA, 'attributes.resourceCenter.isTopLevel');
                    });
                } else {
                    // if the guide is not present, or has no content, don't add it to the list
                    if(!guide || !guide.hasResourceCenterContent) return acc;
                }
                var listItem = JSON.parse(JSON.stringify(templateJson)); // underscore doesn't have deep clone
                delete listItem.templateChildren;
    
                listItem.props.id = listItem.props.id + '-' + index;
                listItem.props['data-pendo-module-guide-id'] = guide.id;
    
                if(!listItem.actions) listItem.actions = [];
                var listItemAction = {
                    'action':      'renderResourceCenterModule',
                    'source':      listItem.props.id,
                    'destination': 'EventRouter',
                    'parameters':  [{
                        'name':  'guideId',
                        'type':  'string',
                        'value': guide.id
                    }],
                    'uiMetadata': {},
                    'eventType':  'click'
                };
    
                if(!pendo.designer) {
                    listItem.actions.push(listItemAction);
                }
    
                var notificationBubbleConfig = get(homeView, 'attributes.notificationBubble');
                var notificationsObj = get(homeView, 'attributes.notifications');
                if (notificationBubbleConfig && notificationsObj) {
                    var notificationId;
    
                    if (get(guide, 'attributes.resourceCenter.moduleId') === 'AnnouncementsModule') {
                        notificationId = guide.id;
                    }
    
                    if (get(guide, 'attributes.resourceCenter.integrationName') === 'chat') {
                        notificationId = 'chat';
                    }
    
                    if (notificationId) {
                        listItem.props['data-pendo-notification-id'] = notificationId;
                        formatListItemForNotificationBubble(listItem, homeView, notificationBubbleConfig, notificationId, homeView.attributes.notifications.individualCounts[notificationId]);
                    }
                }
    
                listItem = recursivelyEvaluateTemplatesForBlock(listItem, childConfig);
                return acc.concat(BuildingBlockGuides.buildNodeFromJSON(listItem, step, guides));
            }, []);
        }
    
        function generateResourceCenterGuideList(templateJson, step, guides) {
            var children = templateJson.templateChildren;
    
            return _.reduce(children, function(acc, childConfig, index) {
                var guide = _.find(guides, function(singleGuide) {
                    return singleGuide.id === childConfig.id;
                });
    
                // if using the designer, show all guides
                if(pendo.designer) {
                    guide = childConfig;
                } else {
                    // if the guide is not present, or has no content, don't add it to the list
                    if(!guide || guide.ineligibleForRC) return acc;
                }
    
                var listItem = JSON.parse(JSON.stringify(templateJson)); // underscore doesn't have deep clone
                if (childConfig.keywords) {
                    listItem.props['data-_pendo-text-list-item-1'] = childConfig.keywords;
                }
                delete listItem.templateChildren;
    
                listItem.props.id = listItem.props.id + '-' + index;
    
                if(!listItem.actions) listItem.actions = [];
    
                var listItemAction = {
                    'action':      'showGuide',
                    'source':      listItem.props.id,
                    'destination': 'EventRouter',
                    'parameters':  [{
                        'name':  'guideId',
                        'type':  'string',
                        'value': guide.id
                    }],
                    'uiMetadata': {},
                    'eventType':  'click'
                };
    
                if(!pendo.designer) {
                    listItem.actions.push(listItemAction);
                }
    
                listItem = recursivelyEvaluateTemplatesForBlock(listItem, childConfig);
                return acc.concat(BuildingBlockGuides.buildNodeFromJSON(listItem, step, guides));
            }, []);
        }
    
        function generateResourceCenterOnboardingList(templateJson, step, guides) {
            var children = templateJson.templateChildren;
    
            return _.reduce(children, function(acc, childConfig, index) {
                var guide = _.find(guides, function(singleGuide) {
                    return singleGuide.id === childConfig.id;
                });
    
                // if using the designer, show all guides
                if(pendo.designer) {
                    guide = childConfig;
                } else {
                    // if the guide is not present, or has no content, don't add it to the list
                    if(!guide || guide.ineligibleForRC) return acc;
                }
    
                var listItem = JSON.parse(JSON.stringify(templateJson)); // underscore doesn't have deep clone
                delete listItem.templateChildren;
                listItem.props.id = listItem.props.id + '-' + index;
    
                if(!listItem.actions) listItem.actions = [];
    
                var listItemAction = {
                    'action':      'showGuide',
                    'source':      listItem.props.id,
                    'destination': 'EventRouter',
                    'parameters':  [{
                        'name':  'guideId',
                        'type':  'string',
                        'value': guide.id
                    }],
                    'uiMetadata': {},
                    'eventType':  'click'
                };
    
                if(!pendo.designer) {
                    listItem.actions.push(listItemAction);
                }
    
                var totalSteps = guide.getTotalSteps();
                var seenSteps = guide.getSeenSteps();
                if (guide.isComplete()) seenSteps = totalSteps;
    
                var percentageComplete = parseInt(seenSteps / totalSteps * 100, 10);
    
                var svgCircle = BuildingBlockGuides.findDomBlockInDomJson(listItem, function(item) {
                    return item.svgWidgetId;
                });
    
                svgCircle.svgAttributes.fillCircle.percentComplete = percentageComplete;
    
                if (childConfig.hasOwnProperty('subtitle')) {
                    childConfig.stepProgress = replaceTemplateStrings(
                        childConfig.subtitle, { 'currentStep': seenSteps, 'totalSteps': totalSteps }
                    );
                } else {
                    var stepProgress = 'Step ' + seenSteps + ' of ' + totalSteps;
                    childConfig.stepProgress = stepProgress;
                }
    
                listItem = recursivelyEvaluateTemplatesForBlock(listItem, childConfig);
                return acc.concat(BuildingBlockGuides.buildNodeFromJSON(listItem, step, guides));
            }, []);
        }
    
        function generateResourceCenterOnboardingProgressBar(templateJson, step, guides) {
            var children = step.getGuide().attributes.resourceCenter.children;
            var totalSteps = 0;
            var totalSeenSteps = 0;
            _.forEach(children, function(childGuideId) {
                var guide = _.find(guides, function(singleGuide) {
                    return singleGuide.id === childGuideId;
                });
    
                // if using the designer, show all guides
                if(pendo.designer) {
                    guide = childGuideId;
                } else {
                    // if the guide is not present, or has no content, don't add it to the list
                    if(!guide || guide.ineligibleForRC) return;
                }
                if (guide.isComplete()) {
                    totalSteps += guide.getTotalSteps();
                    totalSeenSteps += guide.getTotalSteps();
                } else {
                    totalSteps += guide.getTotalSteps();
                    totalSeenSteps += guide.getSeenSteps();
                }
            });
    
            var percentageComplete = parseInt(totalSeenSteps / totalSteps * 100, 10);
            if(isNaN(percentageComplete)) {
                percentageComplete = 0;
            }
    
            var variables = {
                'totalPercentComplete': percentageComplete + '%'
            };
    
            var listItem = JSON.parse(JSON.stringify(templateJson)); // underscore doesn't have deep clone
            listItem = recursivelyEvaluateTemplatesForBlock(listItem, variables);
    
            var progressBarFillEle = BuildingBlockGuides.findDomBlockInDomJson(listItem, function(item) {
                return item.props && item.props.id && item.props.id.indexOf('pendo-progress-bar-fill') !== -1;
            });
    
            progressBarFillEle.props.style.width = variables.totalPercentComplete;
            return [BuildingBlockGuides.buildNodeFromJSON(listItem, step, guides)];
        }
    
        function generateResourceCenterAnnouncements(templateJson, step, guides) {
            var children = step.getGuide().attributes.resourceCenter.children;
    
            // iterates over RC children and returns guide matching from guides array to ultimately render out
            // iterates over guides (1st priority - mocked guides) OR pendo.guides (2nd priority - staged + public guides only)
            var renderableGuides = _.reduce(children, function(acc, childGuideId, index) {
                var guide = _.find(guides, function(singleGuide) {
                    return singleGuide.id === childGuideId;
                });
    
                // if using the designer, show all guides
                if(pendo.designer) {
                    guide = childGuideId;
                } else {
                    // if the guide is not present, or has no content, don't add it to the list
                    if(!guide) return acc;
                }
    
                acc.push(guide);
                return acc;
            }, []);
    
            var sortedGuides = _.sortBy(renderableGuides, function(guide) {
                var dateToDisplay = get(guide, 'showsAfter') || get(guide, 'publishedAt');
                if(!dateToDisplay) {
                    dateToDisplay = new Date().getTime();
                }
    
                return -1 * dateToDisplay;
            });
    
            var resourceCenter = BuildingBlockResourceCenter.getResourceCenter();
            var bubbleConfig = get(resourceCenter, 'attributes.notificationBubble');
    
            return _.map(sortedGuides, function(guide, index) {
                var isP1WhatsNewGuide = get(guide, 'attributes.type') === 'whatsnew';
                var listItem = JSON.parse(JSON.stringify(templateJson)); // underscore doesn't have deep clone
    
                var annoucementStep = guide.steps[0];
                annoucementStep.eventRouter = new EventRouter();
    
                listItem.props.id = listItem.props.id + '-' + index;
                listItem.props['data-pendo-announcement-guide-id'] = guide.id;
    
                if(isP1WhatsNewGuide) {
                    return renderWhatsNew(guide, listItem, bubbleConfig);
                }
    
                return renderAnnouncement(guide, listItem, bubbleConfig);
            });
        }
    
        function renderAnnouncement(guide, listItem, bubbleConfig) {
            var miniBubble;
            var processedGuide = window.pendo.GuideFactory(guide);
            var announcementStep = guide.steps[0];
            
            if (_.isFunction(announcementStep.script)) {
                announcementStep.script(announcementStep, processedGuide);
            }
    
            var announcementDomJson = announcementStep.domJson;
            listItem.children = [announcementDomJson];
    
            if(bubbleConfig) {
                miniBubble = generateUnreadAnnouncementMiniBubble(bubbleConfig);
                var containerTruthTest = function(listItem) { return listItem.props.id === 'pendo-guide-container'; };
                var containerDomJson = BuildingBlockGuides.findDomBlockInDomJson(listItem, containerTruthTest);
                var containerTopPadding = parseInt(listItem.props.style['padding-top'], 10);
                var guideTopPadding = parseInt(containerDomJson.props.style['padding-top'], 10);
                miniBubble.props.style.top = guideTopPadding + containerTopPadding + 5 + 'px';
            }
    
            if (!BuildingBlockResourceCenter.hasAnnouncementBeenSeen(guide) && miniBubble) {
                listItem.props['class'] += ' pendo-unseen-announcement';
                listItem.children.unshift(miniBubble);
            }
    
            delete listItem.templateName;
            return BuildingBlockGuides.buildNodeFromJSON(listItem, announcementStep);
        }
    
        function renderWhatsNew(guide, listItem, bubbleConfig) {
            var miniBubble;
            var processedGuide = window.pendo.GuideFactory(guide);
            var announcementStep = processedGuide.steps[0];
    
            announcementStep.render();
    
            if (_.isFunction(announcementStep.script)) {
                announcementStep.script(announcementStep, processedGuide);
            }
    
            var generatedHtml = announcementStep.guideElement;
            var elementId = generatedHtml[0].id;
            var styleString = '#' + elementId + ' h1::after { display:none; }';
            var styleElem = generatedHtml[0].appendChild(document.createElement('style'));
            styleElem.innerHTML = styleString;
    
            if(bubbleConfig) {
                miniBubble = generateUnreadAnnouncementMiniBubble(bubbleConfig);
                miniBubble.props.style.top = '20px';
            }
    
            if(!BuildingBlockResourceCenter.hasAnnouncementBeenSeen(guide) && miniBubble) {
                listItem.props['class'] += ' pendo-unseen-announcement';
                listItem.children = [miniBubble];
            }
    
            var listItemContainer = BuildingBlockGuides.buildNodeFromJSON(listItem, announcementStep);
            generatedHtml.appendTo(listItemContainer);
            return listItemContainer;
        }
    
        function generateUnreadAnnouncementMiniBubble(bubbleConfig) {
            return {
                'type':     'div',
                'children': [],
                'props':    {
                    'class': 'pendo-unread-announcement-mini-bubble',
                    'style': {
                        'position':         'absolute',
                        'border-radius':    '5px',
                        'height':           '10px',
                        'width':            '10px',
                        'line-height':      '0px',
                        'left':             '0px',
                        'top':              '30px',
                        'box-sizing':       'content-box',
                        'background-color': bubbleConfig['background-color'],
                        'z-index':          '10'
                    }
                }
            };
        }
    
        function generateGuideDataTextBlock(templateJson, step, guides) {
            var guide = step.getGuide ? step.getGuide() : _.find(guides, function(guide) {
                return guide.id === step.guideId;
            });
    
            var translatedDate = get(guide, 'attributes.dates.' + guide.language, false);
            var variables;
    
            if (translatedDate) {
                variables = { 'showsAfter': translatedDate };
            } else {
                var dateToDisplay =  get(guide, 'showsAfter') || get(guide, 'publishedAt');
                if(dateToDisplay) {
                    dateToDisplay = new Date(dateToDisplay);
                } else {
                    dateToDisplay = new Date();
                }
    
                var englishShortFormMonths = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
                var formattedDate = englishShortFormMonths[dateToDisplay.getMonth()] + ' ' + dateToDisplay.getDate() + ', ' + dateToDisplay.getFullYear();
                variables = { 'showsAfter': formattedDate };
            }
    
            var guideDataTextBlock = JSON.parse(JSON.stringify(templateJson));
            guideDataTextBlock = recursivelyEvaluateTemplatesForBlock(guideDataTextBlock, variables);
    
            return [BuildingBlockGuides.buildNodeFromJSON(guideDataTextBlock, step, guides)];
        }
    
        function formatListItemForNotificationBubble(templateJson, homeView, bubbleConfig, type, count) {
            var listItemRow = BuildingBlockGuides.findDomBlockInDomJson(templateJson, function(block) {
                return block && block.props && block.props.id && block.props.id.indexOf('pendo-row') !== -1;
            });
            if(!listItemRow) return;
    
            var textContainer = _.find(listItemRow.children, function(child) {
                return child && child.props && child.props.id && child.props.id.indexOf('pendo-text') !== -1;
            });
    
            if(!textContainer || !textContainer.props || !textContainer.props.style) return;
    
            var existingWidth = parseInt(textContainer.props.style.width, 10);
            if(!existingWidth || isNaN(existingWidth)) return;
    
            var textContainerIndex = listItemRow.children.indexOf(textContainer);
            var adjustedWidth = existingWidth - 40 + 'px';
            if (textContainer.props.style.width !== '100%') {
                textContainer.props.style.width = adjustedWidth;
            }
            textContainer.props.style['padding-right'] = '40px';
            // Box-sizing will be ignored by IE7, but it only supports content-box
            textContainer.props.style['box-sizing'] = 'content-box';
    
            var notificationBubble = {
                'type':     'div',
                'children': [{
                    'type':    'div',
                    'content': String(homeView.attributes.notifications.individualCounts[type]),
                    'props':   {
                        'style': {
                            'display':        'inline-block',
                            'vertical-align': 'middle',
                            'line-height':    '26px',
                            'font-weight':    bubbleConfig['font-weight'],
                            'font-family':    bubbleConfig['font-family'],
                            'color':          bubbleConfig.color
                        }
                    }
                }],
                'props': {
                    'class': '_pendo-home-view-bubble',
                    'style': {
                        'position':         'absolute',
                        'border-radius':    '20px',
                        'height':           '26px',
                        'line-height':      '0px',
                        'padding':          '0px 10px',
                        'right':            '20px',
                        'top':              '50%',
                        'margin-top':       '-14px',
                        'box-sizing':       'content-box',
                        'background-color': bubbleConfig['background-color'],
                        'display':          count ? 'block' : 'none'
                    }
                }
            };
    
            listItemRow.children.splice(textContainerIndex + 1, 0, notificationBubble);
        }
    
    })();
    
    var BuildingBlockTooltips = (function() {
    
        return {
            'createBBTooltip':                      createBBTooltip,
            'getBBTooltipDimensions':               getBBTooltipDimensions,
            'determineBBHorizontalBias':            determineBBHorizontalBias,
            'determineTooltipPosition':             determineTooltipPosition,
            'positionBBTooltipWithBias':            positionBBTooltipWithBias,
            'calculateToolTipPositionForTopBottom': calculateToolTipPositionForTopBottom,
            'calculateToolTipPositionForLeftRight': calculateToolTipPositionForLeftRight,
            'buildTooltipCaret':                    buildTooltipCaret,
            'styleTopOrBottomCaret':                styleTopOrBottomCaret,
            'styleLeftOrRightCaret':                styleLeftOrRightCaret,
            'buildBorderCaret':                     buildBorderCaret,
            'determineBorderCaretColor':            determineBorderCaretColor,
            'placeBBTooltip':                       placeBBTooltip,
            'attachBBAdvanceActions':               attachBBAdvanceActions
        };
    
        function createBBTooltip(domJson, element, step, guideContainer) {
            if(!step.guideElement) return;
    
            var tooltipDiv = step.guideElement;
            tooltipDiv.addClass(buildTooltipCSSName());
            var elementPos = getOffsetPosition(element);
    
            // RETURN IF THE FOUND ELEMENT IS NOT VISIBLE ON THE SCREEN.
            if(elementPos.height === 0 && elementPos.width === 0) {
                return null;
            }
    
            var containerTruthTest = function(block) { return block.props.id === 'pendo-guide-container'; };
            var containerDomJson = BuildingBlockGuides.findDomBlockInDomJson(domJson, containerTruthTest);
    
            if(!containerDomJson) return;
    
            var layoutDir = step.attributes.layoutDir;
            var tooltipSizes = {
                'height': guideContainer.offsetHeight,
                'width':  guideContainer.offsetWidth
            };
            var caretDimensions = {
                'height':          parseInt(containerDomJson.props['data-caret-height'], 10) || 0,
                'width':           parseInt(containerDomJson.props['data-caret-width'], 10) || 0,
                'backgroundColor': containerDomJson.props.style['background-color'],
                'offset':          10
            };
    
            attachBBAdvanceActions(step);
    
            if(containerDomJson.props.style.border) {
                var guideBorderArray = containerDomJson.props.style.border.split(' ');
                caretDimensions.borderColor = guideBorderArray[2];
                caretDimensions.borderWidth = parseInt(guideBorderArray[0], 10);
            }
    
            var tooltipDimensions = getBBTooltipDimensions(elementPos, tooltipSizes, caretDimensions, layoutDir);
    
            if (step) {
                step.dim = tooltipDimensions;
            }
    
            var curGuide;
    
            if (step && _.isFunction(step.getGuide)) {
                curGuide = step.getGuide();
            }
    
            var isResourceCenter = get(curGuide, 'attributes.resourceCenter');
            if (elementPos.fixed) {
                // If the target is fixed, fix the tooltip as well
                tooltipDiv.css({ 'position': 'fixed' });
                guideContainer.style.position = 'absolute';
            } else if (!(step && isResourceCenter)) {
                guideContainer.style.position = 'absolute';
            }
    
            if(caretDimensions.height && caretDimensions.width) {
                buildTooltipCaret(tooltipDiv, tooltipDimensions, caretDimensions);
            }
    
            var inheritedZIndex = '300000';
            if(guideContainer && guideContainer.style && guideContainer.style['z-index']) {
                inheritedZIndex = guideContainer.style['z-index'];
            }
            //
            // styles for OUTER Guide
            //
            tooltipDiv.css({
                'z-index': inheritedZIndex
            });
    
            if (!isResourceCenter) {
                tooltipDiv.css({
                    'height':   'auto',
                    'width':    'auto',
                    'overflow': 'visible'
                });
            }
    
            if(step.elementPathRule) {
                tooltipDiv.css({
                    'left':     tooltipDimensions.left,
                    'top':      tooltipDimensions.top,
                    'position': elementPos.fixed ? 'fixed' : 'absolute'
                });
            }
    
    
            if (tooltipDimensions.layoutDir === 'top' && tooltipDimensions.hbias === 'left') {
                // adjust watermark from bottom to top
                tooltipDiv.find('#pendo-watermark').css({
                    'top':    'auto',
                    'bottom': '100%'
                });
            }
    
            // attach scroll handlers
            var overflowScroll = /(auto|scroll)/,
                scrollParent = getScrollParent(element, overflowScroll),
                pbody = getBody();
            while (scrollParent && scrollParent !== pbody) {
                step.attachEvent(scrollParent, 'scroll',
                    _.throttle(_.bind(onscroll, this, step, scrollParent, overflowScroll), 10));
                scrollParent = getScrollParent(scrollParent, overflowScroll);
            }
    
            return tooltipDiv[0];
        }
    
        function advanceGuide(eventType, step) {
            var btn = Sizzle(step.elementPathRule)[0];
            var onEvent = function() {
                pendo.onGuideAdvanced(eventType, step);
            };
            step.attachEvent(btn, eventType, onEvent);
        }
    
        function attachBBAdvanceActions(step) {
            if (step.attributes && step.attributes.advanceActions && step.elementPathRule) {
                if (step.attributes.advanceActions.elementHover) {
                    advanceGuide('mouseover', step);
                }
                else if (step.attributes.advanceActions.elementClick) {
                    advanceGuide('click', step);
                }
            }
        }
    
        function getBBTooltipDimensions(elementPos, tooltipSizes, caretSizes, layoutDir) {
            var screenDimensions = pendo._get_screen_dim();
            var layoutDirection = layoutDir || 'auto';
            var tooltipDimensions = {
                'width':  Math.min(tooltipSizes.width, screenDimensions.width), // Do not bust out of the horizontal space (mobile)
                'height': tooltipSizes.height //... but okay to have to scroll vertically a bit
            };
    
            tooltipDimensions.layoutDir = layoutDirection;
            // Determine position bias here
            tooltipDimensions.hbias = determineBBHorizontalBias(elementPos, screenDimensions, layoutDirection);
            tooltipDimensions.layoutDir = determineTooltipPosition(tooltipDimensions, screenDimensions, elementPos, layoutDirection);
    
            var tooltipPosition = positionBBTooltipWithBias(tooltipDimensions, elementPos, screenDimensions);
            tooltipDimensions.top = tooltipPosition.top;
            tooltipDimensions.left = tooltipPosition.left;
    
            // Adjust tooltip top/left for the size of the caret
            if(tooltipDimensions.layoutDir === 'top') {
                tooltipDimensions.top -= caretSizes.height;
            } else if(tooltipDimensions.layoutDir === 'bottom') {
                tooltipDimensions.top += caretSizes.height;
            } else if(tooltipDimensions.layoutDir === 'right') {
                tooltipDimensions.left += caretSizes.height;
            } else if(tooltipDimensions.layoutDir === 'left') {
                tooltipDimensions.left -= caretSizes.height;
            }
    
            return tooltipDimensions;
        }
    
        function determineBBHorizontalBias(elementPos, screenDim, layoutDir) {
            if (layoutDir === 'right' || layoutDir === 'left') {
                pendo.log('Setting layout position to ' + layoutDir);
                return layoutDir;
            }
    
            // if elementPos is in center column of screen, divide the screen into thirds.
            // If the tooltip starts after the first column, and fits inside columns 2 and 3, its center
            // if x(0) < elementPos.left < x(1)
            var columnSize = screenDim.width / 3;
            var firstColumnWidth = columnSize;
            var secondAndThirdColumnWidth = columnSize * 2;
    
            if (firstColumnWidth < elementPos.left && elementPos.left < secondAndThirdColumnWidth) {
                return 'center';
            }
    
            if (elementPos.left < (screenDim.width / 2)) {
                return 'right';
            }
    
            return 'left';
        }
    
        function determineTooltipPosition(tooltipDimensions, screenDimensions, elementPosition, layoutDirection) {
            if (layoutDirection && layoutDirection !== 'auto') {
                return layoutDirection;
            }
    
            var isElementFixed = elementPosition.fixed;
            var top = elementPosition.top - documentScrollTop();
            var left = elementPosition.left - documentScrollLeft();
            var right = left + elementPosition.width;
            var clientViewportDimensions = getClientRect(getBody());
            var offscreenTop = elementPosition.top - tooltipDimensions.height < 0;
            var offscreenBottom = elementPosition.top + elementPosition.height + tooltipDimensions.height > (isElementFixed ? clientViewportDimensions.height : clientViewportDimensions.bottom);
            var offscreenLeft = elementPosition.left - tooltipDimensions.width < 0;
            var offscreenRight = elementPosition.left + elementPosition.width + tooltipDimensions.width > (isElementFixed ? clientViewportDimensions.width : clientViewportDimensions.right);
            var offscreenAllDirections = offscreenBottom && offscreenTop && offscreenLeft && offscreenRight;
    
            // If everything is offscreen just be on the bottom and get out of here
            if (offscreenAllDirections) return 'bottom';
    
            var position;
            //Upper third of viewport, put arrow on top of guide
            if (top < (screenDimensions.height / 3)) {
                position = 'bottom';
            }
    
            //Bottom third of viewport
            var isElementInBottomThirdOfScreen = top > (2 * screenDimensions.height / 3);
            if (isElementInBottomThirdOfScreen || tooltipDimensions.hbias === 'center') {
                position = 'top';
            }
    
            if (left < tooltipDimensions.width && screenDimensions.width - right < tooltipDimensions.width) {
                //Not enough horizontal space for the hbias default, so just position it below the element
                position = 'bottom';
            }
    
            if (position === 'bottom') {
                var bodyDimensions = getOffsetPosition(document.body);
                // If something would expand the document beyond its normal height, try to put
                // the tooltip above the target element
                if(elementPosition.top + tooltipDimensions.height > bodyDimensions.height) {
                    position = 'top';
                }
            }
    
            if (position === 'top') {
                // If guide would go off the top of the screen, make sure it doesn't
                // This also acts as a fall-through for the above conditional - the tooltip
                // causing the document to become longer than normal is better than having
                // the guide off the top of the screen, where it can't be dismissed
                if(elementPosition.top - tooltipDimensions.height < 0) {
                    position = 'bottom';
                }
            }
    
            if (offscreenBottom && offscreenTop) {
                if (tooltipDimensions.hbias !== 'center') position = tooltipDimensions.hbias;
                // Only set left/right if at least one of them is on the screen.
                // Otherwise leave its position set as described in the above two comments
                if (!offscreenLeft || !offscreenRight) {
                    if (!offscreenRight) position = 'right';
                    if (!offscreenLeft) position = 'left';
                }
            }
    
            if ((!position || position === 'bottom') && offscreenBottom && !offscreenTop) {
                position = 'top';
            }
    
            if(position) return position;
            return tooltipDimensions.hbias ? tooltipDimensions.hbias : 'bottom';
        }
    
        function positionBBTooltipWithBias(tooltipDimensions, elementPosition, screenDimensions) {
            if (tooltipDimensions.layoutDir === 'top' || tooltipDimensions.layoutDir === 'bottom') {
                return calculateToolTipPositionForTopBottom(tooltipDimensions, screenDimensions, elementPosition, tooltipDimensions.layoutDir, tooltipDimensions.hbias);
            }
    
            return calculateToolTipPositionForLeftRight(tooltipDimensions, elementPosition, tooltipDimensions.hbias);
        }
    
        function calculateToolTipPositionForTopBottom(tooltipDimensions, screenDimensions, elementPosition, layoutDirection, horizontalBias) {
    
            var height = tooltipDimensions.height;
            var width = tooltipDimensions.width;
            var tooltipPosition = {
                'top':  null,
                'left': null
            };
    
            if (layoutDirection === 'bottom') {
                tooltipPosition.top = elementPosition.top + elementPosition.height;
            } else if (layoutDirection === 'top') {
                tooltipPosition.top = elementPosition.top - height;
            }
    
            if(horizontalBias === 'right') {
                var leftVal = elementPosition.left + (elementPosition.width / 2);
                if(leftVal + tooltipDimensions.width > screenDimensions.width) {
                    leftVal -= (leftVal + tooltipDimensions.width - screenDimensions.width);
                }
                tooltipPosition.left = leftVal;
            } else if(horizontalBias === 'left') {
                tooltipPosition.left = elementPosition.left - width + (elementPosition.width / 2);
            } else {
                // ASSUME CENTER
                tooltipPosition.left = elementPosition.left + (elementPosition.width / 2) - (width / 2);
            }
    
            return tooltipPosition;
        }
    
        function calculateToolTipPositionForLeftRight(tooltipDimensions, elementPosition, horizontalBias) {
            var height = tooltipDimensions.height;
            var width = tooltipDimensions.width;
    
            var tooltipPosition = {
                'top':  null,
                'left': null
            };
    
            tooltipPosition.top = elementPosition.top - (height / 2) + (elementPosition.height / 2);
            if (tooltipDimensions.layoutDir === 'right') {
                tooltipPosition.left = elementPosition.left + elementPosition.width;
            } else if (tooltipDimensions.layoutDir === 'left') {
                // this keeps the guide visible.
                tooltipPosition.left = Math.max(0, elementPosition.left - width);
            }
    
            return tooltipPosition;
        }
    
        function buildTooltipCaret(tooltipDiv, tooltipDimensions, caretDimensions) {
            var caretDiv = document.createElement('div');
            caretDiv.setAttribute('class', 'pendo-tooltip-caret');
            caretDiv.style.position = 'absolute';
            caretDiv.style.zIndex = 11;
            if(tooltipDimensions.layoutDir === 'top' || tooltipDimensions.layoutDir === 'bottom') {
                styleTopOrBottomCaret(caretDiv, tooltipDiv, tooltipDimensions, caretDimensions);
            }
    
            if(tooltipDimensions.layoutDir === 'left' || tooltipDimensions.layoutDir === 'right') {
                styleLeftOrRightCaret(caretDiv, tooltipDiv, tooltipDimensions, caretDimensions);
            }
    
    
            var guideDiv = tooltipDiv.find('#pendo-guide-container')[0].parentNode;
            guideDiv.appendChild(caretDiv);
    
            if(!caretDimensions.borderWidth) return;
    
            var borderCaret = buildBorderCaret(caretDiv, caretDimensions, tooltipDimensions.layoutDir);
    
            guideDiv.appendChild(borderCaret);
        }
    
        function styleTopOrBottomCaret(caret, tooltipDiv, tooltipDimensions, caretDimensions) {
            var screenDimensions = pendo._get_screen_dim();
    
            caret.style['border-left'] = caretDimensions.width + 'px solid transparent';
            caret.style['border-right'] = caretDimensions.width + 'px solid transparent';
    
            if(tooltipDimensions.hbias === 'left') {
                var maxArrowLeft = tooltipDimensions.width - caretDimensions.width * 2 - caretDimensions.offset - caretDimensions.borderWidth;
                caret.style.left = maxArrowLeft + 'px';
                tooltipDimensions.left += caretDimensions.offset + caretDimensions.width + caretDimensions.borderWidth;
            } else if(tooltipDimensions.hbias === 'right') {
                caret.style.left = (caretDimensions.offset + caretDimensions.borderWidth) + 'px';
                tooltipDimensions.left -= caretDimensions.offset + caretDimensions.width + caretDimensions.borderWidth;
                if(tooltipDimensions.left + tooltipDimensions.width > screenDimensions.width) {
                    tooltipDimensions.left = tooltipDimensions.left - (tooltipDimensions.left + tooltipDimensions.width - screenDimensions.width);
                }
                tooltipDimensions.left = Math.max(0, tooltipDimensions.left);
            } else { // ASSUME CENTER
                caret.style.left = (tooltipDimensions.width / 2) - caretDimensions.width + 'px';
            }
    
            // Tooltip is below element, put caret on the top of the tooltip
            if(tooltipDimensions.layoutDir === 'bottom') {
                caret.style['border-bottom'] = caretDimensions.height + 'px solid ' + caretDimensions.backgroundColor;
                var caretTop = -1 * caretDimensions.height;
                if (caretDimensions.borderWidth) {
                    caretTop = caretTop + caretDimensions.borderWidth;
                }
                caret.style.top = caretTop + 'px';
            }
    
            // Tooltip is above element, put caret on the bottom of the tooltip
            if(tooltipDimensions.layoutDir === 'top') {
                caret.style['border-top'] = caretDimensions.height + 'px solid ' + caretDimensions.backgroundColor;
                var caretBottom = -1 * caretDimensions.height;
                if (caretDimensions.borderWidth) {
                    caretBottom = caretBottom + caretDimensions.borderWidth;
                }
                caret.style.bottom = caretBottom + 'px';
            }
    
            return caret;
        }
    
        function styleLeftOrRightCaret(caret, tooltipDiv, tooltipDimensions, caretDimensions) {
            caret.style['border-top'] = caretDimensions.width + 'px solid transparent';
            caret.style['border-bottom'] = caretDimensions.width + 'px solid transparent';
            caret.style.top = (tooltipDimensions.height / 2) - caretDimensions.width + 'px';
    
            // Tooltip is to the left of the element, put caret on the right of the tooltip
            if(tooltipDimensions.layoutDir === 'left') {
                caret.style['border-left'] = caretDimensions.height + 'px solid ' + caretDimensions.backgroundColor;
                var caretRight = -1 * caretDimensions.height;
                if (caretDimensions.borderWidth) {
                    caretRight = caretRight + caretDimensions.borderWidth;
                }
                caret.style.right = caretRight + 'px';
            }
    
            // Tooltip is to the right of the element, put caret on the left of the tooltip
            if(tooltipDimensions.layoutDir === 'right') {
                caret.style['border-right'] = caretDimensions.height + 'px solid ' + caretDimensions.backgroundColor;
                var caretLeft = -1 * caretDimensions.height;
                if (caretDimensions.borderWidth) {
                    caretLeft = caretLeft + caretDimensions.borderWidth;
                }
                caret.style.left = caretLeft + 'px';
            }
    
            return caret;
        }
    
        function buildBorderCaret(caret, caretDimensions, tooltipLayoutDirection) {
            var borderCaret = caret.cloneNode();
            borderCaret.setAttribute('class', 'pendo-tooltip-caret-border');
            borderCaret.style.zIndex = 10;
            var borderDirections = ['Top', 'Right', 'Bottom', 'Left'];
    
            for(var i = 0; i < borderDirections.length; i++) {
                var borderWidthKey = 'border' + borderDirections[i] + 'Width'; // borderTopWidth, etc
                var borderColorKey = 'border' + borderDirections[i] + 'Color'; // borderTopColor, etc
    
                if(borderCaret.style[borderWidthKey]) {
                    borderCaret.style[borderWidthKey] = parseInt(borderCaret.style[borderWidthKey], 10) + caretDimensions.borderWidth + 'px';
                    borderCaret.style[borderColorKey] = determineBorderCaretColor(borderCaret.style[borderColorKey], caretDimensions.borderColor);
                }
            }
    
            // Tooltip is above element, border moves further down
            if(tooltipLayoutDirection === 'top') {
                borderCaret.style.left = parseInt(borderCaret.style.left, 10) - caretDimensions.borderWidth + 'px';
                borderCaret.style.bottom = parseInt(borderCaret.style.bottom, 10) - caretDimensions.borderWidth + 'px';
            }
    
            // Tooltip is below element, border moves further up
            if(tooltipLayoutDirection === 'bottom') {
                borderCaret.style.left = parseInt(borderCaret.style.left, 10) - caretDimensions.borderWidth + 'px';
                borderCaret.style.top = parseInt(borderCaret.style.top, 10) - caretDimensions.borderWidth + 'px';
            }
    
            // Tooltip is to the right of the element, border moves further left
            if(tooltipLayoutDirection === 'right') {
                borderCaret.style.top = parseInt(borderCaret.style.top, 10) - caretDimensions.borderWidth + 'px';
                borderCaret.style.left = parseInt(borderCaret.style.left, 10) - caretDimensions.borderWidth + 'px';
            }
    
            // Tooltip is to the left of the element, border moves further right
            if(tooltipLayoutDirection === 'left') {
                borderCaret.style.top = parseInt(borderCaret.style.top, 10) - caretDimensions.borderWidth + 'px';
                borderCaret.style.right = parseInt(borderCaret.style.right, 10) - caretDimensions.borderWidth + 'px';
            }
    
            return borderCaret;
        }
    
        function determineBorderCaretColor(currentColor, borderColor) {
            if(currentColor === 'transparent') return currentColor;
    
            return borderColor;
        }
    
        function placeBBTooltip(step, guideContainer) {
            if (!guideContainer) return;
            var element = getElementForGuideStep(step);
            var elPos = getOffsetPosition(element);
            // has the elPos changed?
            if (!checkPlacementChanged(elPos) || getComputedStyle_safe(step.elements[0]).display === 'none') return;
    
            var layoutDir = step.attributes.layoutDir;
            var ttdiv = step.guideElement;
            var ttContainer = dom(guideContainer).find('#pendo-guide-container');
            var ttContainerStyles = ttContainer[0].style;
            var tooltipSizes = {
                'height': guideContainer.offsetHeight,
                'width':  guideContainer.offsetWidth
            };
            var caretStyles = {
                'height':          parseInt(ttContainer[0].getAttribute('data-caret-height'), 10) || 0,
                'width':           parseInt(ttContainer[0].getAttribute('data-caret-width'), 10) || 0,
                'backgroundColor': ttContainer[0].style['background-color'],
                'offset':          10,
                'borderColor':     ttContainerStyles.borderColor,
                'borderWidth':     parseInt(ttContainerStyles.borderWidth, 10)
            };
    
            var tooltipDimensions = this.getBBTooltipDimensions(elPos, tooltipSizes, caretStyles, layoutDir);
    
            if (caretStyles.height && caretStyles.width) {
                this.buildTooltipCaret(ttdiv, tooltipDimensions, caretStyles);
            }
    
            // we can update the tooltipDimensions.top and tooltipDimensions.left now
            ttdiv.css({
                'top':      tooltipDimensions.top,
                'left':     tooltipDimensions.left,
                'position': elPos.fixed ? 'fixed' : ttdiv[0].style.position
            });
    
            // remove old carets that are in the wrong position
            pendo.dom(ttdiv.find('.pendo-tooltip-caret')[0]).remove();
            pendo.dom(ttdiv.find('.pendo-tooltip-caret-border')[0]).remove();
        }
    
        function onscroll(step, scrollParent, overflowPattern) {
            var elementRect = getClientRect(step.element);
            if (isVisibleInScrollParent(elementRect, scrollParent, overflowPattern)) {
                // Scroll position updates go here!!
                // show step if element is in view
                dom(step.elements[0]).css({'display': 'block'});
            } else {
                //Hide if element is scrolled out of view
                dom(step.elements[0]).css({'display': 'none'});
            }
        }
    })();
    
    var BuildingBlockGuides = (function() {
        return {
            'renderGuideFromJSON':             renderGuideFromJSON,
            'buildNodeFromJSON':               buildNodeFromJSON,
            'recalculateGuideHeightOnImgLoad': recalculateGuideHeightOnImgLoad,
            'buildStyleString':                buildStyleString,
            'buildStyleTagContent':            buildStyleTagContent,
            'bindActionToNode':                bindActionToNode,
            'recalculateGuideHeight':          recalculateGuideHeight,
            'findDomBlockInDomJson':           findDomBlockInDomJson,
            'isElementHiddenInGuide':          isElementHiddenInGuide,
            'positionStepForTooltip':          positionStepForTooltip,
            'flexAllThings':                   flexAllThings,
            'flexElement':                     flexElement,
            'findTopLevelContainer':           findTopLevelContainer,
            'updateBackdrop':                  updateBackdrop,
            'buildNodesFromJSON':              buildNodesFromJSON,
            'findGuideContainerJSON':          findGuideContainerJSON,
            'maintainAspectRatios':            maintainAspectRatios,
            'sizeElement':                     sizeElement
        };
    
        function findGuideContainerJSON(buildingBlocks) {
            if (buildingBlocks.props && buildingBlocks.props.id && buildingBlocks.props.id.indexOf('pendo-g-') === 0) {
                return buildingBlocks;
            }
    
            if (buildingBlocks.children) {
                return _.find(buildingBlocks.children, function(child) {
                    return findGuideContainerJSON(child);
                });
            }
        }
    
        function sizeElement(targetEle, containerEle) {
            var allParentChildren = targetEle.parentNode.children;
            var heightOfSiblings = 0;
            for(var i = 0; i < allParentChildren.length; i++) {
                if(allParentChildren[i] === targetEle) continue;
    
                heightOfSiblings += allParentChildren[i].offsetHeight;
            }
            var containerHeight = containerEle.offsetHeight;
            var fillHeight = Math.max(containerHeight - heightOfSiblings, 0);
            targetEle.style.height = fillHeight + 'px';
        }
    
        function renderGuideFromJSON(json, step, guides) {
            var containerJSON = BuildingBlockGuides.findGuideContainerJSON(json);
            var guide = step.getGuide();
    
            var isResourceCenter = get(guide, 'attributes.resourceCenter');
            var isFullyCustomResourceCenter = isResourceCenter && get(guide, 'attributes.resourceCenter.moduleId') === 'FullyCustomModule';
    
            step.hasEscapeListener = false;
            step.containerId = containerJSON && containerJSON.props && containerJSON.props.id;
            step.element = getElementForGuideStep(step);
            var guideToAppend = BuildingBlockGuides.buildNodeFromJSON(json, step, guides);
            step.guideElement = guideToAppend;
            var guideContainer = guideToAppend.find('#' + step.containerId);
    
            var verticalAlignmentAttr = 'data-vertical-alignment';
            var relativeToElement = guideContainer.attr(verticalAlignmentAttr) === 'Relative to Element';
    
            if (relativeToElement && !isResourceCenter) {
                pendo.dom(step.guideElement).css({
                    'overflow': 'hidden',
                    'height':   '0',
                    'width':    '0'
                });
            }
    
            // In the wild, we should start with a guide hidden, so we can ensure we correctly
            // position and calculate its height before making it visible. In the designer,
            // however, this isn't an issue, as we're not dealing with async loading of content.
            // In the designer, changing visibility like this causes the guide to "flicker"
            // between re-renders
            if(!pendo.designer) {
                guideContainer.css({ 'visibility': 'hidden' });
            }
    
            var watermark = BuildingBlockWatermark.buildWatermark({
                'targetAccount':   guide.targetAccount,
                'isBottomAligned': guideContainer.attr(verticalAlignmentAttr) === 'Bottom Aligned'
            }, BuildingBlockGuides.buildNodeFromJSON);
    
            if (watermark) {
                guideContainer.append(watermark);
            }
    
            var hasImageCount = step && step.attributes && step.attributes.imgCount;
    
            // Do conditional Guide Rendering Things
            guideToAppend.appendTo(getGuideAttachPoint());
    
            var targetEle = guideContainer.find('[data-pendo-grow-height="true"]')[0];
            if (targetEle) {
                sizeElement(targetEle, guideToAppend[0]);
            }
    
            // Guide Alignment
            flexAllThings(step.containerId);
            if (!isFullyCustomResourceCenter) {
                BuildingBlockGuides.recalculateGuideHeight(step.containerId);
            }
    
            // Tooltip
            if(relativeToElement) {
                step.attributes.calculatedType = 'tooltip';
            } else {
                BuildingBlockTooltips.attachBBAdvanceActions(step);
            }
    
            if (relativeToElement && !hasImageCount) {
                positionStepForTooltip(step, json, guideContainer[0]);
            }
    
            if(isResourceCenter) {
                BuildingBlockResourceCenter.showHomeViewOrEmptyState(guide);
            }
    
            if (!hasImageCount) {
                guideContainer.css({ 'visibility': 'visible' });
            }
    
            step.elements.push(step.guideElement[0]);
    
            if (get(step, 'attributes.isAutoFocus') && !pendo.designer) {
                dom(guideContainer).find('#pendo-guide-container').focus();
            }
    
            return guideToAppend;
        }
    
        function buildNodesFromJSON(json, step, guides) {
            if (json && json.templateName) {
                return BuildingBlockTemplates.buildNodesFromTemplate(json.templateName, json, step, guides);
            }
            return [buildNodeFromJSON(json, step, guides)];
        }
    
        function buildNodeFromJSON(json, step, guides) {
            var curNode = pendo.dom('<' + json.type + '></' + json.type + '>');
            var id = json.props && json.props.id;
    
            // This builds the 4pc backdrop to allow block clicking for any guide without changing how the backdrop is saved
            if (id === 'pendo-backdrop') {
                if (step.attributes && step.attributes.blockOutUI && step.attributes.blockOutUI.enabled) {
                    // Scroll listener to try and move the block click backdrop every 25ms, looks way better
                    var scrollHander = _.throttle(_.partial(updateBackdrop, step), 25);
                    step.attachEvent(window, 'scroll', scrollHander, true);
                }
    
                return buildBackdrop(step);
            }
    
            _.each(json.props, function(propValue, propKey) {
                if (propKey === 'style') {
                    curNode.css(json.props.style);
                } else if (propKey === 'data-pendo-code-block' && propValue === true && !getPendoConfigValue('preventCodeInjection')) {
                    curNode.addClass('pendo-code-block').html(step.getContent());
                } else {
                    curNode.attr(propKey, propValue);
                }
            });
    
            if (json.content) {
                curNode.text(json.content);
            }
    
            if (json.type === 'style') {
                // TODO: make this render building-block pseudo-styles properly for IE7-8. This current functionality allows guides to render in IE but there are lots of styling problems.
                // `curNode.text` specifically breaks in IE8 since style tags text attributes are read only. From researching `node.styleSheet.cssText` is the correct way to do it.
                if (curNode.styleSheet) {
                    curNode.styleSheet.cssText = BuildingBlockGuides.buildStyleTagContent(json.css);
                } else {
                    curNode.text(BuildingBlockGuides.buildStyleTagContent(json.css));
                }
            }
    
            if(json.svgWidgetId) {
                var svg = BuildingBlockSvgs.buildSvgNode(json.svgWidgetId, json);
                svg.appendTo(curNode);
            }
    
            var isBadge = json.props.id && json.props.id.indexOf('badge') !== -1;
    
            // Placeholder images don't have a src value
            // We don't want them to be a blocking factor in making the guide container visible to the end user
            // So, if there is no source, it will fall out of image node check below and not get a count.
            var curNodeHasSrc = !!json.props.src;
    
            if ((json.type === 'img' && curNodeHasSrc && !isBadge) || (json.type === 'iframe' && step)) {
                if (step.attributes && !step.attributes.imgCount) {
                    step.attributes.imgCount = 1;
                } else if (step.attributes && step.attributes.imgCount) {
                    step.attributes.imgCount++;
                }
    
    
                BuildingBlockGuides.recalculateGuideHeightOnImgLoad(curNode, step);
            }
    
            if (json.actions && json.actions.length) {
                for (var i = 0; i < json.actions.length; i++) {
                    BuildingBlockGuides.bindActionToNode(curNode, json.actions[i], step);
                    if (json.actions[i].action === 'renderGuidesListItem') {
                        var guide = pendo.findGuideById(json.actions[i].parameters[0]);
                        if (guide) {
                            curNode.text(guide.name);
                        } else {
                            curNode.attr('style', 'display: none;');
                        }
                    }
                }
            }
    
            var hasDismissAction = _.find(json.actions, function(data) {
                return data.action === 'dismissGuide';
            });
    
            // Close guide with ESC key if dismiss action is option
            if (hasDismissAction && !step.hasEscapeListener) {
                step.hasEscapeListener = true;
                step.attachEvent(window, 'keyup', function(evt) {
                    if (evt.keyCode === 27) {
                        step.eventRouter.eventable.trigger('pendoEvent', { 'step': step, 'action': 'dismissGuide' });
                    }
                }, true);
            }
    
            if (json.children) {
                for (var j = 0; j < json.children.length; j++) {
                    var childNodes = BuildingBlockGuides.buildNodesFromJSON(json.children[j], step, guides);
                    _.each(childNodes, function(childNode) {
                        if (childNode) {
                            childNode.appendTo(curNode);
                        }
                    });
                }
            }
    
            return curNode;
        }
    
        function positionStepForTooltip(step, json, guideContainerEle) {
            // This directly modifies step.guideElement object
            BuildingBlockTooltips.createBBTooltip(json, step.element, step, guideContainerEle);
    
            if (!step.hasBeenScrolledTo) {
                scrollIntoView(step.element);
                scrollToTooltip(step.element, guideContainerEle, step.attributes.layoutDir);
                step.hasBeenScrolledTo = true;
            }
        }
    
        function recalculateGuideHeightOnImgLoad(node, step) {
            node.on('load', function() {
                var containerJSON = {};
                if (!step.containerId && step.domJson) {
                    containerJSON = findGuideContainerJSON(step.domJson);
                }
                var containerId = step.containerId || (containerJSON.props && containerJSON.props.id) || '';
    
                flexAllThings(containerId);
                recalculateGuideHeight(containerId);
    
                var guideContainer = document.getElementById(step.containerId);
    
                if (step && step.attributes && step.attributes.imgCount) {
                    step.attributes.imgCount--;
    
                    if (guideContainer && step.attributes.imgCount <= 0) {
                        guideContainer.style.visibility = 'visible';
    
                        if(step.attributes.calculatedType === 'tooltip') {
                            positionStepForTooltip(step, step.domJson, guideContainer);
                        }
                    }
                }
            });
    
            // For now, we'll just automatically show the guide if an image errors.
            node.on('error', function() {
                var guideContainer = document.getElementById(step.containerId);
                if (!guideContainer) {
                    log('Failed to find guideContainer for id: ' + step.containerId);
                    return;
                }
                guideContainer.style.visibility = 'visible';
            });
        }
    
        function bindActionToNode(node, actionObject, step) {
            node.on(actionObject.eventType, function(e) {
                if (actionObject.designerAction) {
                    // designerActions is injected by the agent-plugins from the designer
                    pendo.designerv2.designerActions[actionObject.action](node, actionObject.parameters);
                } else {
                    var eventData = {
                        'action':     actionObject.action,
                        'params':     actionObject.parameters,
                        'step':       step,
                        'ignore':     !!actionObject.ignore,
                        'srcElement': e.srcElement
                    };
    
                    if (actionObject.action === 'showElements' || actionObject.action === 'hideElements') {
                        // srcElement is for IE < 9
                        if (e.srcElement && e.srcElement.getAttribute('id') === actionObject.source) {
                            step.eventRouter.eventable.trigger('pendoEvent', eventData);
                        } else if (e.target && e.target.getAttribute('id') === actionObject.source) {
                            step.eventRouter.eventable.trigger('pendoEvent', eventData);
                        }
                    } else {
                        step.eventRouter.eventable.trigger('pendoEvent', eventData);
                    }
                }
            });
        }
    
        function buildStyleString(styleObject) {
            var styleString = '';
    
            _.each(styleObject, function(styleValue, styleKey) {
                styleString = styleString + styleKey + ':' + styleValue + ';';
            });
    
            return styleString;
        }
    
        function buildStyleTagContent(css) {
            var styleContentString = '';
            for (var i = 0; i < css.length; i++) {
                styleContentString += css[i].selector + '{';
    
                _.each(css[i].styles, function(styleValue, styleKey) {
                    styleContentString += styleKey + ':' + styleValue;
                    styleContentString += '!important;';
                });
    
                styleContentString += '}';
            }
            return styleContentString;
        }
    
        function findTopLevelContainer(guideEle) {
            var possibleContainerIds = ['pendo-base', 'pendo-resource-center-container'];
            for(var i = 0; i < 20; i++) {
                var foundMatch = _.find(possibleContainerIds, function(id) {
                    return guideEle.id === id;
                });
    
                if(foundMatch) return guideEle;
    
                if(guideEle === document.body) return document.body;
    
                if(guideEle.parentNode) {
                    guideEle = guideEle.parentNode;
                }
            }
    
            // return body as a last-resort
            return document.body;
        }
    
        function flexElement(ele) {
            var flexRows = Sizzle('[data-pendo-display-flex]', ele);
    
            _.each(flexRows, function(row) {
                var flexRow = FlexboxPolyfill.initializeFlexboxContainer(row);
                var flexType = row.getAttribute('data-pendo-justify-content');
                FlexboxPolyfill.justifyContent(flexRow, flexType);
            });
        }
    
        function flexAllThings(containerId) {
            var guideContainer = document.getElementById(containerId);
    
            if (!guideContainer) return;
    
            BuildingBlockGuides.flexElement(guideContainer);
            maintainAspectRatios(guideContainer);
        }
    
        function maintainAspectRatios(ele) {
            var dataAspectRatio = 'data-aspect-ratio';
            var elements = Sizzle('[' + dataAspectRatio + ']', ele);
    
            _.each(elements, function(element) {
                var dimensions = element.getAttribute(dataAspectRatio).split(':');
                var ratio;
                if (dimensions.length > 1) {
                    ratio = parseInt(dimensions[0], 10) / parseInt(dimensions[1], 10);
                } else {
                    ratio = parseFloat(dimensions[0]);
                }
                if (isNaN(ratio)) return;
                element.style.height = (element.offsetWidth / ratio) + 'px';
            });
        }
    
        function isElementHiddenInGuide(ele) {
            isSingleElementHidden(ele);
    
            var clientRect = getClientRect(ele);
            // Check if the element has no client width/height
            if (clientRect.width === 0 || clientRect.height === 0) return true;
    
            // Child visibility can override parent visibility, so if this element specifically
            // is visible, we don't need to check the parent
            if(ele.style && ele.style.visibility === 'visible') return false;
    
            var elePointer = ele;
            var eleId = ele.id || '';
            var numberOfIterations = 0;
    
            while(eleId.indexOf('pendo-g-') !== 0) {
                isSingleElementHidden(elePointer);
    
                elePointer = elePointer.parentNode;
                eleId = elePointer.id || '';
    
                // safety check to ensure we don't get stuck in an endless loop
                numberOfIterations++;
                if(numberOfIterations > 10) {
                    break;
                }
            }
    
            return false;
        }
    
        function isSingleElementHidden(ele) {
            if(ele.style && ele.style.display === 'none') return true;
            if(ele.style && ele.style.opacity === '0') return true;
            if(ele.style && ele.style.visibility === 'hidden') return true;
    
            return false;
        }
    
        function recalculateGuideHeight(containerId) {
            var guideContainer = document.getElementById(containerId);
            if (!guideContainer) return;
    
            var styleHeight = parseInt(guideContainer.style.height, 10);
    
            var previousHeightVal = guideContainer.style.height;
            pendo.dom(guideContainer).css({ 'height': 'auto' });
            var computedHeight = parseInt(getComputedStyle_safe(guideContainer).height, 10);
            var staticHeightAtt = guideContainer.getAttribute('data-pendo-static-height');
    
            if (computedHeight > window.innerHeight) {
                var pendoGuideContainer = dom(guideContainer).find('#pendo-guide-container')[0];
                pendo.dom(pendoGuideContainer).css({
                    'max-height': '100vh',
                    'overflow':   'auto'
                });
            }
    
            if (computedHeight !== styleHeight) {
                var height = computedHeight;
                if (staticHeightAtt && styleHeight) height = styleHeight;
    
                pendo.dom(guideContainer).css({ 'height': '' + height + 'px' });
    
                var verticalAlignment = guideContainer.getAttribute('data-vertical-alignment');
    
                if (verticalAlignment === 'Centered') {
                    var guideMargin = (computedHeight > window.innerHeight) ? window.innerHeight : height;
                    pendo.dom(guideContainer).css({ 'margin-top': '-' + (guideMargin / 2) + 'px' });
                }
            } else {
                pendo.dom(guideContainer).css({ 'height': previousHeightVal });
            }
        }
    
        function findDomBlockInDomJson(domJson, truthTestFn) {
            if(truthTestFn(domJson)) return domJson;
    
            if(!domJson.children) return false;
    
            for(var i = 0; i < domJson.children.length; i++) {
                var childMatch = findDomBlockInDomJson(domJson.children[i], truthTestFn);
    
                if(childMatch) return childMatch;
            }
    
            return false;
        }
    
        function buildBackdrop(step) {
            try {
                var config = step.attributes.blockOutUI || {};
                config.additionalElements = config.additionalElements || '';
                var targetAreaElements = [];
                if (config.enabled && step.element !== getBody()) {
                    targetAreaElements.push(step.element);
    
                    var additionalElementsSelectors = config.additionalElements.replace(/\s/g,'').split(',');
                    for (var i = 0; i < config.additionalElements.length; i++) {
                        try {
                            var results = Sizzle(additionalElementsSelectors[i]);
                            if (results) {
                                _.each(results, function(result) {
                                    targetAreaElements.push(result);
                                });
                            }
                        } catch (e) {
                            log('Additional element for blockOutUI is invalid selector', 'error');
                        }
                    }
                }
    
                var box = computeBBBlockOutBoundingBox(targetAreaElements);
                var padding = config.padding || {'left': 0, 'right': 0, 'top': 0, 'bottom': 0};
    
                var bodySize = getClientRect(getBody());
                // If there is no element, pretend like the element has 0 size and is in the top left corner
                // This should produce a right block the size of the body
                if (!box) {
                    box = {
                        'top':    0,
                        'left':   0,
                        'right':  bodySize.width,
                        'bottom': bodySize.height,
                        'width':  0,
                        'height': 0
                    };
                }
    
                if (box.fixed) {
                    bodySize.top = 0;
                    bodySize.bottom = bodySize.height;
                    bodySize.left = 0;
                    bodySize.right = bodySize.width;
                }
    
                // build the block out regions for Top, Bottom, Left, Right
                var coords = computeBBBlockOutOverlayPositions(bodySize, box, padding);
    
                // has box specs changed?  if not, don't redraw
                if (!hasBlockBoxChanged(box) &&
                    !hasBodyDimensionsChanged(bodySize) &&
                    !haveScreenCoordsChanged(coords) &&
                    blockBoxIsRendered()) {
                    return;
                }
    
                var defaults = {
                    'z-index':  10000,
                    'position': 'fixed'
                };
    
                var backdrops = [];
                _.each(coords, function(overlay, direction) {
                    var backdrop = buildBBBackdropDiv(direction, _.extend({}, overlay, defaults));
                    backdrops.push(backdrop);
                });
                return addStylesToBackdrops(backdrops, step);
            } catch (e) {
                log('Failed to add BlockOut ui', 'error');
            }
        }
    
        function computeBBBlockOutBoundingBox(elements) {
            if (!elements || !elements.length) return;
            var box = _.reduce(elements, function(box, elem) {
                if (!isElementVisible(elem)) return box;
    
                var rect = getClientRect(elem);
                if (!rect) return;
    
                box.fixed = box.fixed && rect.fixed;
    
                // While reducing all of the elements ensure we are never outside of the client rectangle
                _.each([
                    ['top', isLessThan],
                    ['right', isGreaterThan],
                    ['bottom', isGreaterThan],
                    ['left', isLessThan]
                ], function(dirTup) {
                    var dir = dirTup[0];
                    var op = dirTup[1];
    
                    if (!box[dir] || op(rect[dir], box[dir])) {
                        box[dir] = rect[dir];
                    }
                });
    
                return box;
            }, {
                'fixed': true
            });
    
            box.height = box.bottom - box.top;
            box.width = box.right - box.left;
    
            // Undo the body offset, if not fixed
            var offset = bodyOffset();
            if (!box.fixed) {
                box.left += offset.left;
                box.right += offset.left;
                box.top += offset.top;
                box.bottom += offset.top;
            }
    
            box.fixed = !!box.fixed;
    
            return box;
        }
    
        function buildBBBackdropDiv(direction, styles) {
            var div = dom('div._pendo-guide-backdrop-region-block_._pendo-region-' + direction + '_');
    
            if (!div.length) {
                div = dom('<div class="_pendo-guide-backdrop-region-block_ _pendo-region-' + direction + '_"></div>');
            }
    
            dom(div).css(styles);
    
            return div;
        }
    
        function blockBoxIsRendered() {
            var regions = dom('._pendo-guide-backdrop_');
            return regions.length > 0;
        }
    
        function computeBBBlockOutOverlayPositions(bodySize, blockOutBoundingBox, padding) {
            var blockOutBoundingBoxWithOffset = {};
    
            var adjustedTop = blockOutBoundingBox.top - bodySize.top;
            var adjustedLeft = blockOutBoundingBox.left - bodySize.left;
    
            blockOutBoundingBoxWithOffset.top = adjustedTop - padding.top;
            blockOutBoundingBoxWithOffset.left = adjustedLeft - padding.left;
    
            blockOutBoundingBoxWithOffset.height = blockOutBoundingBox.height + padding.top + padding.bottom;
            blockOutBoundingBoxWithOffset.width = blockOutBoundingBox.width + padding.left + padding.right;
    
            var offset = { 'left': 0, 'top': 0 };
            if (positionFixedActsLikePositionAbsolute()) {
                offset = bodyOffset();
                blockOutBoundingBoxWithOffset.left += documentScrollLeft();
                blockOutBoundingBoxWithOffset.top += documentScrollTop();
            }
    
            blockOutBoundingBoxWithOffset.bottom = blockOutBoundingBoxWithOffset.top + blockOutBoundingBoxWithOffset.height;
            blockOutBoundingBoxWithOffset.right = blockOutBoundingBoxWithOffset.left + blockOutBoundingBoxWithOffset.width;
    
            return {
                'top': {
                    'top':    0,
                    'height': Math.max(blockOutBoundingBoxWithOffset.top - offset.top, 0),
                    'left':   blockOutBoundingBoxWithOffset.left,
                    'width':  blockOutBoundingBoxWithOffset.width
                },
                'right': {
                    'top':    -offset.top,
                    'bottom': 0,
                    'left':   blockOutBoundingBoxWithOffset.right - offset.left,
                    'right':  0
                },
                'bottom': {
                    'top':    blockOutBoundingBoxWithOffset.bottom - offset.top,
                    'bottom': 0,
                    'left':   blockOutBoundingBoxWithOffset.left - offset.left,
                    'width':  blockOutBoundingBoxWithOffset.width
                },
                'left': {
                    'top':    -offset.top,
                    'bottom': 0,
                    'left':   -offset.left,
                    'width':  blockOutBoundingBoxWithOffset.left
                }
            };
        }
    
        function addStylesToBackdrops(backdrops, step) {
            var originalBackdrop = findBlockById('pendo-backdrop', step.domJson);
    
            delete originalBackdrop.props.style.left;
            delete originalBackdrop.props.style.right;
            delete originalBackdrop.props.style.width;
            delete originalBackdrop.props.style.height;
            delete originalBackdrop.props.style.bottom;
            delete originalBackdrop.props.style.top;
    
            var backdropContainer = pendo.dom('<div class="_pendo-guide-backdrop_">');
            backdropContainer.attr('class', '_pendo-guide-backdrop_');
            _.each(originalBackdrop.props, function(propValue, propKey) {
                _.each(backdrops, function(backdrop) {
                    if (propKey === 'style') {
                        backdrop.css(originalBackdrop.props.style);
                    } else {
                        backdrop.attr(propKey, propValue);
                    }
    
                    backdropContainer.append(backdrop);
                });
            });
    
            return backdropContainer;
        }
    
        function findBlockById(id, json) {
            if (json.props && json.props.id === id) return json;
    
            if (json.children) {
                for (var i = 0; i < json.children.length; i++) {
                    var block = findBlockById(id, json.children[i]);
                    if (block) return block;
                }
            }
        }
    
        function updateBackdrop(step) {
            var backdrop = buildBackdrop(step);
            if (backdrop) {
                dom('._pendo-guide-backdrop_').remove();
                step.guideElement.append(backdrop);
            }
        }
    
    })();
    
    var BuildingBlockResourceCenter = (function() {
        return {
            'initializeResourceCenter':                   initializeResourceCenter,
            'findResourceCenterHomeView':                 findResourceCenterHomeView,
            'findResourceCenterModules':                  findResourceCenterModules,
            'replaceResourceCenterContent':               replaceResourceCenterContent,
            'showHomeViewOrEmptyState':                   showHomeViewOrEmptyState,
            'showResourceCenterEmptyState':               showResourceCenterEmptyState,
            'launchIntegrationByNameAndProvider':         launchIntegrationByNameAndProvider,
            'appendIntegrationToBodyByNameAndProvider':   appendIntegrationToBodyByNameAndProvider,
            'attemptToPreserveIntegrationIframes':        attemptToPreserveIntegrationIframes,
            'getResourceCenter':                          getResourceCenter,
            'addNotificationBubbleToResourceCenterBadge': addNotificationBubbleToResourceCenterBadge,
            'addNotificationBubbleToTargetElement':       addNotificationBubbleToTargetElement,
            'updateNotificationBubbles':                  updateNotificationBubbles,
            'removeNotificationBubble':                   removeNotificationBubble,
            'updateNotificationBubbleCount':              updateNotificationBubbleCount,
            'updateNotificationBubbleOnHomeView':         updateNotificationBubbleOnHomeView,
            'updateOrCreateNotificationBubble':           updateOrCreateNotificationBubble,
            'hexToRgb':                                   hexToRgb,
            'doesIntegrationExist':                       doesIntegrationExist,
            'calculateTotalNotificationCount':            calculateTotalNotificationCount,
            'updateNotificationBubblesOnHomeView':        updateNotificationBubblesOnHomeView,
            'createNotification':                         createNotification,
            'appendNotificationBubble':                   appendNotificationBubble,
            'hasAnnouncementBeenSeen':                    hasAnnouncementBeenSeen,
            'clearAnnouncementUnseenInterval':            clearAnnouncementUnseenInterval,
            'createAnnouncementUnseenInterval':           createAnnouncementUnseenInterval
        };
    
        var resourceCenter;
        var announcementUnseenInterval;
    
        function initializeResourceCenter(guideList) {
            resourceCenter = findResourceCenterHomeView(guideList);
            if(!resourceCenter) return q.resolve();
            if (FrameController.isShownInAnotherFrame(resourceCenter.steps[0])) return q.resolve();
    
            var isFullyCustomRC = resourceCenter.attributes &&
                resourceCenter.attributes.resourceCenter &&
                resourceCenter.attributes.resourceCenter.moduleId &&
                resourceCenter.attributes.resourceCenter.moduleId === 'FullyCustomModule';
    
            if (isFullyCustomRC) {
                resourceCenter.hasResourceCenterContent = true;
                return q.resolve();
            }
    
            var resourceCenterModules = findResourceCenterModules(resourceCenter, guideList);
    
            var promises = _.reduce(resourceCenterModules, function(acc, module) {
                return acc.concat(module.steps[0].fetchContent());
            }, []);
    
            promises.push(ContentValidation.validate(resourceCenter).then(_.noop, function() {
                // prevent RC badge from displaying if content fails validation
                // (note that validate is a noop if content validation is not enabled)
                resourceCenter.launchMethod = 'api';
            }));
    
            // Notification bubble unseen counts
            // individualCounts is an object of all unseen counts - each announcements
            // module will store its unseen count here as guideId: unseenCount
            // totalUnseenCount is used to track the sum total of all unseen things, and
            // will update after all notification bubbles have been successfully updated
            resourceCenter.attributes.notifications = {
                'totalUnseenCount': 0,
                'individualCounts': {
                    'chat': 0
                }
            };
    
            _.forEach(resourceCenterModules, function(module) {
                var resourceCenterConfig = module.attributes.resourceCenter;
                var children = resourceCenterConfig.children;
                var moduleId = resourceCenterConfig.moduleId;
    
                // The sandbox module is considered to always have content
                if(moduleId === 'SandboxModule') module.hasResourceCenterContent = true;
                if(moduleId === 'IntegrationModule') {
                    module.integrationConfig = doesIntegrationExist(resourceCenterConfig.integrationName, resourceCenterConfig.integrationProvider);
                    module.hasResourceCenterContent = !!module.integrationConfig;
    
                    if (module.integrationConfig && module.integrationConfig.name === 'chat') {
                        appendIntegrationToBodyByNameAndProvider(resourceCenterConfig.integrationName, resourceCenterConfig.integrationProvider);
                    }
                }
    
                var childrenInPayload = _.reduce(children, function(acc, childGuideId) {
                    var inPayload = _.find(guideList, function(guide) {
                        return guide.id === childGuideId;
                    });
                    if(!inPayload) return acc;
    
                    return acc.concat(inPayload);
                }, []);
    
                if (moduleId === 'AnnouncementsModule') {
                    resourceCenter.attributes.notifications.individualCounts[module.id] = 0;
    
                    childrenInPayload.forEach(function(child) {
                        if(!hasAnnouncementBeenSeen(child)) {
                            resourceCenter.attributes.notifications.individualCounts[module.id]++;
                        }
    
                        promises.push(child.steps[0].fetchContent());
                    });
                }
    
                var moduleIdsWithChildren = ['GuideListModule', 'OnboardingModule', 'AnnouncementsModule'];
                if (moduleIdsWithChildren.indexOf(moduleId) > -1) {
                    var eligibleChildrenInPayload = _.filter(childrenInPayload, function(child) {
                        return child.shouldBeAddedToResourceCenter();
                    });
    
                    if (eligibleChildrenInPayload.length) module.hasResourceCenterContent = true;
                }
    
                // Assign all guides for a module on to the module
                module.guidesInModule = childrenInPayload;
            });
    
            // Assign all modules for the RC on to the RC
            resourceCenter.modules = resourceCenterModules;
    
            return q.all(promises);
        }
    
        function findResourceCenterHomeView(guideList) {
            var resourceCenters = _.filter(guideList, function(guide) {
                return guide &&
                    guide.attributes &&
                    guide.attributes.resourceCenter &&
                    guide.attributes.resourceCenter.isTopLevel;
            });
    
            var hasStagingRC = _.find(resourceCenters, function(rc) {
                return rc.state === 'staged';
            });
    
            var resourceCenterState = hasStagingRC ? 'staged' : 'public';
    
            return _.find(resourceCenters, function(guide) {
                return guide &&
                    guide.attributes &&
                    guide.attributes.resourceCenter &&
                    guide.attributes.resourceCenter.isTopLevel &&
                    guide.state === resourceCenterState;
            });
        }
    
        function findResourceCenterModules(resourceCenter, guideList) {
            return _.filter(guideList, function(guide) {
                return guide &&
                    get(guide, 'attributes.resourceCenter.isModule', false) &&
                    guide.state === resourceCenter.state;
            });
        }
    
        function replaceResourceCenterContent(guideIdToReplace, transitionParams, ignoreTransition) {
            var transitionCss = 'left 200ms';
            var transitionDirection = 'left';
    
            if(transitionParams) {
                transitionCss = transitionParams[0].value;
                transitionDirection = transitionParams[1].value;
            }
    
            var resourceCenterContainer = pendo.Sizzle('#pendo-resource-center-container')[0];
            if(!resourceCenterContainer) return;
            var currentlyRenderedGuide = pendo.dom(resourceCenterContainer).find('[id^="pendo-g-"]')[0];
            if(!currentlyRenderedGuide) return;
            var module = _.find(pendo.guides, function(guide) {
                return guide.id === guideIdToReplace;
            });
    
            if (guideIdToReplace !== resourceCenter.id) {
                // Do not mark Home View as an active module
                resourceCenter.activeModule = module;
            } else {
                // And if it is the home view, clear the active module
                delete resourceCenter.activeModule;
            }
    
            var step = module.steps[0];
            step.eventRouter = new EventRouter();
    
            var domJsonToRender = step.domJson;
            domJsonToRender.props['data-pendo-guide-id'] = module.id;
            var renderedGuide = BuildingBlockGuides.buildNodeFromJSON(domJsonToRender, step);
            step.guideElement = renderedGuide;
    
            var guideContainer = renderedGuide[0];
            if(guideContainer.id.indexOf('pendo-g-') === -1) {
                guideContainer = renderedGuide.find('[id^="pendo-g-"]')[0];
            }
    
            if (!ignoreTransition) {
                guideContainer.style.transition = transitionCss;
                currentlyRenderedGuide.style.transition = transitionCss;
    
                if (transitionDirection === 'left') {
                    guideContainer.style.left = resourceCenterContainer.offsetWidth + 'px';
                } else if (transitionDirection === 'right') {
                    guideContainer.style.left = -1 * resourceCenterContainer.offsetWidth + 'px';
                }
            }
    
            if (ignoreTransition) {
                pendo.dom(currentlyRenderedGuide).remove();
            }
    
            pendo.dom(guideContainer).appendTo(resourceCenterContainer);
    
            var elementToSize = pendo.dom(guideContainer).find('[data-pendo-grow-height="true"]')[0];
    
            if (elementToSize) {
                BuildingBlockGuides.sizeElement(elementToSize, resourceCenterContainer);
            }
    
            BuildingBlockGuides.flexElement(resourceCenterContainer);
            BuildingBlockGuides.recalculateGuideHeight(step.containerId);
    
            guideContainer.style.left = '0px';
    
            if (!ignoreTransition) {
                if (transitionDirection === 'left') {
                    currentlyRenderedGuide.style.left = -1 * resourceCenterContainer.offsetWidth + 'px';
                } else if (transitionDirection === 'right') {
                    currentlyRenderedGuide.style.left = resourceCenterContainer.offsetWidth + 'px';
                }
    
                window.setTimeout(function() {
                    pendo.dom(currentlyRenderedGuide).remove();
                }, 200);
            }
    
            var isAnnouncementModule = module.attributes.resourceCenter.moduleId === 'AnnouncementsModule';
            if(isAnnouncementModule) {
                createAnnouncementUnseenInterval();
            }
            // We don't want to go through `renderGuideFromJSON` because we're rendering multiple guides at
            // once, so we'll manually call the seen analytics hook
            step.onShown('launcher');
    
            return renderedGuide;
        }
    
        function clearAnnouncementUnseenInterval() {
            window.clearInterval(announcementUnseenInterval);
            announcementUnseenInterval = null;
        }
    
        function createAnnouncementUnseenInterval() {
            if(announcementUnseenInterval) return;
    
            announcementUnseenInterval = window.setInterval(function() {
                var resourceCenter = Sizzle('#pendo-resource-center-container');
                if(!resourceCenter.length) return clearAnnouncementUnseenInterval();
    
                var announcementsModule = pendo.dom(resourceCenter[0]).find('[data-layout="AnnouncementsModule"]');
                if(!announcementsModule.length) return clearAnnouncementUnseenInterval();
    
                var listContainer = pendo.dom(announcementsModule).find('ol[id^="pendo-list"]');
                if(!listContainer.length) return clearAnnouncementUnseenInterval();
    
                var listContainerRect = getClientRect(listContainer[0]);
                var listItems = pendo.dom(listContainer).find('li.pendo-unseen-announcement');
    
                if (!listItems.length) return clearAnnouncementUnseenInterval();
    
                var announcementModuleId = announcementsModule.attr('data-pendo-guide-id');
                var unseenCount = getResourceCenter().attributes.notifications.individualCounts[announcementModuleId];
    
                // We want an announcement to be partially in the viewport before we mark it seen
                // This offset will ensure an announcement is "unseen" until it occupies more than 33%
                // of the ol viewport
                var listContainerViewportOffset = listContainerRect.height / 3;
    
                var lastItemInListRect = getClientRect(listItems[listItems.length - 1]);
                // If the user has items that have small height values, we'll check to see if
                // they've scrolled to the bottom of the list, and if so mark everything as seen
                // We can't do this with el.scrollHeight because it isn't calculated correctly
                // in IE7 and IE8 :(
                var userHasScrolledToBottom = lastItemInListRect.bottom - 30 < listContainerRect.top + listContainerRect.height;
    
                for(var i = 0; i < listItems.length; i++) {
                    var announcement = listItems[i];
                    var announcementRect = getClientRect(announcement);
    
                    // As soon as we find an item that is still below the fold, exit the loop
                    var guideIsBelowFold = announcementRect.top - listContainerRect.top > listContainerRect.height - listContainerViewportOffset;
                    if(guideIsBelowFold && !userHasScrolledToBottom) {
                        break;
                    }
    
                    pendo.dom(announcement).removeClass('pendo-unseen-announcement');
                    var minibubble = pendo.dom(announcement).find('.pendo-unread-announcement-mini-bubble');
                    if(!isOldIE(10)) {
                        minibubble[0].style.visibility = 'hidden';
                        minibubble[0].style.opacity = '0';
                        minibubble[0].style.transition = 'visibility 0s 2s, opacity 2s linear';
                    } else {
                        pendo.dom(announcement).find('.pendo-unread-announcement-mini-bubble').remove();
                    }
                    var guideId = pendo.dom(announcement).attr('data-pendo-announcement-guide-id');
                    var announcementGuide = _.find(pendo.guides, function(guide) {
                        return guide.id === guideId;
                    });
    
                    if(!announcementGuide) break;
    
                    if(!hasAnnouncementBeenSeen(announcementGuide)) {
                        unseenCount--;
                    }
    
                    announcementGuide.steps[0].seenState = 'advanced';
                    seenGuide(announcementGuide.id, announcementGuide.steps[0].id, pendo.get_visitor_id(), 'whatsnew', announcementGuide.language);
                    advancedGuide(announcementGuide.id, announcementGuide.steps[0].id, pendo.get_visitor_id(), 'advanced', announcementGuide.language);
                }
    
                updateNotificationBubbleCount(unseenCount, announcementModuleId);
            }, 500);
        }
    
        function showHomeViewOrEmptyState(resourceCenter) {
            if (resourceCenter.hasResourceCenterContent && resourceCenter.skipResourceCenterHomeView) {
                BuildingBlockResourceCenter.replaceResourceCenterContent(resourceCenter.moduleIdToReplaceHomeViewWith, [{ 'value': 'none' }, { 'value': 'left' }]);
            } else if (resourceCenter.showEmptyState) {
                BuildingBlockResourceCenter.showResourceCenterEmptyState();
            }
        }
    
        function showResourceCenterEmptyState() {
            var resourceCenter = pendo.Sizzle('#pendo-resource-center-container');
            if(!resourceCenter || !resourceCenter.length) return;
    
            var emptyState = pendo.Sizzle('#pendo-resource-center-empty-state-container');
    
            if(!emptyState || !emptyState.length) return;
            pendo.dom(emptyState[0]).css({ 'display': 'block' });
        }
    
        function doesIntegrationExist(name, provider) {
            return ExtensionService.findExtensionByNameAndProvider(name, provider);
        }
    
        function launchIntegrationByNameAndProvider(name, provider, ele) {
            var integrationObj = ExtensionService.findExtensionByNameAndProvider(name, provider);
            if(!integrationObj) return log(provider + ' integration has not been loaded into the agent');
    
            var parentContainer = pendo.dom(ele);
            if(!parentContainer) return log('could not find target element for ' + provider + ' integration');
    
            var integrationIframe = integrationObj.getFrame();
    
            integrationIframe.appendTo(parentContainer);
            integrationIframe.css({ 'display': 'block' });
        }
    
        function appendIntegrationToBodyByNameAndProvider(name, provider) {
            var integrationObj = ExtensionService.findExtensionByNameAndProvider(name, provider);
            if(!integrationObj) return log(provider + ' integration has not been loaded into the agent');
    
            var integrationIframe = integrationObj.getFrame();
            if (!isInDocument(integrationIframe[0])) {
                integrationIframe.appendTo(getGuideAttachPoint());
            }
            integrationIframe.css({ 'display': 'none' });
        }
    
        function attemptToPreserveIntegrationIframes(evt) {
            if(!evt.step) return;
    
            var guide = evt.step.getGuide();
    
            if(!guide.attributes || !guide.attributes.resourceCenter) return;
    
            var resourceCenterContainer = pendo.dom('#pendo-resource-center-container');
            if (!resourceCenterContainer || !resourceCenterContainer.length) return;
    
            var integrationIframes = resourceCenterContainer.find('iframe[id^="_pendo-launcher-ext-frame-chat"]');
            if (!integrationIframes || !integrationIframes.length) return;
    
            integrationIframes.each(function(integrationIframe) {
                var domIframe = pendo.dom(integrationIframe);
                domIframe.css({ 'display': 'none' });
                domIframe.appendTo(getGuideAttachPoint());
            });
        }
    
        function getResourceCenter() {
            return resourceCenter;
        }
    
        function hexToRgb(hex) {
            var result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
            return result ? {
                'r': parseInt(result[1], 16),
                'g': parseInt(result[2], 16),
                'b': parseInt(result[3], 16)
            } : null;
        }
    
        function updateNotificationBubbles() {
            var resourceCenter = getResourceCenter();
            var notificationsObj = get(resourceCenter, 'attributes.notifications');
            if(!notificationsObj) return;
    
            var totalUnseenCount = calculateTotalNotificationCount(notificationsObj.individualCounts);
            if (totalUnseenCount <= 0) {
                removeNotificationBubble();
                return;
            }
    
            updateNotificationBubblesOnHomeView();
    
            var shouldUpdateTotalCount = totalUnseenCount !== notificationsObj.totalUnseenCount;
            if(!shouldUpdateTotalCount) return;
    
            if(resourceCenter.launchMethod === 'badge') {
                var resourceCenterBadge = pendo.dom('._pendo-resource-center-badge-container');
                if(!resourceCenterBadge.length) return;
    
                addNotificationBubbleToResourceCenterBadge(resourceCenterBadge[0], resourceCenter.attributes.notificationBubble, totalUnseenCount);
            }
    
            if(resourceCenter.launchMethod === 'dom') {
                if (resourceCenter.attributes && resourceCenter.attributes.activation && resourceCenter.attributes.activation.selector) {
                    var targetElement = pendo.Sizzle(resourceCenter.attributes.activation.selector);
                    if(!targetElement.length) return;
                    addNotificationBubbleToTargetElement(targetElement[0], resourceCenter.attributes.notificationBubble, totalUnseenCount);
                }
            }
    
            notificationsObj.totalUnseenCount = totalUnseenCount;
        }
    
        function calculateTotalNotificationCount(notificationsObj) {
            return _.reduce(notificationsObj, function(acc, singleCount) {
                return acc + singleCount;
            }, 0);
        }
    
        function updateNotificationBubblesOnHomeView() {
            var resourceCenter = getResourceCenter();
            if(!resourceCenter) return;
    
            var notificationsObj = get(resourceCenter, 'attributes.notifications');
            if(!notificationsObj) return;
    
            var homeViewContainer = Sizzle('[data-layout="HomeViewModule"]');
            if(!homeViewContainer.length) return;
    
            var homeViewList = pendo.dom(homeViewContainer[0]).find('._pendo-resource-center-home-list');
            if(!homeViewList.length) return;
    
            _.each(notificationsObj.individualCounts, function(unseenCount, notificationId) {
                updateNotificationBubbleOnHomeView(unseenCount, notificationId);
            });
        }
    
        function updateNotificationBubbleOnHomeView(unseenCount, notificationId) {
            var resourceCenter = Sizzle('#pendo-resource-center-container');
            if(!resourceCenter.length) return;
    
            var currentListItem = pendo.dom(resourceCenter[0]).find('[data-pendo-notification-id="' + notificationId + '"]');
            if (currentListItem.length) {
                var homeViewBubble = pendo.dom(currentListItem[0]).find('._pendo-home-view-bubble');
                var homeViewBubbleTextElement = pendo.dom(homeViewBubble[0].children[0]);
                var numberHasChanged = unseenCount !== parseInt(homeViewBubbleTextElement.text(), 10);
                if (numberHasChanged) {
                    if (unseenCount > 0) {
                        homeViewBubbleTextElement.text(unseenCount);
                        pendo.dom(homeViewBubble[0]).css({ 'display': 'block', 'margin-right': '0' });
                    } else {
                        pendo.dom(homeViewBubble[0]).css({ 'display': 'none' });
                    }
                }
            }
        }
    
        function addNotificationBubbleToResourceCenterBadge(resourceCenterBadge, notificationBubbleConfig, unseenCount) {
            var badgePosition = get(notificationBubbleConfig, 'position', 'top-left');
            // Assume badge width is 50px for now
            var badgeWidth = 50;
            // bubble placement on badge determined via different top/left properties based on keyed config value
            var positionCss = {
                'top-left': {
                    'top':         '-17px',
                    'left':        badgeWidth - 24 + 'px',
                    'padding':     '0px 10px',
                    'margin-left': '-35px',
                    'margin-top':  '8px'
                },
                'top-right': {
                    'top':         '-17px',
                    'left':        badgeWidth + 13 + 'px',
                    'padding':     '0px 10px',
                    'margin-left': '-35px',
                    'margin-top':  '8px'
                },
                'bottom-left': {
                    'top':         '23px',
                    'left':        badgeWidth - 24 + 'px',
                    'padding':     '0px 10px',
                    'margin-left': '-35px',
                    'margin-top':  '8px'
                },
                'bottom-right': {
                    'top':         '23px',
                    'left':        badgeWidth + 13 + 'px',
                    'padding':     '0px 10px',
                    'margin-left': '-35px',
                    'margin-top':  '8px'
                }
            };
            var bubbleCss = positionCss[badgePosition];
    
            updateOrCreateNotificationBubble(resourceCenterBadge, notificationBubbleConfig, unseenCount, bubbleCss);
        }
    
        function addNotificationBubbleToTargetElement(element, notificationBubbleConfig, unseenCount) {
    
            var posTop = 0;
            var posLeft = 0;
            var offsetParentElement = get(element, 'offsetParent');
            var offsetTarget = getOffsetPosition(element);
            var elementGetComputedStyle = getComputedStyle_safe(element);
            var elementIsFixed = elementGetComputedStyle.position === 'fixed';
            var parentGetComputedStyle = getComputedStyle_safe(offsetParentElement);
            if (offsetParentElement && parentGetComputedStyle.position === 'relative') {
                var offsetParent = getOffsetPosition(offsetParentElement);
                posTop = offsetTarget.top - offsetParent.top - parseInt(elementGetComputedStyle.top, 10);
                posLeft = offsetTarget.left - offsetParent.left - parseInt(elementGetComputedStyle.left, 10);
            } else if (!elementGetComputedStyle.position || elementGetComputedStyle.position === 'static' || elementIsFixed) {
                posTop = offsetTarget.top;
                posLeft = offsetTarget.left;
            }
    
            var bubbleCss = {
                'width':    '28px',
                'top':      offsetTarget.top > 14 ? posTop - 14 + 'px' : 0,
                'left':     offsetTarget.left > 14 ? posLeft - 14 + 'px' : 0,
                'position': elementIsFixed ? 'fixed' : 'absolute'
            };
    
            var unseenCountCss = {
                'width':      '28px',
                'font-size':  '16px',
                'text-align': 'center',
                'position':   'absolute',
                'right':      '0px'
            };
    
            updateOrCreateNotificationBubble(element, notificationBubbleConfig, unseenCount, bubbleCss, unseenCountCss);
        }
    
        function updateOrCreateNotificationBubble(element, notificationBubbleConfig, unseenCount, bubbleCss, unseenCountCss) {
            var notificationBubble = document.getElementsByClassName('pendo-resource-center-badge-notification-bubble');
            if (!notificationBubble.length) {
                var notificationElements = createNotification(notificationBubbleConfig, unseenCount, bubbleCss, unseenCountCss);
                appendNotificationBubble(notificationElements, element);
            } else {
                var unreadCountElement = notificationBubble[0].getElementsByClassName('pendo-notification-bubble-unread-count');
    
                unreadCountElement[0].textContent = unseenCount;
            }
        }
    
        function createNotification(notificationBubbleConfig, unseenCount, bubbleCss, unseenCountCss) {
            var defaultBubbleCss = {
                'position':         'absolute',
                'border-radius':    '20px',
                'line-height':      '0px',
                'height':           '26px',
                'box-sizing':       'content-box',
                'background-color': notificationBubbleConfig['background-color']
            };
    
            var defaultUnseenCountCss = {
                'font-weight':    notificationBubbleConfig['font-weight'],
                'font-family':    notificationBubbleConfig['font-family'],
                'height':         '100%',
                'display':        'inline-block',
                'line-height':    '26px',
                'vertical-align': 'middle',
                'color':          notificationBubbleConfig.color
            };
    
            unseenCount = unseenCount || 0;
            var bubbleEle = dom('<div class="pendo-resource-center-badge-notification-bubble"></div>');
            var unseenCountEle = dom('<div class="pendo-notification-bubble-unread-count"></div>');
            var mergedBubbleCss = _.extend(defaultBubbleCss, bubbleCss);
            var mergedUnseenCountCss = _.extend(defaultUnseenCountCss, unseenCountCss);
            bubbleEle.css(mergedBubbleCss);
            unseenCountEle.css(mergedUnseenCountCss);
            var styleEle = dom('<style id="pendo-resource-center-bubble-animation"></style>');
            if(!isOldIE(10)) {
                var rgbColor = hexToRgb(notificationBubbleConfig['background-color']);
                var rgbString = 'rgb(' + rgbColor.r + ', ' + rgbColor.g + ', ' + rgbColor.b + ')';
    
                var pulseAnimation = '@keyframes pulse { ' +
                    '0% { opacity: 1; transform: scale(1); } ' +
                    '100% { opacity: 0; transform: scale(1.6) } ' +
                '}';
    
                var bubblePseudoEleCss = '.pendo-resource-center-badge-notification-bubble::before { ' +
                    'content: ""; ' +
                    'position: absolute; ' +
                    'top: 0; ' +
                    'left: 0; ' +
                    'width: 100%; ' +
                    'height: 100%; ' +
                    'background-color: ' + rgbString + '; ' +
                    'border-radius: 100%; ' +
                    'z-index: -1; ' +
                    'animation: pulse 2s infinite; ' +
                    'will-change: transform; ' +
                '}';
    
                var bubbleStyles = pulseAnimation + ' ' + bubblePseudoEleCss;
    
                if (styleEle.styleSheet) {
                    styleEle.styleSheet.cssText = bubbleStyles;
                } else {
                    styleEle[0].innerHTML = bubbleStyles;
                }
            }
            unseenCountEle.text(unseenCount);
            return {
                'bubbleEle':      bubbleEle,
                'unseenCountEle': unseenCountEle,
                'styleEle':       styleEle
            };
        }
    
        function appendNotificationBubble(notificationBubbleElements, targetElement) {
            notificationBubbleElements.styleEle.appendTo(targetElement);
            notificationBubbleElements.unseenCountEle.appendTo(notificationBubbleElements.bubbleEle);
            notificationBubbleElements.bubbleEle.appendTo(targetElement);
        }
    
        function removeNotificationBubble() {
            var notificationBubbles = window.pendo.Sizzle('.pendo-resource-center-badge-notification-bubble');
            var bubbleStyles = window.pendo.Sizzle('#pendo-resource-center-bubble-animation');
            if (notificationBubbles) {
                _.each(notificationBubbles, function(value, key) {
                    if(notificationBubbles[key]) {
                        var singleElement = notificationBubbles[key];
                        singleElement.parentNode.removeChild(singleElement);
                    }
                });
            }
    
            if (bubbleStyles) {
                _.each(bubbleStyles, function(value, key) {
                    if (bubbleStyles[key]) {
                        var singleEle = bubbleStyles[key];
                        singleEle.parentNode.removeChild(singleEle);
                    }
                });
            }
        }
    
        function updateNotificationBubbleCount(count, notificationId) {
            var resourceCenter = getResourceCenter();
            if (!resourceCenter) return;
    
            var notificationsObj = get(resourceCenter, 'attributes.notifications');
            if(!notificationsObj) return;
    
            if(notificationsObj.individualCounts[notificationId] === count) return;
    
            notificationsObj.individualCounts[notificationId] = count;
    
            BuildingBlockResourceCenter.updateNotificationBubbles();
        }
    
        function hasAnnouncementBeenSeen(guide) {
            if (_.isFunction(guide.hasBeenSeen) && guide.hasBeenSeen()) return true;
            if (guide.steps[0].seenState === 'active') return true;
    
            return false;
        }
    
    })();
    
    var BuildingBlockSvgs = (function() {
        return {
            'buildSvgNode':            buildSvgNode,
            'createProgressCircleSvg': createProgressCircleSvg
        };
    
        function buildSvgNode(widgetId, json) {
            //eslint-disable-next-line default-case
            switch(widgetId) {
            case 'onboardingProgressCircle':
                return createProgressCircleSvg(json);
            }
        }
    
        function createProgressCircleSvg(bbJson) {
            if(isOldIE(9)) return createProgressCircleIEFallback(bbJson);
    
            var svgAttributes = bbJson.svgAttributes;
            var percentComplete = svgAttributes.fillCircle.percentComplete || 0;
            var isComplete = percentComplete >= 100;
    
            if(isComplete) {
                return createCompleteProgressCircleSvg(svgAttributes);
            }
    
            return createPartialProgressCircleSvg(svgAttributes);
        }
    
        function createCompleteProgressCircleSvg(svgAttributes) {
            var fillColor = svgAttributes.fillCircle.stroke;
    
            // This is the feather icon 'check-circle'
            var svgCompleteTemplate =
                '<svg xmlns="http://www.w3.org/2000/svg" class="pendo-progress-circle-fill" viewBox="0 0 24 24" fill="none" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">' +
                    '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>' +
                    '<polyline points="22 4 12 14.01 9 11.01"></polyline>' +
                '</svg>';
    
            var svgElement = pendo.dom(svgCompleteTemplate);
            svgElement[0].setAttributeNS(null, 'stroke', fillColor);
            return svgElement;
        }
    
        function createPartialProgressCircleSvg(svgAttributes) {
            var fillColor = svgAttributes.fillCircle.stroke;
            var backgroundColor = svgAttributes.backgroundCircle.stroke;
            var percentComplete = svgAttributes.fillCircle.percentComplete || 0;
    
            // this lets us do things like `stroke-dasharray="25, 100"` for a 25% full circle
            var saneRadius = 100 / (Math.PI * 2);
    
            // PLEASE NOTE: We're not using string concatenation from user input to build this svg.
            // Doing so would allow for users to perform injection attacks by escaping html attribute values
            var svgTemplate =
                '<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 40 40" preserveAspectRatio="xMidYMid">' +
                    '<circle class="pendo-progress-circle-background" cx="20" cy="20" r="' + saneRadius + '" stroke-width="6px" stroke-linecap="round" fill="none"></circle>' +
                    '<circle class="pendo-progress-circle-fill" cx="20" cy="20" r="' + saneRadius + '" stroke-width="6px" stroke-linecap="round" transform="rotate(-90 20 20)" fill="none"></circle>' +
                '</svg>';
    
            var svgElement = pendo.dom(svgTemplate);
            var fillCircle = svgElement.find('.pendo-progress-circle-fill')[0];
            var backgroundCircle = svgElement.find('.pendo-progress-circle-background')[0];
    
            backgroundCircle.setAttributeNS(null, 'stroke', backgroundColor);
    
            if(percentComplete <= 0) {
                fillCircle.setAttributeNS(null, 'stroke-width', '0px');
            } else {
                fillCircle.setAttributeNS(null, 'stroke', fillColor);
                fillCircle.setAttributeNS(null, 'stroke-dasharray', percentComplete + ', 100');
            }
    
            return svgElement;
        }
    
        function createProgressCircleIEFallback(bbJson) {
            var svgAttributes = bbJson.svgAttributes;
            var fillColor = svgAttributes.fillCircle.stroke;
            var backgroundColor = svgAttributes.backgroundCircle.stroke;
            var percentComplete = svgAttributes.fillCircle.percentComplete || 0;
            var isComplete = percentComplete >= 100;
    
            var fallbackSquareTemplate =
                '<div class="pendo-progress-circle-ie">' +
                    '<div class="pendo-progress-circle-fill"></div>' +
                '</div>';
    
            var fallbackSquare = pendo.dom(fallbackSquareTemplate);
            var fillSquare = fallbackSquare.find('.pendo-progress-circle-fill');
    
            if(isComplete) {
                fillSquare.css({
                    'border': '3px solid ' + fillColor,
                    'height': '10px',
                    'width':  '10px'
                });
            } else {
                fillSquare.css({
                    'border': '3px solid ' + backgroundColor,
                    'height': '10px',
                    'width':  '10px'
                });
            }
    
            return fallbackSquare;
        }
    })();
    
    var BuildingBlockWatermark = (function() {
        return {
            'initializeWatermark': initializeWatermark,
            'buildWatermark':      buildWatermark
        };
    
        function initializeWatermark(guideList) {
            var watermarkGuides = _.filter(guideList, function(guide) {
                return guide && guide.attributes && guide.attributes.isWatermark;
            });
    
            BuildingBlockWatermark.watermarkGuides = watermarkGuides;
    
            var promises = _.map(watermarkGuides, function(guide) {
                return guide.fetchContent();
            });
    
            return q.all(promises);
        }
    
        function findWatermark(targetAccount) {
            return _.find(BuildingBlockWatermark.watermarkGuides, function(watermarkGuide) {
                return targetAccount === watermarkGuide.targetAccount;
            });
        }
    
        function buildWatermark(options, buildNodeFromJSON) {
            options = options || {};
            var watermarkGuide = findWatermark(options.targetAccount);
            if (!watermarkGuide || !watermarkGuide.steps) return;
            var step = watermarkGuide.steps[0];
            if (!step || !step.domJson) return;
            var json = step.domJson;
            var watermarkContainer = buildNodeFromJSON(json, step);
            watermarkContainer.css({
                'position': 'absolute',
                'left':     'auto',
                'top':      options.isBottomAligned ? 'auto' : '100%',
                'bottom':   options.isBottomAligned ? '100%' : 'auto',
                'right':    '0'
            });
            return watermarkContainer;
        }
    })();
    
    var P2AutoLaunch = (function() {
        var ids = {
            'body':          'pendo-launch-modal-body',
            'closeButton':   'pendo-launch-modal-close-button',
            'container':     'pendo-launch-modal',
            'footer':        'pendo-launch-modal-footer',
            'header':        'pendo-launch-modal-header',
            'launchButton':  'pendo-launch-modal-launch-button',
            'title':         'pendo-launch-modal-title',
            'logoContainer': 'pendo-launch-modal-logo-container',
            'style':         'pendo-launch-modal-style',
            'commIframeId':  'pendo-designer-communication-iframe'
        };
    
        var colors = {
            'GRAY_LIGHTER_6': '#EAECF1',
            'GRAY_PRIMARY':   '#2A2C35',
            'PENDO_PINK':     '#FF4876', // new pink!
            'TEAL_DARKER':    '#036463',
            'TEAL_PRIMARY':   '#008180',
            'WHITE':          '#FFFFFF'
        };
    
        var sizes = {
            'BUTTON_HEIGHT':    35,
            'HEADER_HEIGHT':    60,
            'MODAL_HEIGHT':     235,
            'MODAL_TOP_OFFSET': 150,
            'MODAL_WIDTH':      370
        };
    
        sizes.FOOTER_HEIGHT = sizes.HEADER_HEIGHT * 1.25;
        sizes.BODY_HEIGHT = 'calc(100% - ' + px(sizes.HEADER_HEIGHT) + ' - ' + px(sizes.FOOTER_HEIGHT) + ')';
    
        var pendoLogo = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 164.12 164.12"><defs><style>.cls-1{fill:#fff;}</style></defs><title>chevron</title><g id="Layer_2" data-name="Layer 2"><g id="Layer_1-2" data-name="Layer 1"><polygon class="cls-1" points="82.06 0 0 82.06 82.06 82.06 82.06 164.13 164.13 82.06 164.13 0 82.06 0"/></g></g></svg>';
        var pseudoStyles = {};
    
        pseudoStyles[id(ids.closeButton) + ':hover'] = {
            'background-color': colors.GRAY_LIGHTER_6
        };
    
        pseudoStyles[id(ids.launchButton) + ':hover'] = {
            'background-color': colors.TEAL_DARKER + ' !important'
        };
    
        var fonts = {
            'PRIMARY_FONT': 'Helvetica Neue'
        };
    
        return {
            'listen':                    listen,
            'launchOnLocalStorageToken': launchOnLocalStorageToken,
            'ids':                       ids,
            'removeElement':             removeElement,
            'attemptToLaunch':           attemptToLaunch
        };
    
        function listen() {
            if (!_.isFunction(document.addEventListener)) return;
            document.addEventListener('keyup', function(ev) {
                if (ev.shiftKey && ev.altKey && ev.code === 'Digit7') {
                    attemptToLaunch('', true);
                }
                if (ev.shiftKey && ev.altKey && ev.code === 'Digit8') {
                    attemptToLaunch('', false, true);
                }
    
            }, false);
        }
    
        function createModal(token, isVia) {
            var modalStyles = {
                'background-color': colors.WHITE,
                'height':           px(sizes.MODAL_HEIGHT),
                'min-height':       px(sizes.MODAL_HEIGHT),
                'width':            px(sizes.MODAL_WIDTH),
                'position':         'fixed',
                'top':              px(sizes.MODAL_TOP_OFFSET),
                'left':             '50%',
                'margin-left':      px(-sizes.MODAL_WIDTH / 2),
                'border-radius':    px(4),
                'box-shadow':       '0px 13px 28px rgba(0, 0, 0, 0.17)',
                'overflow':         'hidden',
                'z-index':          '300000', // above all guides,
                'box-sizing':       'border-box'
            };
            var modalContainer = createUIElement('div', ids.container, modalStyles);
            modalContainer.appendChild(createPseudoStyles());
            modalContainer.appendChild(createHeader(isVia));
            modalContainer.appendChild(createBody());
            modalContainer.appendChild(createFooter(token));
            document.body.appendChild(modalContainer);
        }
    
        function createHeader(isVia) {
            var headerContainer =  createUIElement('div', ids.header, {
                'background-color': colors.GRAY_PRIMARY,
                'height':           px(sizes.HEADER_HEIGHT),
                'min-height':       px(sizes.HEADER_HEIGHT),
                'width':            '100%',
                'padding':          px(10) + ' ' + px(20),
                'display':          'flex',
                'align-items':      'center',
                'box-sizing':       'border-box'
            });
    
            var logoContainer = createUIElement('div', ids.logoContainer, {
                'height':           px(38),
                'width':            px(44),
                'background-color': colors.PENDO_PINK,
                'padding':          px(8),
                'border-radius':    px(3),
                'box-sizing':       'border-box'
            });
    
            logoContainer.innerHTML = pendoLogo;
            headerContainer.appendChild(logoContainer);
            var titleContainer = createUIElement('div', ids.title, {
                'width':       '100%',
                'display':     'flex',
                'align-items': 'center',
                'font-family': fonts.PRIMARY_FONT,
                'font-size':   px(18),
                'color':       colors.WHITE,
                'margin-left': px(10),
                'box-sizing':  'border-box'
            });
            titleContainer.innerText = isVia ? 'VIA Designer' : 'Pendo Designer';
            headerContainer.appendChild(titleContainer);
            return headerContainer;
        }
    
        function createBody() {
            var bodyContainer = createUIElement('div', ids.body, {
                'height':      sizes.BODY_HEIGHT,
                'min-height':  sizes.BODY_HEIGHT,
                'width':       '100%',
                'display':     'flex',
                'padding':     px(32) + ' ' + px(20),
                'font-family': fonts.PRIMARY_FONT,
                'font-size':   px(14),
                'box-sizing':  'border-box'
            });
            bodyContainer.innerText = 'Thanks for letting us know you\'re here. We\'re ready to try this again. Launch Designer below to begin.';
            return bodyContainer;
        }
    
        function createFooter(token) {
            var footerContainer = createUIElement('div',ids.footer , {
                'align-items':     'center',
                'border-top':      '1px solid' + colors.GRAY_LIGHTER_6,
                'display':         'flex',
                'height':          px(sizes.FOOTER_HEIGHT),
                'justify-content': 'flex-end',
                'min-height':      px(sizes.FOOTER_HEIGHT),
                'padding':         px(10),
                'width':           '100%',
                'box-sizing':      'border-box'
            });
    
            var closeButton = createUIElement('button', ids.closeButton,{
                'border-radius':   px(3),
                'border':          'none',
                'height':          px(sizes.BUTTON_HEIGHT),
                'padding-right':   px(10),
                'padding-left':    px(10),
                'font-family':     fonts.PRIMARY_FONT,
                'font-size':       px(14),
                'display':         'flex',
                'line-height':     '120%',
                'margin-right':    px(10),
                'min-width':       '90px',
                'justify-content': 'center',
                'box-sizing':      'border-box'
            });
            closeButton.innerHTML = 'Close';
            closeButton.onclick = function() {
                removeElement(ids.container);
                removeElement(ids.commIframeId);
            };
    
            var launchDesignerButton = createUIElement('button', ids.launchButton,{
                'background-color': colors.TEAL_PRIMARY,
                'border-radius':    px(3),
                'color':            colors.WHITE,
                'border':           'none',
                'height':           px(sizes.BUTTON_HEIGHT),
                'padding-right':    px(10),
                'padding-left':     px(10),
                'font-family':      fonts.PRIMARY_FONT,
                'font-size':        px(14),
                'display':          'flex',
                'line-height':      '120%',
                'min-width':        '90px',
                'justify-content':  'center',
                'box-sizing':       'border-box'
            });
            launchDesignerButton.innerHTML = 'Launch Designer';
            launchDesignerButton.onclick = function() {
                launchOnLocalStorageToken(token);
            };
            footerContainer.appendChild(closeButton);
            footerContainer.appendChild(launchDesignerButton);
            return footerContainer;
        }
    
        function buildStyles(styles) {
            return _.reduce(_.pairs(styles), function(acc, style) {
                var key = style[0];
                var value = style[1];
                return acc + key + ':' + value + ';';
            }, '');
        }
    
        function buildPseudoStyles(pseudoStyles) {
            return _.reduce(_.pairs(pseudoStyles), function(acc, style) {
                var key = style[0];
                var value = style[1];
                return acc + key + '{' + buildStyles(value) + '} ';
            }, '');
        }
    
        function createPseudoStyles() {
            var styleNode = document.createElement('style');
            styleNode.setAttribute('id', ids.style);
            styleNode.type = 'text/css';
            var styleText = document.createTextNode(buildPseudoStyles(pseudoStyles));
            styleNode.appendChild(styleText);
            return styleNode;
        }
    
        function createUIElement(type, id, styles) {
            var ele = document.createElement(type);
            ele.setAttribute('id', id);
            _.extend(ele.style, styles);
            return ele;
        }
    
        function px(val) {
            return val + 'px';
        }
    
        function id(val) {
            return '#' + val;
        }
    
        // `isVia` is only set when this is called from the via-specific keyboard shortcut
        function attemptToLaunch(lookaside, isVia, fromKeyboard) {
            if(pendo.designerLaunched) return;
    
            var verifyLocalStorage;
            var verifyViaLocalStorage;
            var openDesigner = pendo._.once(function(token) {
                if(isVia || !fromKeyboard) {
                    launchOnLocalStorageToken(token);
                } else {
                    createModal(token, isVia);
                }
                removePendoComms();
            });
    
            addSafeWindowMessageListener(function(message) {
                if (message.data.destination !== 'pendo-designer-launch-modal') {
                    return;
                }
    
                clearInterval(verifyLocalStorage);
    
                // confirm that the VIA origin recieved the visitor ID and clear interval
                if (message.data.viaconfirmed) {
                    clearInterval(verifyViaLocalStorage);
                    return;
                }
    
                if (!message.data.token) {
                    removePendoComms();
                    return;
                }
    
                // get things started to open the designer on the correct origin
                openDesigner(message.data.token);
    
                var parsed = JSON.parse(message.data.token);
                if (!pendo._.contains(parsed.host, 'via') || parsed.visitorId) {
                    return;
                }
    
                // we've already started the VIA interval if this is truthy
                if (verifyViaLocalStorage) {
                    return;
                }
    
                // broadcast visitor ID to VIA origin
                verifyViaLocalStorage = setInterval(function() {
                    if (document.getElementById(ids.commIframeId)) {
                        broadcastVisitorId();
                    }
                }, 100);
            });
    
            pendo.designerv2.addCommunicationIframe({
                'lookasideDir':  lookaside,
                'defaultBucket': 'in-app-designer'
            });
    
            // this broadcast will only target pendo
            broadcastVisitorId();
            verifyLocalStorage = window.setInterval(broadcastVisitorId, 50);
        }
    
        function removeElement(id) {
            document.getElementById(id) && document.getElementById(id).remove();
        }
    
        function removePendoComms() {
            var el = document.querySelector('#' + ids.commIframeId + '[src*="pendo"]');
    
            el && el.remove();
        }
    
        function broadcastVisitorId() {
            document.getElementById(ids.commIframeId).contentWindow.postMessage({
                'destination': 'pendo-designer-ls',
                'source':      'pendo-designer-launch-modal',
                'visitorId':   window.pendo.visitorId
            }, '*');
        }
    
        function launchOnLocalStorageToken(dataToken) {
            var options = {};
            var token = JSON.parse(dataToken);
    
            // latest will route to the pendo designer module, via will route to via designer module
            options.target = token.target || 'latest';
    
            if (token.host) {
                options.host = token.host;
            }
    
            if (token.lookaside) {
                options.lookaside = token.lookaside;
            }
            removeElement(ids.container);
            pendo.designerv2.launchInAppDesigner(options);
        }
    
    })();
    
    var DesignerV2 = (function() {
        // Always use the production server for CNAME customers
        var host = 'https://app.pendo.io';
        //eslint-disable-next-line no-constant-condition
        if ('prod' === 'local') {
            host = 'https://local.pendo.io:8080';
        }
    
        listenForParentSelectionRequests();
    
        return {
            'launchDesigner':                 launchDesigner,
            'launchInAppDesigner':            launchInAppDesigner,
            'launchOnToken':                  launchOnToken,
            'sendMessageToLocalStorage':      sendMessageToLocalStorage,
            'isValidDesignerHost':            isValidDesignerHost,
            'launchSelectionModeFromMessage': launchSelectionModeFromMessage,
            'addCommunicationIframe':         addCommunicationIframe,
            'addStylesToPage':                addStylesToPage
        };
    
        function isValidDesignerHost(host) {
            if (!host) {
                return false;
            }
    
            return isTrustedOrigin2(host);
        }
    
        function launchOnToken(url) {
            if (isDesignerFrame()) {
                return;
            }
    
            var tokenParamTest = /pendo-designer=([A-Za-z0-9-]+)/;
            var lookasideParamTest = /lookaside=[A-Za-z0-9-]+/;
            if (!tokenParamTest.test(url)) return;
    
            var tokenMatch = tokenParamTest.exec(url);
            if (!tokenMatch) return;
    
            var tokenParam = tokenMatch[0];
            var lookasideMatch = lookasideParamTest.exec(url);
            var lookasideParam = lookasideMatch ? lookasideMatch[0] : '';
            var parsedToken = parsePendoToken(tokenMatch[1]);
            var parsedParams = queryStringToObject(tokenParam + '&' + lookasideParam);
            var host = isValidDesignerHost(parsedToken.host) ? parsedToken.host : null;
            if (parsedParams.hasOwnProperty('pendo-designer')) {
                // clear stored designer state if we're launching from a token
                window.localStorage.removeItem('pendo-navigation-state');
                window.localStorage.removeItem('pendo-designer-mode');
                launchInAppDesigner({
                    'target':    parsedToken.target || 'latest',
                    'lookaside': parsedParams.lookaside,
                    'host':      host,
                    'preloader': false
                });
                return true;
            }
        }
    
        function parsePendoToken(token) {
            try {
                return JSON.parse(atob(decodeURIComponent(token))) || {};
            } catch (e) {
                return {};
            }
        }
    
        // This is the main entry point for the P2 designer
        function launchInAppDesigner(options) {
            if (isDesignerFrame()) {
                return;
            }
            pendo.designerLaunchTime = new Date().getTime();
            if (!options) {
                options = {};
            }
    
            if(!options.lookaside) {
                options.lookaside = pendoLocalStorage.getItem('pendo-designer-lookaside') || '';
            }
    
    
            var assetHost = options.host || host;
            var isHostValid = isValidDesignerHost(assetHost);
            var validAssetHost = isHostValid ? assetHost : 'https://app.pendo.io';
            if(!isHostValid) {
                log('Invalid host, falling back to https://app.pendo.io');
            }
    
            var gcsBucket = options.gcsBucket || 'in-app-designer';
            var baseFolder = options.lookaside || options.target || 'latest';
            var designerFile = options.preloader ? 'preloader.js' : 'plugin.js';
            var scriptTagId = options.preloader ? 'preloader-shims' : 'designer-shims';
            var designerShimsSrc = validAssetHost + '/' + gcsBucket + '/' + baseFolder + '/' + designerFile;
            window.pendo.designerv2.hostConfig = {
                'gcsBucket':      gcsBucket,
                'baseFolder':     baseFolder,
                'lookaside':      options.lookaside,
                'uniqueWindowId': options.uniqueWindowId,
                'host':           validAssetHost
            };
    
            var scriptTagAttributes = {};
            if (options.selectionOnly) {
                scriptTagAttributes['selection-only'] = true;
            }
    
    
            addScriptToPage(scriptTagId, designerShimsSrc, scriptTagAttributes);
            pendo.designerLaunched = true;
        }
    
        /*
            Everything below this line is used the support the chrome designer extension.
            None of these code paths are used by the P2 designer - if you edit them,
            ensure that you haven't broken the chrome extension's functionality
        */
    
        function getStyles() {
            var keyframes = '@keyframes pendoExtensionSlideIn{from{transform:translate3d(-300px,0,0)}to{transform:translate3d(0,0,0);}}';
            var draggableEle = '#pendo-draggable-handle{z-index:11;line-height: 15px;text-align:center;font-size:20px;letter-spacing:1.5px;position:absolute;width:100%;height:65px;font-size:16px;background-color:transparent;color:#ABE7DB;user-select:none;cursor: move;cursor: grab;cursor: -moz-grab;cursor: -webkit-grab;}#pendo-draggable-handle:active{cursor: grabbing;cursor: -moz-grabbing;cursor: -webkit-grabbing !important;}#pendo-draggable-handle.hidden{display:none;}#pendo-draggable-handle:hover{color:#2EA2A0;}';
            var mousemoveCover = '#pendo-mousemove-cover{position:absolute;height:100%;width:100%;top:0;left:0;z-index:9999999999;display:none;}';
            var container = '#pendo-designer-container{animation-duration:375ms;animation-name:pendoExtensionSlideIn;animation-timing-function:cubic-bezier(0.4,0.0,0.2,1); box-shadow: 0px 2px 10px rgba(0,0,0,0.15);height:100vh;width:400px;position:fixed;top:0;left:0;overflow:hidden;border-radius:3px;z-index:1000000;}';
            var containerFull = '#pendo-designer-container.fullscreen{width:100%;opacity:0.98;}';
            var containerClosed = '#pendo-designer-container.closed{left:-400px;}';
            var iframe = '#pendo-designer-iframe{background:#3a3c45;border:0px;height:100%;left:0;z-index:10;top:0;width:100%;}';
            return keyframes + draggableEle + container + mousemoveCover + containerFull + containerClosed + iframe;
        }
    
    
        // This is the entry point for the chrome designer extension
        function launchDesigner(options) {
            if (!options) {
                options = {};
            }
    
            var baseFolder = options.lookaside || 'latest';
            var gcsBucket = options.gcsBucket || 'designer';
            addStylesToPage('designer-styles', getStyles(baseFolder));
            var designerShimsSrc = host + '/' + gcsBucket + '/' + baseFolder + '/plugin.js';
            addScriptToPage('designer-shims', designerShimsSrc);
    
            if (window.pendo.DESIGNER_VERSION) {
                onShimsLoaded(baseFolder, options);
    
                return;
            }
    
            var areShimsLoaded = window.setInterval(function() {
                if (window.pendo.DESIGNER_VERSION) {
                    onShimsLoaded(baseFolder, options);
                    clearInterval(areShimsLoaded);
                }
            }, 100);
        }
    
        function addCommunicationIframe(options) {
            if (!options) {
                options = {};
            }
            var baseFolder = options.lookaside || options.lookasideDir || 'latest';
            var gcsBucket = options.gcsBucket || options.defaultBucket || 'designer';
            var windowCommunicationId = (new Date()).getTime();
            window.pendo.designerv2.windowCommunicationId = windowCommunicationId;
            var commIframeId = 'pendo-designer-communication-iframe';
            if (!document.getElementById(commIframeId)) {
                var commIframeName = 'pendo-designer-communication-embedded';
                var commIndex = 'communication.html';
                commIframeName += '__' + windowCommunicationId;
    
                if (options && options.lookaside) {
                    commIframeName += '__' + options.lookaside;
                    commIndex = 'lookaside-' + commIndex;
                }
    
                var commSrc = host + '/' + gcsBucket + '/' + baseFolder + '/' + commIndex;
                var commIframe = createIframeContainer(commIframeId, commSrc, 'border-width:0;height:0;width:0;');
    
                commIframe.setAttribute('name', commIframeName);
    
                document.body.appendChild(commIframe);
                return commIframe;
            }
    
            return document.getElementById(commIframeId);
        }
    
        function onShimsLoaded(baseFolder, options) {
            putAgentIntoDesignerMode();
            addDesignerContainerToBody(baseFolder, options);
        }
    
        function addDesignerContainerToBody(baseFolder, options) {
            if (!document.getElementById('pendo-designer-container')) {
                var iframeName = 'pendo-designer-embedded';
                var designerIndex = 'designer.html';
                var gcsBucket = 'designer';
    
                iframeName += '__' + window.pendo.designerv2.windowCommunicationId;
    
                if (options && options.lookaside) {
                    iframeName += '__' + options.lookaside;
                    designerIndex = 'lookaside.html';
                }
    
                if (options && options.gcsBucket) {
                    gcsBucket = options.gcsBucket;
                }
    
                var editorSrc = host + '/' + gcsBucket + '/' + baseFolder + '/' + designerIndex;
                var designerIframe = createIframeContainer('pendo-designer-iframe', editorSrc);
                designerIframe.setAttribute('name', iframeName);
                var iframeWrapper = createDesignerIframeWrapper(designerIframe);
                document.body.appendChild(iframeWrapper);
            }
        }
    
        function createIframeContainer(id, src, style) {
            var iframe = document.createElement('iframe');
            iframe.setAttribute('id', id);
            if (style) {
                iframe.setAttribute('style', style);
            }
            iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-top-navigation allow-forms allow-pointer-lock allow-popups');
            iframe.src = src;
            return iframe;
        }
    
        function createDesignerIframeWrapper(iframe) {
            var container = document.createElement('div');
            container.setAttribute('id', 'pendo-designer-container');
            container.appendChild(iframe);
    
            return container;
        }
    
        function addStylesToPage(styleId, styles) {
            if (document.getElementById(styleId)) return;
    
            var styleNode = document.createElement('style');
            styleNode.setAttribute('id', styleId);
            styleNode.type = 'text/css';
            var styleText = document.createTextNode(styles);
            styleNode.appendChild(styleText);
            document.getElementsByTagName('head')[0].appendChild(styleNode);
        }
    
        function addScriptToPage(scriptId, scriptURL, attributes) {
            if (document.getElementById(scriptId)) return;
    
            var scriptEle = document.createElement('script');
            scriptEle.setAttribute('charset', 'utf-8');
            scriptEle.setAttribute('id', scriptId);
            scriptEle.src = scriptURL;
            if (attributes) {
                _.forEach(attributes, function(value, attribute) {
                    scriptEle.setAttribute(attribute, value);
                });
            }
            document.body.appendChild(scriptEle);
        }
    
        function putAgentIntoDesignerMode() {
            window.postMessage({
                'type':        'connect',
                'source':      'pendo-designer-content-script',
                'destination': 'pendo-designer-agent'
            }, '*');
        }
    
        function sendMessageToLocalStorage(message) {
            var commIframe = document.getElementById('pendo-designer-communication-iframe');
            if (commIframe) {
                commIframe.contentWindow.postMessage(message.data, '*');
            }
        }
    
        function isDesignerFrame() {
            return /^pendo/.test(window.name);
        }
    
        function listenForParentSelectionRequests() {
            if (!_.isFunction(window.addEventListener)) return;
            if (!detectMaster()) return;
            window.addEventListener('message', launchSelectionModeFromMessage);
        }
    
        function launchSelectionModeFromMessage(event) {
            if (!event || !event.data) return;
    
            var destination = event.data.destination;
            if (!destination || destination !== 'pendo-designer-agent') return;
    
            var type = event.data.type;
            if (!type || type !== 'addSelectionCode') return;
    
            var options = event.data.options;
            if (!options) return;
    
            options.selectionOnly = true;
    
            launchInAppDesigner(options);
            window.removeEventListener('message', launchSelectionModeFromMessage);
        }
    })();
    
    pendo.designerv2 = DesignerV2;
    pendo.P2AutoLaunch = P2AutoLaunch;
    pendo.BuildingBlocks = {
        'BuildingBlockGuides':         BuildingBlockGuides,
        'BuildingBlockResourceCenter': BuildingBlockResourceCenter,
        'BuildingBlockTemplates':      BuildingBlockTemplates,
        'BuildingBlockTooltips':       BuildingBlockTooltips,
        'BuildingBlockSvgs':           BuildingBlockSvgs
    };
    
    // this defines what we're going to export out side of code isolation
    // for the Agent
    
    // Agent Info:
    pendo.getVersion = getVersion;
    pendo.isReady = isReady;
    pendo.pageLoad = pageLoad;
    pendo.getVisitorId = pendo.get_visitor_id;
    pendo.getAccountId = pendo.get_account_id;
    
    // cache.js
    pendo.flushNow = function forceFlushNow() {
        return flushNow(true);
    };
    
    // guides.js
    pendo.initGuides = initGuides;
    pendo.loadGuides = loadGuides;
    pendo.findGuideByName = findGuideByName;
    pendo.hideGuides = hideGuides;
    pendo.onGuideDismissed = onGuideDismissed;
    pendo.onGuideAdvanced = onGuideAdvanced;
    pendo.onGuidePrevious = onGuidePrevious;
    pendo.startGuides = manuallyStartGuides;
    pendo.stopGuides = stopGuides;
    pendo.toggleLauncher = toggleLauncher;
    pendo.showLauncher = expandLauncherList;
    pendo.hideLauncher = collapseLauncherList;
    pendo.removeLauncher = removeLauncher;
    pendo.defaultCssUrl = getDefaultCssUrl();
    pendo.getActiveGuides = getActiveGuides;
    pendo.getActiveGuide = getActiveGuide;
    pendo.guideSeenTimeoutLength = getGuideSeenTimeoutLength();
    
    pendo.areGuidesDisabled = areGuidesDisabled;
    pendo.setGuidesDisabled = setGuidesDisabled;
    pendo.buildNodeFromJSON = BuildingBlockGuides.buildNodeFromJSON;
    pendo.flexElement = BuildingBlockGuides.flexElement;
    pendo.GuideFactory = GuideFactory;
    
    // dom
    pendo.dom = dom;
    
    // event properties
    pendo.getEventPropertyTarget = getEventPropertyTarget;
    pendo.previewEventProperty = collectEventProperty;
    
    // logging
    pendo.log = log;
    pendo.enableLogging = enableLogging;
    pendo.disableLogging = disableLogging;
    pendo.setActiveContexts = setActiveContexts;
    pendo.showLogHistory = showLogHistory;
    pendo.getLoggedContexts = getLoggedContexts;
    
    // debugging
    pendo.isDebuggingEnabled = isDebuggingEnabled;
    pendo.enableDebugging = enableDebugging;
    pendo.disableDebugging = disableDebugging;
    pendo.addDebuggingFunctions = addDebuggingFunctions;
    
    // data I/O (transmit.js)
    pendo.stopSendingEvents = lockEvents;
    pendo.startSendingEvents = unlockEvents;
    pendo.isSendingEvents = isUnlocked;
    
    pendo.fromByteArray = b64.uint8ToBase64;
    
    var designer = {
        'dom':                       dom,
        'placeBadge':                placeBadge,
        'showPreview':               showPreview,
        'stopGuides':                stopGuides,
        'removeAllBadges':           removeAllBadges,
        '_':                         _,
        'sizzle':                    Sizzle,
        'tellMaster':                tellMaster, // deprecated
        'tell':                      tellMaster,
        'log':                       log,
        'attachEvent':               attachEvent,
        'createLauncher':            createLauncher,
        'removeLauncher':            removeLauncher,
        'addGuideToLauncher':        addGuideToLauncher,
        'updateLauncherContent':     updateLauncherContent,
        'DEFAULT_TIMER_LENGTH':      DEFAULT_TIMER_LENGTH,
        'getOffsetPosition':         getOffsetPosition,
        'getScreenDimensions':       getScreenDimensions,
        'registerMessageHandler':    registerMessageHandler,
        'whenLoadedCall':            whenLoadedCall,
        'loadResource':              pendo.loadResource,
        'loadGuideCss':              loadGuideCss,
        'GuideFactory':              GuideFactory,
        'GuideStep':                 GuideStep,
        'extractElementTreeContext': extractElementTreeContext,
        'previewGuideFromJSON':      BuildingBlockGuides.previewGuideFromJSON,
        'hidePreviewedGuide':        BuildingBlockGuides.hidePreviewedGuide,
        'shadowAPI':                 shadowAPI,
        'getTarget':                 getTarget
    };
    
    var addDesignerFunctionality = function() {
        designer.areGuidesEnabled = !areGuidesDisabled();
        if (pendo.designer) return;
        pendo.designer = designer;
    };
    var removeDesignerFunctionality = function() {
        if (!pendo.designer) return;
        pendo.designer = null;
        delete pendo.designer;
    };
    
    /**
     * @link https://pendo-io.atlassian.net/browse/APP-2040 -- Relevant JIRA Issue
     * @link http://stackoverflow.com/a/13848813/126992 -- Stack Overflow discussion
     *
     * - The Pendo client uses `JSON.stringify` to build the JSON that it sends to
     *   the backend.
     * - Prototype JS monkey-patches many JavaScript native objects with `toJSON`
     *   methods for internal use.
     * - `JSON.stringify` treats the `toJSON` method of an object as responsible
     *   for producing the JSON representation of that object.
     * - The implmentation of `toJSON` for `Array` in Prototype JS < 1.7 produces
     *   an invalid JSON representation.
     *
     * To workaround customer applications that use Prototype < 1.7 and based on
     * suggestions from Stack Overflow, we:
     *
     * - _conditionally_ monkey-patch `JSON.stringify` if Prototype < 1.7 is detected
     * - _temporarily_ reverse-monkey-patch `Array.prototype.toJSON` (and put it
     *   back when we're done serializing)
     */
    function patchJSONstringify() {
        var jsonStringify = JSON.stringify;
    
        JSON.stringify = function(value, replacer, space) {
            var Prototype_toJSON = Array.prototype.toJSON;
    
            delete Array.prototype.toJSON; // remove the monkey-patch
    
            var json = jsonStringify(value, replacer, space);
    
            Array.prototype.toJSON = Prototype_toJSON;
    
            return json;
        };
    }
    
    /**
     * @return {boolean} whether Prototype JS < 1.7 and has `Array.prototype.toJSON`
     */
    function isPrototypeOlderThan(version) {
        /*global Prototype*/
        return (typeof Prototype !== 'undefined'
            && parseFloat(Prototype.Version.substr(0,3)) < version
            && typeof Array.prototype.toJSON !== 'undefined'
        );
    }
    
    if (isPrototypeOlderThan(1.7)) patchJSONstringify();
    
    function track(name, props) {
        var url = pendo.url.get();
        collectEvent('track', props, url, name);
    }
    
    pendo.track = track;
    
    var Feedback = (function() {
        var notificationCountCookie = 'feedback_notification_count';
        var pingCookie = 'feedback_ping_sent';
        var pingCookieExpirationMs = 3600000;
        var vendorApiHome = '';
        var vendorId = '';
        var siteUrl = '';
        var feedbackLoginHost = '';
        var widgetLoaded = false;
        var feedbackAllowedProductId = '';
        var initialized = false;
    
        var overflowMediaQuery =
            '@media only screen and (max-device-width:1112px){#feedback-widget{overflow-y:scroll}}';
        var slideIn =
            '@-webkit-keyframes pendoFeedbackSlideIn{from{opacity:0;transform:translate(145px,0) rotate(270deg) translateY(-50%)}to{opacity:1;transform:translate(50%,0) rotate(270deg) translateY(-50%)}}@keyframes pendoFeedbackSlideIn{from{opacity:0;transform:translate(145px,0) rotate(270deg) translateY(-50%)}to{opacity:1;transform:translate(50%,0) rotate(270deg) translateY(-50%)}}';
        var slideInLeft =
            '@-webkit-keyframes pendoFeedbackSlideIn-left{from{opacity:0;transform:rotate(270deg) translateX(-55%) translateY(-55%)}to{opacity:1;transform:rotate(270deg) translateX(-55%) translateY(0)}}@keyframes pendoFeedbackSlideIn-left{from{opacity:0;transform:rotate(270deg) translateX(-55%) translateY(-55%)}to{opacity:1;transform:rotate(270deg) translateX(-55%) translateY(0)}}';
        var slideFromRight =
            '@-webkit-keyframes pendoFeedbackSlideFromRight{from{transform:translate(-460px,0)}to{transform:translate(0,0)}}@keyframes pendoFeedbackSlideFromRight{from{opacity:0;transform:translate(460px,0)}to{opacity:1;transform:translate(0,0)}}';
        var slideFromLeft =
            '@-webkit-keyframes pendoFeedbackSlideFromLeft{from{opacity:0;transform:translate(-460px,0)}to{opacity:1;transform:translate(0,0)}}@keyframes pendoFeedbackSlideFromLeft{from{opacity:0;transform:translate(-460px,0)}to{opacity:1;transform:translate(0,0)}}';
        var pulse =
            '@-webkit-keyframes pendoFeedbackPulse{from{-webkit-transform:scale(1,1);transform:scale(1,1)}50%{-webkit-transform:scale(1.15,1.15);transform:scale(1.15,1.15)}to{-webkit-transform:scale(1,1);transform:scale(1,1)}}@keyframes pendoFeedbackPulse{from{-webkit-transform:scale(1,1);transform:scale(1,1)}50%{-webkit-transform:scale(1.15,1.15);transform:scale(1.15,1.15)}to{-webkit-transform:scale(1,1);transform:scale(1,1)}}';
        var fadeIn =
            '@-webkit-keyframes pendoFeedbackFadeIn{from{opacity:0}to{opacity:1}}@keyframes pendoFeedbackFadeIn{from{opacity:0}to{opacity:1}}';
        var buttonRightMediaQuery =
            '@media only screen and (max-width:470px){#feedback-widget.buttonIs-right.visible{width:100%;right:2%}}';
        var buttonLeftMediaQuery =
            '@media only screen and (max-width:470px){#feedback-widget.buttonIs-left.visible{width:100%}}';
        var buttonHoverAndFocus =
            '#feedback-trigger button:focus,#feedback-trigger button:hover{box-shadow:0 -5px 20px rgba(0,0,0,.19);outline:0;background:#3e566f}';
    
        var elemIds = {
            'feedbackIframe':        'feedback-widget_iframe',
            'feedbackTrigger':       'feedback-trigger',
            'feedbackWidget':        'feedback-widget',
            'feedbackOverlay':       'feedback-overlay',
            'feedbackTriggerButton': 'feedback-trigger-button'
        };
    
        function resetFeedbackToInitialState() {
            vendorApiHome = '';
            vendorId = '';
            siteUrl = '';
            feedbackLoginHost = '';
            widgetLoaded = false;
            feedbackAllowedProductId = '';
            initialized = false;
        }
    
        function getWidgetInitialSource() {
            return siteUrl + '/html/widget/notLoaded.html';
        }
    
        function getPseudoStyles(horizontalPosition) {
            var slideFromPosition;
            var buttonMediaQuery;
            if (horizontalPosition === 'left') {
                slideFromPosition = slideFromLeft;
                buttonMediaQuery = buttonLeftMediaQuery;
            } else {
                slideFromPosition = slideFromRight;
                buttonMediaQuery = buttonRightMediaQuery;
            }
    
            return (
                overflowMediaQuery +
                slideIn +
                slideInLeft +
                slideFromPosition +
                pulse +
                fadeIn +
                buttonMediaQuery +
                buttonHoverAndFocus
            );
        }
    
        function storeLastPingTime() {
            agentStorage.write(pingCookie, true, pingCookieExpirationMs);
        }
    
        function wasPingSentRecently() {
            return agentStorage.read(pingCookie);
        }
    
        function getFullUrl(path) {
            return vendorApiHome + path;
        }
    
        function ping(feedbackOptions) {
            if (!wasPingSentRecently()) {
                var toSend = getFeedbackOptionsForRequest(feedbackOptions);
                if (toSend.data && toSend.data !== '{}' && toSend.data !== 'null') {
                    return pendo.ajax
                        .postJSON(getFullUrl('/widget/pendo_ping'), toSend)
                        .then(onWidgetPingResponse);
                }
            }
            return q.resolve();
        }
    
        function getFeedbackOptionsForRequest(feedbackOptions) {
            if (!feedbackOptions) {
                feedbackOptions = convertPendoToFeedbackOptions(getOptionsCopy());
            }
            return { 'data': JSON.stringify(feedbackOptions) };
        }
    
        function getNotificationCount() {
            var notificationCount =
                agentStorage.read(notificationCountCookie) || 0;
            return parseInt(notificationCount, 10);
        }
    
        function setNotificationCount(notificationCount) {
            agentStorage.write(notificationCountCookie, notificationCount);
        }
    
        function showNotificationsFromCookie() {
            var notificationCountElems = pendo.Sizzle('#feedback-trigger-notification');
            if (notificationCountElems.length === 0) {
                return;
            }
            var notificationCount = getNotificationCount();
            if (notificationCount > 0) {
                _.forEach(notificationCountElems, function(elem) {
                    pendo.dom(elem).css({ 'visibility': 'visible' });
                });
            } else {
                _.forEach(notificationCountElems, function(elem) {
                    pendo.dom(elem).css({ 'visibility': 'hidden' });
                });
            }
        }
    
        function onWidgetPingResponse(response) {
            storeLastPingTime();
            setNotificationCount(response.data.notifications);
            showNotificationsFromCookie();
        }
    
        function initializeFeedbackOnce() {
            return initialized ? q.resolve()
                : init(getOptionsCopy(), getPendoConfigValue('feedbackSettings'));
        }
    
        function loginAndRedirect(tabOptions, data) {
    
            return initializeFeedbackOnce().then(function() {
                if (_.isUndefined(tabOptions)) {
                    tabOptions = {};
                }
                if (
                    get(tabOptions, 'anchor.nodeName', '').toUpperCase() === 'A'
                ) {
                    openNewAjaxTab();
                    return false;
                } else {
                    getFeedbackLoginUrl().then(function(loginUrl) {
                        window.location.href = loginUrl;
                    });
                }
            }, function() {
                return;
            });
        }
    
        function openNewAjaxTab() {
            var tabOpen = window.open(
                getWidgetInitialSource(),
                Math.random()
                    .toString(36)
                    .substring(7)
            );
    
            getFeedbackLoginUrl().then(function(loginurl) {
                tabOpen.location = loginurl;
            });
        }
    
        function getUrlHost(url) {
            var parser = document.createElement('a');
            parser.href = url;
            return parser.host;
        }
    
        function saveLoginHost(url) {
            feedbackLoginHost = getUrlHost(url);
        }
    
        function getFeedbackLoginUrl() {
            var toSend = getFeedbackOptionsForRequest();
            if (toSend.data && toSend.data !== '{}' && toSend.data !== 'null') {
                return pendo.ajax
                    .postJSON(getFullUrl('/widget/token'), toSend)
                    .then(function(response) {
                        saveLoginHost(response.data.login_url);
                        return response.data.login_url;
                    });
            }
        }
    
        function getWidgetElement() {
            return document.getElementById(elemIds.feedbackWidget);
        }
    
        function widgetFrameElem() {
            return document.getElementById(elemIds.feedbackIframe);
        }
    
        function getWidgetFrame() {
            var widgetIframe = widgetFrameElem();
            if (!widgetIframe) {
                initialiseWidgetFrame();
                widgetIframe = widgetFrameElem();
            }
            return widgetIframe;
        }
    
        function isUnsupportedIE() {
            var myNav = navigator.userAgent.toLowerCase();
            return myNav.indexOf('msie') != -1 && parseInt(myNav.split('msie')[1], 10) < 10;
        }
    
        function openFeedback(evt) {
            if(!canInitFeedback()) return;
            evt && evt.preventDefault && evt.preventDefault();
            var widgetIframe = getWidgetFrame();
            if (!widgetIframe.src || widgetIframe.src === getWidgetInitialSource()) {
                getFeedbackLoginUrl().then(function(loginUrl) {
                    widgetIframe.src = loginUrl + '&inWidget=true';
                });
            }
            addOverlay();
            dom.addClass(getWidgetElement(), 'visible');
            sendEvent('user.widget.opened');
        }
    
        function closeFeedback() {
            removeOverlay();
            dom.removeClass(getWidgetElement(), 'visible');
            sendEvent('user.widget.closed');
        }
    
        function sendEvent(eventName) {
            var toSend = getFeedbackOptionsForRequest();
            toSend.event = eventName;
            return pendo.ajax.postJSON(getFullUrl('/analytics'), toSend);
        }
    
        function addOverlay() {
            var widget = document.getElementById(elemIds.feedbackWidget);
            if (!widget) {
                return;
            }
            var overlayStyles = {
                'position':          'fixed',
                'top':               '0',
                'right':             '0',
                'bottom':            '0',
                'left':              '0',
                'background':        'rgba(0, 0, 0, 0.4)',
                'z-index':           '9000',
                'opacity':           '0',
                'animation':         'pendoFeedbackFadeIn 0.5s 0s 1 alternate both',
                '-webkit-animation': 'pendoFeedbackFadeIn 0.5s 0s 1 alternate both'
            };
    
            var overlayElement = buildBaseElement(
                'feedback-overlay',
                overlayStyles,
                'div'
            );
            var overlayElementToAppend = BuildingBlockGuides.buildNodeFromJSON(
                overlayElement
            );
            var parentNode = widget.parentNode;
            overlayElementToAppend.appendTo(parentNode);
        }
    
        function removeOverlay() {
            var widget = document.getElementById(elemIds.feedbackWidget);
            var overlay = document.getElementById(elemIds.feedbackOverlay);
            if (!widget || !overlay) {
                return;
            }
            var overlayElementToRemove = document.getElementById(elemIds.feedbackOverlay);
            overlayElementToRemove.parentNode.removeChild(overlayElementToRemove);
        }
    
        function originIsFeedback(origin) {
            if (feedbackLoginHost) {
                return getUrlHost(origin) === feedbackLoginHost;
            }
            return getUrlHost(origin) === getUrlHost(siteUrl);
        }
    
        function subscribeToIframeMessages() {
            window.addEventListener(
                'message',
                function(event) {
                    var origin = event.origin || event.originalEvent.origin;
                    if (!originIsFeedback(origin)) {
                        return;
                    }
                    processIframeMessage(event.data.message, event.data.data);
                },
                false
            );
        }
    
        function processIframeMessage(message, data) {
            //eslint-disable-next-line default-case
            switch (message) {
            case 'close-receptive-widget':
                closeFeedback();
                break;
            case 'open-receptive':
                loginAndRedirect();
                break;
            case 'update-receptive-notification-count':
                agentStorage.write('receptiveNotificationCount', data.count);
                showNotificationsFromCookie();
                break;
            case 'handle-logout':
                getWidgetFrame().src = getWidgetInitialSource();
                closeFeedback();
                break;
            case 'loaded-receptive-widget':
                widgetLoaded = true;
                break;
            }
        }
    
        function initialiseWidget(options, settings) {
            if (options.jwt || !options.user.id) {
                return;
            }
            var feedbackSettings = _.extend(settings, {
                'triggerColor':    '#' + settings.triggerColor,
                'triggerPosition': settings.triggerPosition.toLowerCase()
            });
    
            registerTurbolinksHook();
            var positionInfo = getTriggerPositions(feedbackSettings);
    
            pendo.designerv2.addStylesToPage(
                'pendo-feedback-styles',
                getPseudoStyles(positionInfo.horizontalPosition)
            );
            if (!settings.customTrigger) {
                createTrigger(feedbackSettings, positionInfo);
            }
            initialiseWidgetFrame(positionInfo.horizontalPosition);
        }
    
        function getTriggerPositions(settings) {
            var positions = settings.triggerPosition.split('_');
            return {
                'horizontalPosition': positions[1],
                'verticalPosition':   positions[0]
            };
        }
    
        function getHorizontalPositionStyles(positionInfo) {
            if (positionInfo.horizontalPosition === 'left') {
                return {
                    'transform-origin':  'center left',
                    'left':              '23px',
                    'animation':         'pendoFeedbackSlideIn-left 0.2s 0s 1 alternate forwards',
                    '-webkit-animation': 'pendoFeedbackSlideIn-left 0.2s 0s 1 alternate forwards'
                };
            } else {
                return {
                    'right':             '0px',
                    'animation':         'pendoFeedbackSlideIn 0.2s 0s 1 alternate forwards',
                    '-webkit-animation': 'pendoFeedbackSlideIn 0.2s 0s 1 alternate forwards'
                };
            }
        }
    
        function getVerticalPositionStyles(positionInfo) {
            //eslint-disable-next-line default-case
            switch (positionInfo.verticalPosition) {
            case 'top':
                return {
                    'top': ' 10%'
                };
            case 'middle':
                return {
                    'top': ' 45%'
                };
            case 'bottom':
                return {
                    'bottom': ' 20%'
                };
            }
        }
    
        function buildBaseElement(id, styles, type) {
            return {
                'props': {
                    'id':    id,
                    'style': styles
                },
                'type': type
            };
        }
    
        function getTurboLinkAttribute() {
            return { 'data-turbolinks-permanent': '' };
        }
    
        function buildOuterTriggerDiv(positionInfo) {
            var horizontalStyles = getHorizontalPositionStyles(positionInfo);
            var verticalStyles = getVerticalPositionStyles(positionInfo);
    
            var styles = {
                'position': 'fixed',
                'height':   '43px',
                'opacity':  '1 !important',
                'z-index':  '9001'
            };
    
            var domObj = buildBaseElement(elemIds.feedbackTrigger, styles, 'div');
    
            _.extend(domObj.props, getTurboLinkAttribute());
            _.extend(domObj.props.style, horizontalStyles);
            _.extend(domObj.props.style, verticalStyles);
            return domObj;
        }
    
        function buildNotification() {
            var styles = {
                'background-color':          '#D85039',
                'color':                     '#fff',
                'border-radius':             '50%',
                'height':                    '17px',
                'width':                     '17px',
                'position':                  'absolute',
                'right':                     '-6px',
                'top':                       '-8px',
                'visibility':                'hidden',
                'z-index':                   '1',
                'animation':                 'pendoFeedbackPulse',
                'animation-fill-mode':       'both',
                'animation-duration':        '1s',
                'animation-delay':           '1s',
                'animation-iteration-count': '1'
            };
            var domObj = buildBaseElement(
                'feedback-trigger-notification',
                styles,
                'span'
            );
            return domObj;
        }
    
        function buildTriggerButton(settings, positionInfo) {
            var borderRadius;
            if (positionInfo.horizontalPosition === 'left') {
                borderRadius = '0 0 5px 5px';
            } else {
                borderRadius = '3px 3px 0 0';
            }
    
            var styles = {
                'border':           'none',
                'padding':          '11px 18px 14px 18px',
                'background-color': settings.triggerColor,
                'border-radius':    borderRadius,
                'font-size':        '15px',
                'color':            '#fff',
                'box-shadow':       '0 -5px 9px rgba(0,0,0,.16)',
                'cursor':           'pointer',
                'text-align':       'left'
            };
    
            var triggerButtonAction = {
                'actions': [
                    {
                        'action':      'openFeedback',
                        'destination': 'Global',
                        'eventType':   'click',
                        'parameters':  [],
                        'source':      elemIds.feedbackTriggerButton,
                        'uiMetadata':  {}
                    }
                ]
            };
    
            var domObj = buildBaseElement(
                elemIds.feedbackTriggerButton,
                styles,
                'button'
            );
    
            _.extend(domObj, triggerButtonAction);
            return _.extend(domObj, { 'content': settings.triggerText });
        }
    
        function createTrigger(settings, positionInfo) {
            var triggerElement = buildOuterTriggerDiv(positionInfo);
            var notificationElement = buildNotification();
            var triggerButtonElement = buildTriggerButton(settings, positionInfo);
            var psuedoStyles = {
                'type':  'style',
                'props': {
                    'type':   'text/css',
                    'scoped': 'scoped'
                },
                'css': [
                    {
                        'selector': '#feedback-trigger button:hover',
                        'styles':   {
                            'box-shadow': '0 -5px 20px rgba(0,0,0,.19)',
                            'outline':    'none',
                            'background': '#3e566f'
                        }
                    },
                    {
                        'selector': '#feedback-trigger button:focus',
                        'styles':   {
                            'box-shadow': '0 -5px 20px rgba(0,0,0,.19)',
                            'outline':    'none',
                            'background': '#3e566f'
                        }
                    }
                ]
            };
    
            _.extend(triggerElement, {
                'children': [notificationElement, triggerButtonElement, psuedoStyles]
            });
    
            var mockStep = {};
            mockStep.eventRouter = new EventRouter();
            var triggerElementToAppend = BuildingBlockGuides.buildNodeFromJSON(
                triggerElement,
                mockStep
            );
            triggerElementToAppend.appendTo(getBody());
        }
    
        function registerTurbolinksHook() {
            if (typeof Turbolinks !== 'undefined') {
                //Turbolinks copies the src of the old iframe to the new iframe on page transitions.
                //This causes the browser to re-request a feedback login using the same token.
                //Before page transition blank out the iframe src to force the widget to re auth.
                document.addEventListener('turbolinks:before-visit', function(
                    event
                ) {
                    var iframe = document.getElementById(elemIds.feedbackIframe);
                    if (iframe) {
                        iframe.src = getWidgetInitialSource();
                    }
                });
            }
        }
    
        function buildIframeWrapper(horizontalPosition) {
            var iframeWrapper = buildBaseElement(
                elemIds.feedbackWidget,
                getWidgetOriginalStyles(),
                'div'
            );
            _.extend(iframeWrapper, { 'data-turbolinks-permanent': 'true' });
            _.extend(iframeWrapper.props, {
                'class': 'buttonIs-' + horizontalPosition
            });
            return iframeWrapper;
        }
    
        function buildIframeContainer() {
            var iframeContainerStyles = {
                'width':  '100%',
                'height': '99.6%',
                'border': '0 none'
            };
            var iframeContainer = buildBaseElement(
                elemIds.feedbackIframe,
                iframeContainerStyles,
                'iframe'
            );
            _.extend(iframeContainer.props, { 'src': getWidgetInitialSource() });
    
            return iframeContainer;
        }
    
        function getWidgetVisibleButtonStyles(buttonStylePosition) {
            var visibleButtonStyles;
            if (buttonStylePosition === 'left') {
                visibleButtonStyles = {
                    'selector': '.buttonIs-left.visible',
                    'styles':   {
                        'left':                '0px',
                        'width':               '470px',
                        'animation-direction': 'alternate-reverse',
                        'animation':           'pendoFeedbackSlideFromLeft 0.5s 0s 1 alternate both',
                        '-webkit-animation':   'pendoFeedbackSlideFromLeft 0.5s 0s 1 alternate both',
                        'z-index':             '9002'
                    }
                };
            } else {
                visibleButtonStyles = {
                    'selector': '.buttonIs-right.visible',
                    'styles':   {
                        'right':               '0',
                        'width':               '470px',
                        'animation-direction': 'alternate-reverse',
                        'animation':           'pendoFeedbackSlideFromRight 0.5s 0s 1 alternate both',
                        '-webkit-animation':   'pendoFeedbackSlideFromRight 0.5s 0s 1 alternate both',
                        'z-index':             '9002'
                    }
                };
            }
    
            return {
                'type':  'style',
                'props': {
                    'type':   'text/css',
                    'scoped': 'scoped'
                },
                'css': [visibleButtonStyles]
            };
        }
    
        function initialiseWidgetFrame(horizontalPosition) {
            var buttonStyles = getWidgetVisibleButtonStyles(horizontalPosition);
            var iframeElement = buildIframeWrapper(horizontalPosition);
            _.extend(iframeElement, {
                'children': [buildIframeContainer(), buttonStyles]
            });
    
            var iframeElementToAppend = BuildingBlockGuides.buildNodeFromJSON(
                iframeElement
            );
            iframeElementToAppend.appendTo(getBody());
    
            subscribeToIframeMessages();
        }
    
        function getWidgetOriginalStyles() {
            return {
                'height':                     '100%',
                'position':                   'fixed',
                'right':                      '0',
                'top':                        '0',
                'width':                      '0',
                'background-color':           '#f7f7f7',
                'transition':                 'animation 0.4s ease-in-out',
                'box-shadow':                 '0 5px 40px rgba(0,0,0,.46)',
                'display':                    'block !important',
                '-webkit-overflow-scrolling': 'touch',
                'overflow-y':                 'hidden'
            };
        }
    
        var isFeedbackLoaded = function() {
            return widgetLoaded;
        };
    
        function canInitFeedback(options) {
            var pendoOptions = options || getOptionsCopy();
            if (isUnsupportedIE()) return;
    
            if(!vendorId || !vendorApiHome || !siteUrl || !feedbackAllowedProductId) return;
    
            if(!_.has(pendoOptions.visitor, 'id')) {
                pendo.log('Not valid visitor id');
                return;
            }
    
            if(isAnonymousVisitor(pendoOptions.visitor.id)) return;
    
            if(!_.has(pendoOptions.account, 'id')) {
                pendo.log('The current visitor is not associated with an account.');
                return; //This is temporary until we figure out how to hand no account.id
            }
    
            return true;
        }
    
        function init(pendoOptions, feedbackSettings) {
            vendorId = feedbackSettings.vendorId;
            vendorApiHome = feedbackSettings.apiUrl;
            siteUrl = feedbackSettings.siteUrl;
            feedbackAllowedProductId = feedbackSettings.productId;
    
            if(!canInitFeedback(pendoOptions)) return q.reject();
    
            var feedbackOptions = convertPendoToFeedbackOptions(pendoOptions);
    
            try {
                if (feedbackSettings.type === 'WIDGET') {
                    initialiseWidget(feedbackOptions, feedbackSettings);
                }
                showNotificationsFromCookie();
        
                initialized = true;
                return ping(feedbackOptions);
            } catch (e) {
                initialized = false;
                pendo.log(e, 'unhandled error while initializing feedback');
                return q.reject(e);
            }
        }
    
        function getEmail(options) {
            if(_.isUndefined(options.user) || _.isUndefined(options.user.id)) {
                return 'noemail+' + pendo.randomString(32) + '@pendo.io';
            }
            return 'noemail+' + options.user.id + '@pendo.io';
        }
    
        function getFullName(options) {
            if(!_.isUndefined(options.user.firstName) || !_.isUndefined(options.user.lastName)) {
                var fullNameArr = [];
                if (!_.isUndefined(options.user.firstName)) {
                    fullNameArr.push(options.user.firstName);
                }
                if (!_.isUndefined(options.user.lastName)) {
                    fullNameArr.push(options.user.lastName);
                }
                return fullNameArr.join(' ');
            }
            if(_.isUndefined(options.user) || _.isUndefined(options.user.id)) {
                return 'No Name Provided' + pendo.randomString(32);
            }
            return 'No Name Provided' + options.user.id;
        }
    
        function convertPendoToFeedbackOptions(options) {
            var optionsClone = JSON.parse(JSON.stringify(options)); //underscore doesn't have cloneDeep
            var visitor = optionsClone.visitor;
            delete optionsClone.visitor;
            optionsClone.user = visitor;
            _.extend(optionsClone, { 'vendor': { 'id': vendorId } });
            _.extend(optionsClone.user, { 'allowed_products': [{ 'id': feedbackAllowedProductId }] });
    
            if(_.isUndefined(optionsClone.account.is_paying)) {
                optionsClone.account.is_paying = true;
            }
    
            if(_.isUndefined(optionsClone.user.email)) {
                optionsClone.user.email = getEmail(optionsClone);
            }
    
            if(_.isUndefined(optionsClone.user.full_name)) {
                optionsClone.user.full_name = getFullName(optionsClone);
            }
            return optionsClone;
        }
    
        function getInitialized() {
            return initialized;
        }
    
        function removeFeedbackWidget() {
            pendo.P2AutoLaunch.removeElement('feedback-trigger');
            pendo.P2AutoLaunch.removeElement('feedback-widget');
            pendo.P2AutoLaunch.removeElement('pendo-feedback-styles');
            pendo.P2AutoLaunch.removeElement('feedback-overlay');
            pendo.P2AutoLaunch.removeElement('feedback-widget_iframe');
            resetFeedbackToInitialState();
        }
    
    
        return {
            'ping':                          ping,
            'init':                          init,
            'initialized':                   getInitialized,
            'loginAndRedirect':              loginAndRedirect,
            'openFeedback':                  openFeedback,
            'initializeFeedbackOnce':        initializeFeedbackOnce,
            'isFeedbackLoaded':              isFeedbackLoaded,
            'convertPendoToFeedbackOptions': convertPendoToFeedbackOptions,
            'isUnsupportedIE':               isUnsupportedIE,
            'removeFeedbackWidget':          removeFeedbackWidget
        };
    })();
    
    pendo.feedback = Feedback;
    
    function disableUnusedMethodsPendoCoreOff(methodsToRemove) {
        _.each(methodsToRemove, function(methodToRemove) {
            if(pendo[methodToRemove]) {
                pendo[methodToRemove] = function() {
                    //eslint-disable-next-line no-console
                    console.warn('This functionality is not supported by your subscription.');
                };
            }
        });
    }
    
    if(!pendoCore) {
        var guidesCoreOff =  [
            'initGuides',
            'loadGuides',
            'findGuideByName',
            'hideGuides',
            'onGuideDismissed',
            'onGuideAdvanced',
            'onGuidePrevious',
            'startGuides',
            'stopGuides',
            'toggleLauncher',
            'showLauncher',
            'hideLauncher',
            'removeLauncher',
            'defaultCssUrl',
            'areGuidesDisabled',
            'setGuidesDisabled',
            'flexElement',
            'GuideFactory',
            'P2AutoLaunch',
            'BuildingBlocks',
            'designer',
            'advancedGuide',
            'dismissedGuide',
            'findGuideBy',
            'findGuideById',
            'findStepInGuide',
            'getElementForGuideStep',
            'guideContent',
            'guideDev',
            'isGuideShown',
            'seenGuide',
            'showGuideById',
            'showGuideByName',
            'showGuideByName',
            'showPreview',
            'stageGuideEvent',
            'waitThenStartGuides',
            '_addCloseButton',
            '_addGuideToLauncher',
            '_shouldAutoDisplayGuide',
            '_showElementGuide',
            '_showGuide',
            '_showLightboxGuide',
            '_updateGuideStepStatus',
            'badgeDiv',
            'badgesShown',
            'isBadge',
            'placeBadge',
            'removeAllBadges',
            '_addCredits',
            '_createGuideEvent',
            '_createToolTip',
            '_getNextStepInMultistep',
            '_getOpacityStyles',
            '_get_offset',
            '_get_screen_dim',
            '_get_tooltip_dimensions',
            '_isInViewport',
            '_isOldIE',
            '_sendGuideEvent',
            'findModuleByName',
            'guidesProcessingThreadHandle',
            'initLauncher',
            'getTooltipDivId',
            'receiveDomStructureJson',
            'setupWatchOnTooltip',
            'testUrlForStep',
            'hasModule'
        ];
    
        var eventsCoreOff = [
            'flushEventCache',
            'flushNow',
            'getEventCache',
            'isSendingEvents',
            'processEventCache',
            'send_event',
            'startSendingEvents',
            'stopSendingEvents',
            'track',
            '_sendEvent',
            '_stopEvents',
            '_storeInCache',
            '_writeEventImgTag',
            '_writeImgTag',
            'events',
            'eventCache',
            'attachEvent',
            'detachEvent',
            'getText'
        ];
    
        var functionsCoreOff = guidesCoreOff.concat(eventsCoreOff);
    
        disableUnusedMethodsPendoCoreOff(functionsCoreOff);
    }
    
    /**
    * Called caboose b/c this needs to be the last file concat'd into
    * the bundled Agent build.
    *
    */
    
    // Delay execution of these methods until initialize is called:
    _.each(['identify', 'updateOptions', 'pageLoad'], function(method) {
        var originalMethod = pendo[method];
        pendo[method] = function() {
            try {
                if (isReady()) {
                    originalMethod.apply(this, arguments);
                } else {
                    enqueueCall(method, arguments);
                }
            } catch (e) {
                writeException(e);
            }
        };
    });
    
    function autoInitialize() {
        if (isReady()) {
            pendo.log('already running');
            return;
        }
    
        if (window.pendo_options) { // Support pre-2.0 initialization
            initialize(window.pendo_options);
        }
    
        flushCallQueue();
    
        flushEvery(SEND_INTERVAL);
    }
    
    whenLoadedCall(autoInitialize);
    
    })(); // END agent IIFE
    // GENERATED CODE
    pendo.defaultLauncher("<div class=\"_pendo-launcher-content_\" style=\"border-color:<%= data.color %>\">\n    <div class=\"_pendo-launcher-header_\">\n        <img src=\"<%= data.launcherBadgeUrl %>\"/>\n        <div class=\"_pendo-launcher-title_\"><%= data.title %></div>\n        <% if (data.enableSearch) { %>\n        <div class=\"_pendo-launcher-search-box_\">\n        <input type=\"text\" placeholder=\"Type here to start looking...\" />\n        </div>\n        <% } %>\n    </div>\n    <div class=\"_pendo-launcher-guide-listing_\">\n    <% pendo._.each(guides, function(guide) { %>\n        <div class=\"_pendo-launcher-item_\" id=\"launcher-<%= guide.id %>\">\n            <a href=\"javascript:void(0);\"><%= guide.name %></a>\n        </div>\n    <% }) %>\n    </div>\n    <% if (hidePoweredBy) { %>\n    <div class=\"_pendo-launcher-footer_\"></div>\n    <% } else { %>\n    <div class=\"_pendo-launcher-footer_ _pendo-launcher-footer-credits_\">\n        <span>powered by pendo</span>\n    </div>\n    <% } %>\n</div>\n", function(obj) {
    obj || (obj = {});
    var __t, __p = '', __j = Array.prototype.join;
    function print() { __p += __j.call(arguments, '') }
    with (obj) {
    __p += '<div class="_pendo-launcher-content_" style="border-color:' +
    ((__t = ( data.color )) == null ? '' : __t) +
    '">\n    <div class="_pendo-launcher-header_">\n        <img src="' +
    ((__t = ( data.launcherBadgeUrl )) == null ? '' : __t) +
    '"/>\n        <div class="_pendo-launcher-title_">' +
    ((__t = ( data.title )) == null ? '' : __t) +
    '</div>\n        ';
     if (data.enableSearch) { ;
    __p += '\n        <div class="_pendo-launcher-search-box_">\n        <input type="text" placeholder="Type here to start looking..." />\n        </div>\n        ';
     } ;
    __p += '\n    </div>\n    <div class="_pendo-launcher-guide-listing_">\n    ';
     pendo._.each(guides, function(guide) { ;
    __p += '\n        <div class="_pendo-launcher-item_" id="launcher-' +
    ((__t = ( guide.id )) == null ? '' : __t) +
    '">\n            <a href="javascript:void(0);">' +
    ((__t = ( guide.name )) == null ? '' : __t) +
    '</a>\n        </div>\n    ';
     }) ;
    __p += '\n    </div>\n    ';
     if (hidePoweredBy) { ;
    __p += '\n    <div class="_pendo-launcher-footer_"></div>\n    ';
     } else { ;
    __p += '\n    <div class="_pendo-launcher-footer_ _pendo-launcher-footer-credits_">\n        <span>powered by pendo</span>\n    </div>\n    ';
     } ;
    __p += '\n</div>\n';
    
    }
    return __p
    });
    })(window, document); // END config IIFE