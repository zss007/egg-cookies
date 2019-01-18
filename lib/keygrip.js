'use strict';

const debug = require('debug')('egg-cookies:keygrip');
const crypto = require('crypto');
const assert = require('assert');
const constantTimeCompare = require('scmp');

const replacer = {
  '/': '_',
  '+': '-',
  '=': '',
};

// patch from https://github.com/crypto-utils/keygrip

class Keygrip {
  constructor(keys) {
    assert(Array.isArray(keys) && keys.length, 'keys must be provided and should be an array');

    this.keys = keys;
    this.hash = 'sha256';
    this.cipher = 'aes-256-cbc';
  }

  // encrypt a message 加密信息，默认通过第一个 key 加密
  encrypt(data, key) {
    key = key || this.keys[0];
    const cipher = crypto.createCipher(this.cipher, key);
    return crypt(cipher, data);
  }

  // decrypt a single message 解密，默认会从 keys 数组先到后逐个 key 尝试解密
  // returns false on bad decrypts
  decrypt(data, key) {
    if (!key) {
      // decrypt every key 尝试所有key
      const keys = this.keys;
      for (let i = 0; i < keys.length; i++) {
        const value = this.decrypt(data, keys[i]);
        if (value !== false) return { value, index: i };
      }
      return false;
    }

    try {
      const cipher = crypto.createDecipher(this.cipher, key);
      return crypt(cipher, data);
    } catch (err) {
      debug('crypt error', err.stack);
      return false;
    }
  }

  // 签名，默认使用第一个 key
  sign(data, key) {
    // default to the first key
    key = key || this.keys[0];

    return crypto
      .createHmac(this.hash, key)
      .update(data)
      .digest('base64')
      .replace(/\/|\+|=/g, x => replacer[x]);
  }

  // 遍历 keys 判断签名是否正确
  verify(data, digest) {
    const keys = this.keys;
    for (let i = 0; i < keys.length; i++) {
      if (constantTimeCompare(new Buffer(digest), new Buffer(this.sign(data, keys[i])))) {
        debug('data %s match key %s', data, keys[i]);
        return i;
      }
    }
    return -1;
  }
}

function crypt(cipher, data) {
  const text = cipher.update(data, 'utf8');
  const pad = cipher.final();
  return Buffer.concat([ text, pad ]);
}

module.exports = Keygrip;
