'use strict';

const assert = require('assert');
const utility = require('utility');
const Keygrip = require('./keygrip');
const Cookie = require('./cookie');

const KEYS_ARRAY = Symbol('eggCookies:keysArray');
const KEYS = Symbol('eggCookies:keys');
const keyCache = new Map();

/**
 * cookies for egg
 * extend pillarjs/cookies, add encrypt and decrypt
 */

class Cookies {
  constructor(ctx, keys) {
    this[KEYS_ARRAY] = keys;
    this._keys = keys;
    this.ctx = ctx;
    this.secure = this.ctx.secure;
    this.app = ctx.app;
  }

  // 获取 keys
  get keys() {
    if (!this[KEYS]) {
      const keysArray = this[KEYS_ARRAY];
      assert(Array.isArray(keysArray), '.keys required for encrypt/sign cookies');
      // 做缓存处理
      const cache = keyCache.get(keysArray);
      if (cache) {
        this[KEYS] = cache;
      } else {
        this[KEYS] = new Keygrip(this[KEYS_ARRAY]);
        keyCache.set(keysArray, this[KEYS]);
      }
    }

    return this[KEYS];
  }

  /**
   * get cookie value by name 根据 name 获取 cookie 的值
   * @param  {String} name - cookie's name
   * @param  {Object} opts - cookies' options
   *            - {Boolean} signed - default to true
   *            - {Boolean} encrypt - default to false
   * @return {String} value - cookie's value
   */
  get(name, opts) {
    opts = opts || {};
    // 判断是否需要签名
    const signed = computeSigned(opts);

    // 获取请求头 cookie
    const header = this.ctx.get('cookie');
    if (!header) return;

    // 如果没有匹配到
    const match = header.match(getPattern(name));
    if (!match) return;

    // 获取 cookie 相应 key 的值
    let value = match[1];
    // 如果不加密不签名，直接返回 value
    if (!opts.encrypt && !signed) return value;

    // signed 如果签名
    if (signed) {
      const sigName = name + '.sig';
      // 如果没找到 xxx.sig 对应的值则直接返回
      const sigValue = this.get(sigName, { signed: false });
      if (!sigValue) return;

      const raw = name + '=' + value;
      // 验证是否签名存在
      const index = this.keys.verify(raw, sigValue);
      if (index < 0) {
        // can not match any key, remove ${name}.sig 如果没有匹配到，则移除 name 为 xxx.sig 的 cookie
        this.set(sigName, null, { path: '/', signed: false });
        return;
      }
      if (index > 0) {
        // not signed by the first key, update sigValue 更新签名为第一个 key 加密的值
        this.set(sigName, this.keys.sign(raw), { signed: false });
      }
      return value;
    }

    // encrypt
    value = utility.base64decode(value, true, 'buffer');
    const res = this.keys.decrypt(value);
    return res ? res.value.toString() : undefined;
  }

  // 设置 cookie
  set(name, value, opts) {
    opts = opts || {};
    const signed = computeSigned(opts);
    value = value || '';
    if (!this.secure && opts.secure) {
      throw new Error('Cannot send secure cookie over unencrypted connection');
    }

    // 获取响应头 set-cookie
    let headers = this.ctx.response.get('set-cookie') || [];
    if (!Array.isArray(headers)) headers = [ headers ];

    // encrypt 加密，前端无法读到真实的 cookie 值
    if (opts.encrypt) {
      value = value && utility.base64encode(this.keys.encrypt(value), true);
    }

    // http://browsercookielimits.squawky.net/ 如果长度超出
    if (value.length > 4093) {
      this.app.emit('cookieLimitExceed', { name, value, ctx: this.ctx });
    }

    const cookie = new Cookie(name, value, opts);

    // if user not set secure, reset secure to ctx.secure
    if (opts.secure === undefined) cookie.attrs.secure = this.secure;

    // 添加 cookie 到 cookies
    headers = pushCookie(headers, cookie);

    // signed 签名，签名后前端无法篡改这个 cookie
    if (signed) {
      cookie.value = value && this.keys.sign(cookie.toString());
      cookie.name += '.sig';
      // 添加到 cookies
      headers = pushCookie(headers, cookie);
    }

    // 设置相应头 set-cookie
    this.ctx.set('set-cookie', headers);
    return this;
  }
}

// 获取正则并缓存
const partternCache = new Map();
function getPattern(name) {
  const cache = partternCache.get(name);
  if (cache) return cache;
  const reg = new RegExp(
    '(?:^|;) *' +
    name.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&') +
    '=([^;]*)'
  );
  partternCache.set(name, reg);
  return reg;
}

// 判断是否需要签名，如果已经加密了则不签名
function computeSigned(opts) {
  // encrypt default to false, signed default to true.
  // disable singed when encrypt is true.
  if (opts.encrypt) return false;
  return opts.signed !== false;
}

// 添加 cookie 到 cookies 中
function pushCookie(cookies, cookie) {
  // 判断是否需要重写
  if (cookie.attrs.overwrite) {
    cookies = cookies.filter(c => !c.startsWith(cookie.name + '='));
  }
  cookies.push(cookie.toHeader());
  return cookies;
}

module.exports = Cookies;
