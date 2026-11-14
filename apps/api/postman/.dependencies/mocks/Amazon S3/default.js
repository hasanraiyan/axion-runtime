/**
 * Amazon S3 mock, scenario "default": S3 in one region.
 *
 * Buckets and objects behave as on S3 in us-east-1: objects come back byte for byte with their
 * ETag, metadata and checksums, listings page and group by delimiter, and multipart uploads
 * assemble.
 *
 * Sections: SCENARIO (this scenario's settings), DATA (test data), API (the endpoints and how
 * they behave), RUNTIME (routing, state, request parsing, the docs page and the server), and
 * META and SPEC (what the docs page shows, and what the mock takes from the API's spec).
 */
'use strict';

// ═══ SCENARIO ════════════════════════════════════════════════════════════════════════════════════
const SCENARIO = Object.freeze({"name":"default"});

// ═══ DATA ════════════════════════════════════════════════════════════════════════════════════════
const DATA = {
  "ERRORS": {
    "AccessDenied": {
      "status": 403,
      "message": "Access Denied"
    },
    "AuthorizationHeaderMalformed": {
      "status": 400,
      "message": "The authorization header is malformed; the authorization header requires three components: Credential, SignedHeaders, and Signature."
    },
    "BadDigest": {
      "status": 400,
      "message": "The Content-MD5 you specified did not match what we received."
    },
    "BucketAlreadyOwnedByYou": {
      "status": 409,
      "message": "Your previous request to create the named bucket succeeded and you already own it."
    },
    "BucketNotEmpty": {
      "status": 409,
      "message": "The bucket you tried to delete is not empty"
    },
    "EntityTooSmall": {
      "status": 400,
      "message": "Your proposed upload is smaller than the minimum allowed object size."
    },
    "InternalError": {
      "status": 500,
      "message": "We encountered an internal error. Please try again."
    },
    "InvalidArgument": {
      "status": 400,
      "message": "Invalid Argument"
    },
    "InvalidBucketName": {
      "status": 400,
      "message": "The specified bucket is not valid."
    },
    "InvalidPart": {
      "status": 400,
      "message": "One or more of the specified parts could not be found.  The part may not have been uploaded, or the specified entity tag may not match the part's entity tag."
    },
    "InvalidPartOrder": {
      "status": 400,
      "message": "The list of parts was not in ascending order. Parts must be ordered by part number."
    },
    "InvalidRange": {
      "status": 416,
      "message": "The requested range is not satisfiable"
    },
    "InvalidRequest": {
      "status": 400,
      "message": "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes."
    },
    "MalformedXML": {
      "status": 400,
      "message": "The XML you provided was not well-formed or did not validate against our published schema"
    },
    "MethodNotAllowed": {
      "status": 405,
      "message": "The specified method is not allowed against this resource."
    },
    "NoSuchBucket": {
      "status": 404,
      "message": "The specified bucket does not exist"
    },
    "NoSuchKey": {
      "status": 404,
      "message": "The specified key does not exist."
    },
    "NoSuchUpload": {
      "status": 404,
      "message": "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed."
    },
    "NotImplemented": {
      "status": 501,
      "message": "A header you provided implies functionality that is not implemented"
    },
    "PreconditionFailed": {
      "status": 412,
      "message": "At least one of the pre-conditions you specified did not hold"
    },
    "SlowDown": {
      "status": 503,
      "message": "Please reduce your request rate."
    }
  },
  "LIMITS": {
    "minPartSize": 5242880,
    "maxParts": 10000,
    "maxKeys": 1000,
    "maxDeleteKeys": 1000
  },
  "REGION": "us-east-1",
  "OWNER": {
    "ID": "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a",
    "DisplayName": "mock"
  }
};

// @endpoint GET /
// @endpoint PUT /:bucket
// @endpoint HEAD /:bucket
// @endpoint DELETE /:bucket
// @endpoint GET /:bucket
// @endpoint POST /:bucket
// @endpoint GET /:bucket/:key*
// @endpoint HEAD /:bucket/:key*
// @endpoint PUT /:bucket/:key*
// @endpoint DELETE /:bucket/:key*
// @endpoint POST /:bucket/:key*

// ═══ API ═════════════════════════════════════════════════════════════════════════════════════════
/* global SCENARIO, DATA, pm, store, route, provider, reply */
// S3's behaviour: buckets, objects (put, get with ranges and conditions, head, copy, delete, delete many),
// listings (v2 and v1, with prefix, delimiter and paging) and multipart uploads, with S3's
// XML and its errors. Objects keep their bytes exactly, with their ETag, metadata and
// checksums. Path-style (`/bucket/key`) and virtual-host-style (`bucket.s3.amazonaws.com/key`)
// requests both work. S3 routes on the query as well as the path (`?uploads`, `?list-type=2`),
// so each route below dispatches on it.

const { createHash, randomBytes } = require('crypto');
const { Buffer } = require('buffer');
const { ERRORS, LIMITS, REGION, OWNER } = DATA;

// ─── XML ───

const escapeXml = (value) => {
    return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
};
const unescapeXml = (value) => {
    return String(value).replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, '\'').replace(/&amp;/g, '&');
};

// An element from a value: a list repeats the element, an object nests elements, undefined is left out.
function element (name, value) {
    if (value === undefined || value === null) { return ''; }
    if (Array.isArray(value)) { return value.map((item) => { return element(name, item); }).join(''); }
    if (typeof value === 'object') { return `<${name}>${Object.entries(value).map(([key, item]) => { return element(key, item); }).join('')}</${name}>`; }

    return `<${name}>${escapeXml(value)}</${name}>`;
}

// A response document. S3's results carry its namespace; its errors don't.
function document (root, content, { namespace = true } = {}) {
    const body = element(root, content);

    return `<?xml version="1.0" encoding="UTF-8"?>\n${namespace ? body.replace(`<${root}>`, `<${root} xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`) : body}`;
}

// The text of every <tag>…</tag> in a document (S3's request bodies are flat enough for this).
const contents = (xml, tag) => { return [...String(xml).matchAll(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, 'g'))].map((m) => { return m[1]; }); };

const XML = { 'Content-Type': 'application/xml' };

// ─── Errors ───

const hex = (length) => { return randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length); };

class S3Error extends Error {
    constructor (code, extra = {}, headers = {}) {
        const { status, message } = ERRORS[code];

        super(message);
        this.status = status;
        this.headers = { ...XML, ...headers };
        this.body = document('Error', { Code: code, Message: message, ...extra, RequestId: hex(16).toUpperCase(), HostId: randomBytes(48).toString('base64') }, { namespace: false });
    }
}

function fail (code, extra, headers) {
    return new S3Error(code, extra, headers);
}

// ─── Values ───

const md5 = (data) => { return createHash('md5').update(data).digest(); };
const etagOf = (data) => { return `"${md5(data).toString('hex')}"`; };
const unquote = (etag) => { return String(etag || '').replace(/^W\//, '').replace(/"/g, ''); };
const isoTime = (ms) => { return new Date(ms).toISOString(); };
const httpTime = (ms) => { return new Date(ms).toUTCString(); };

const CHECKSUMS = ['crc32', 'crc32c', 'crc64nvme', 'sha1', 'sha256'];

// Bucket names: 3 to 63 lowercase letters, digits, dots and hyphens, starting and ending with a letter or digit.
const isBucketName = (name) => {
    return /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(name) && !name.includes('..') && !/^\d+\.\d+\.\d+\.\d+$/.test(name) && !name.startsWith('xn--');
};

// The body as uploaded. Newer AWS SDKs send `aws-chunked` bodies: hex-sized chunks, then
// trailers (usually the checksum); signed chunks carry `;chunk-signature=…` after the size.
function payload (ctx) {
    const sha = ctx.headers['x-amz-content-sha256'] || '';
    const encoding = ctx.headers['content-encoding'] || '';

    if (!sha.startsWith('STREAMING-') && !encoding.includes('aws-chunked')) { return { data: ctx.body, trailers: {} }; }

    const chunks = [];
    let offset = 0;

    while (offset < ctx.body.length) {
        const lineEnd = ctx.body.indexOf('\r\n', offset);

        if (lineEnd === -1) { break; }

        const size = parseInt(ctx.body.subarray(offset, lineEnd).toString().split(';')[0], 16);

        offset = lineEnd + 2;
        if (!size) { break; }
        chunks.push(ctx.body.subarray(offset, offset + size));
        offset += size + 2;
    }

    const trailers = Object.fromEntries(ctx.body.subarray(offset).toString().split('\r\n').filter((line) => { return line.includes(':'); })
        .map((line) => { return [line.slice(0, line.indexOf(':')).trim().toLowerCase(), line.slice(line.indexOf(':') + 1).trim()]; }));

    return { data: Buffer.concat(chunks), trailers };
}

// The checksums the client sent with an upload (as headers or aws-chunked trailers), kept to give back.
function checksumsOf (ctx, trailers) {
    return Object.fromEntries(CHECKSUMS.map((name) => { return [name, ctx.headers[`x-amz-checksum-${name}`] || trailers[`x-amz-checksum-${name}`]]; })
        .filter(([, value]) => { return value; }));
}

// The object's own headers, as an upload sets them and a download gives them back.
const OBJECT_HEADERS = ['content-type', 'cache-control', 'content-disposition', 'content-encoding', 'content-language', 'expires'];

function headersOf (ctx) {
    return {
        contentType: ctx.headers['content-type'] || 'binary/octet-stream',
        cacheControl: ctx.headers['cache-control'],
        contentDisposition: ctx.headers['content-disposition'],
        contentEncoding: (ctx.headers['content-encoding'] || '').split(',').map((e) => { return e.trim(); }).filter((e) => { return e && e !== 'aws-chunked'; }).join(', ') || undefined,
        contentLanguage: ctx.headers['content-language'],
        expires: ctx.headers.expires,
        metadata: Object.fromEntries(Object.entries(ctx.headers).filter(([name]) => { return name.startsWith('x-amz-meta-'); })
            .map(([name, value]) => { return [name.slice('x-amz-meta-'.length), value]; }))
    };
}

// ─── State ───

// Object descriptions are entities; their bytes are kept apart, so a listing doesn't load them.
const blobKey = (id) => { return `blob:${id}`; };
const readBlob = async (id) => { return Buffer.from((await pm.state.get(blobKey(id))) || '', 'base64'); };
const writeBlob = (id, data) => { return pm.state.set(blobKey(id), Buffer.from(data).toString('base64')); };

async function loadBucket (name) {
    const bucket = await store.get('bucket', name);

    if (!bucket) { throw fail('NoSuchBucket', { BucketName: name }); }

    return bucket;
}

async function loadObject (bucket, key) {
    await loadBucket(bucket);

    const object = await store.get('object', `${bucket}/${key}`);

    if (!object) { throw fail('NoSuchKey', { Key: key }); }

    return object;
}

async function saveObject (bucket, key, data, fields) {
    const id = `${bucket}/${key}`;

    await writeBlob(id, data);

    return store.save({ id, bucket, key, size: data.length, lastModified: Date.now(), ...fields }, 'object');
}

async function removeObject (bucket, key) {
    await store.remove('object', `${bucket}/${key}`);
    await pm.state.delete(blobKey(`${bucket}/${key}`));
}

// ─── Buckets ───

route('GET', '/', async () => {
    const buckets = (await store.all('bucket')).reverse();

    return reply(200, document('ListAllMyBucketsResult', {
        Owner: OWNER,
        Buckets: { Bucket: buckets.map((b) => { return { Name: b.id, CreationDate: isoTime(b.created), BucketRegion: b.region }; }) }
    }), XML);
});

route('PUT', '/:bucket', async (ctx, name) => {
    if (Object.keys(ctx.query).length) { throw fail('NotImplemented'); }
    if (!isBucketName(name)) { throw fail('InvalidBucketName', { BucketName: name }); }
    // A bucket you already own: in us-east-1, for legacy compatibility, S3 answers 200 again;
    // anywhere else it is BucketAlreadyOwnedByYou.
    const existing = await store.get('bucket', name);

    if (existing) {
        if (existing.region !== REGION) { throw fail('BucketAlreadyOwnedByYou', { BucketName: name }); }

        return reply(200, undefined, { Location: `/${name}` });
    }

    const location = contents(ctx.body.toString(), 'LocationConstraint')[0];

    await store.save({ id: name, created: Date.now(), region: location || REGION }, 'bucket');

    return reply(200, undefined, { Location: `/${name}` });
});

route('HEAD', '/:bucket', async (ctx, name) => {
    const bucket = await loadBucket(name);

    return reply(200, undefined, { 'x-amz-bucket-region': bucket.region });
});

route('DELETE', '/:bucket', async (ctx, name) => {
    await loadBucket(name);
    if ((await store.all('object')).some((o) => { return o.bucket === name; })) { throw fail('BucketNotEmpty', { BucketName: name }); }
    await store.remove('bucket', name);

    return reply(204);
});

// ─── Listings ───

// A page of keys under `prefix`, keys sharing everything up to the next `delimiter` rolled up
// into one common prefix, from `start` on. The continuation token says where the page stopped.
async function page (bucket, { prefix = '', delimiter = '', maxKeys = LIMITS.maxKeys, after = '', afterPrefix = false }) {
    const objects = (await store.all('object')).filter((o) => {
        return o.bucket === bucket && o.key.startsWith(prefix) && o.key > after && !(afterPrefix && o.key.startsWith(after));
    }).sort((a, b) => { return a.key < b.key ? -1 : 1; });
    const keys = [];
    const prefixes = [];
    let last = null;
    let truncated = false;

    for (const object of objects) {
        const rest = object.key.slice(prefix.length);
        const cut = delimiter ? rest.indexOf(delimiter) : -1;
        const common = cut === -1 ? null : prefix + rest.slice(0, cut + delimiter.length);

        if (common && prefixes.includes(common)) { continue; }
        if (keys.length + prefixes.length >= maxKeys) { truncated = true; break; }
        if (common) { prefixes.push(common); last = { after: common, afterPrefix: true }; }
        else { keys.push(object); last = { after: object.key, afterPrefix: false }; }
    }

    return { keys, prefixes, truncated, last };
}

const contentsOf = (object, encode) => {
    return { Key: encode(object.key), LastModified: isoTime(object.lastModified), ETag: object.etag, ...(object.checksumAlgorithm ? { ChecksumAlgorithm: object.checksumAlgorithm } : {}), Size: object.size, StorageClass: 'STANDARD' };
};

async function listV2 (bucket, q) {
    const token = q['continuation-token'] ? JSON.parse(Buffer.from(q['continuation-token'], 'base64url').toString()) : null;
    const maxKeys = Math.min(q['max-keys'] === undefined ? LIMITS.maxKeys : Number(q['max-keys']), LIMITS.maxKeys);
    const encode = q['encoding-type'] === 'url' ? encodeURIComponent : (key) => { return key; };
    const result = await page(bucket, { prefix: q.prefix, delimiter: q.delimiter, maxKeys, ...(token || { after: q['start-after'] || '' }) });

    return document('ListBucketResult', {
        Name: bucket,
        Prefix: encode(q.prefix || ''),
        ...(q.delimiter ? { Delimiter: encode(q.delimiter) } : {}),
        MaxKeys: maxKeys,
        ...(q['encoding-type'] ? { EncodingType: q['encoding-type'] } : {}),
        KeyCount: result.keys.length + result.prefixes.length,
        IsTruncated: result.truncated,
        ...(q['continuation-token'] ? { ContinuationToken: q['continuation-token'] } : {}),
        ...(result.truncated ? { NextContinuationToken: Buffer.from(JSON.stringify(result.last)).toString('base64url') } : {}),
        ...(q['start-after'] ? { StartAfter: encode(q['start-after']) } : {}),
        Contents: result.keys.map((o) => { return contentsOf(o, encode); }),
        CommonPrefixes: result.prefixes.map((p) => { return { Prefix: encode(p) }; })
    });
}

async function listV1 (bucket, q) {
    const maxKeys = Math.min(q['max-keys'] === undefined ? LIMITS.maxKeys : Number(q['max-keys']), LIMITS.maxKeys);
    const encode = q['encoding-type'] === 'url' ? encodeURIComponent : (key) => { return key; };
    const result = await page(bucket, { prefix: q.prefix, delimiter: q.delimiter, maxKeys, after: q.marker || '' });

    return document('ListBucketResult', {
        Name: bucket,
        Prefix: encode(q.prefix || ''),
        Marker: encode(q.marker || ''),
        ...(result.truncated && q.delimiter ? { NextMarker: encode(result.last.after) } : {}),
        MaxKeys: maxKeys,
        ...(q.delimiter ? { Delimiter: encode(q.delimiter) } : {}),
        ...(q['encoding-type'] ? { EncodingType: q['encoding-type'] } : {}),
        IsTruncated: result.truncated,
        Contents: result.keys.map((o) => { return { ...contentsOf(o, encode), Owner: OWNER }; }),
        CommonPrefixes: result.prefixes.map((p) => { return { Prefix: encode(p) }; })
    });
}

route('GET', '/:bucket', async (ctx, name) => {
    const bucket = await loadBucket(name);
    const q = ctx.query;

    if ('location' in q) { return reply(200, document('LocationConstraint', bucket.region === 'us-east-1' ? '' : bucket.region), XML); }
    if ('uploads' in q) {
        const uploads = (await store.all('upload')).filter((u) => { return u.bucket === name; });

        return reply(200, document('ListMultipartUploadsResult', {
            Bucket: name, KeyMarker: '', UploadIdMarker: '', MaxUploads: 1000, IsTruncated: false,
            Upload: uploads.map((u) => { return { Key: u.key, UploadId: u.id, Initiator: OWNER, Owner: OWNER, StorageClass: 'STANDARD', Initiated: isoTime(u.initiated) }; })
        }), XML);
    }
    if (['versioning', 'acl', 'policy', 'cors', 'tagging', 'lifecycle', 'website', 'encryption', 'versions', 'notification'].some((sub) => { return sub in q; })) { throw fail('NotImplemented'); }

    return reply(200, q['list-type'] === '2' ? await listV2(name, q) : await listV1(name, q), XML);
});

// Delete many: <Delete><Object><Key>…</Key></Object>…<Quiet>true</Quiet></Delete>.
route('POST', '/:bucket', async (ctx, name) => {
    await loadBucket(name);
    if (!('delete' in ctx.query)) { throw fail('MethodNotAllowed'); }

    const body = ctx.body.toString();
    const keys = contents(body, 'Object').map((object) => { return unescapeXml(contents(object, 'Key')[0] || ''); });

    if (!body.includes('<Delete') || !keys.length || keys.length > LIMITS.maxDeleteKeys) { throw fail('MalformedXML'); }
    for (const key of keys) { await removeObject(name, key); }

    const quiet = (contents(body, 'Quiet')[0] || '').trim() === 'true';

    return reply(200, document('DeleteResult', { Deleted: quiet ? [] : keys.map((key) => { return { Key: key }; }) }), XML);
});

// ─── Objects ───

// Conditional reads: If-Match and If-Unmodified-Since fail with 412; If-None-Match and
// If-Modified-Since answer 304 when nothing changed.
function checkConditions (ctx, object) {
    const h = ctx.headers;
    const etag = unquote(object.etag);
    const modified = Math.floor(object.lastModified / 1000) * 1000;

    if (h['if-match'] && !h['if-match'].split(',').map(unquote).some((tag) => { return tag === etag || tag === '*'; })) { throw fail('PreconditionFailed', { Condition: 'If-Match' }); }
    if (h['if-unmodified-since'] && modified > Date.parse(h['if-unmodified-since'])) { throw fail('PreconditionFailed', { Condition: 'If-Unmodified-Since' }); }

    const notModified = h['if-none-match'] ? h['if-none-match'].split(',').map(unquote).some((tag) => { return tag === etag || tag === '*'; }) :
        Boolean(h['if-modified-since']) && modified <= Date.parse(h['if-modified-since']);

    return notModified;
}

// The headers a download (or HEAD) gives: the object's own, its metadata, and its checksums when asked for.
function objectHeaders (ctx, object) {
    const q = ctx.query;

    return {
        'Content-Type': q['response-content-type'] || object.contentType,
        ETag: object.etag,
        'Last-Modified': httpTime(object.lastModified),
        'Accept-Ranges': 'bytes',
        'x-amz-server-side-encryption': 'AES256',
        ...(object.parts ? { 'x-amz-mp-parts-count': String(object.parts) } : {}),
        ...Object.fromEntries([
            ['Cache-Control', q['response-cache-control'] || object.cacheControl],
            ['Content-Disposition', q['response-content-disposition'] || object.contentDisposition],
            ['Content-Encoding', q['response-content-encoding'] || object.contentEncoding],
            ['Content-Language', q['response-content-language'] || object.contentLanguage],
            ['Expires', q['response-expires'] || object.expires]
        ].filter(([, value]) => { return value; })),
        ...Object.fromEntries(Object.entries(object.metadata || {}).map(([name, value]) => { return [`x-amz-meta-${name}`, value]; })),
        ...(ctx.headers['x-amz-checksum-mode'] === 'ENABLED' ?
            Object.fromEntries(Object.entries(object.checksums || {}).map(([name, value]) => { return [`x-amz-checksum-${name}`, value]; })) : {})
    };
}

// `bytes=a-b`, `bytes=a-` or `bytes=-n`, within the object.
function rangeOf (header, size) {
    const match = /^bytes=(\d*)-(\d*)$/.exec(String(header).trim());

    if (!match || (!match[1] && !match[2])) { return null; }

    const start = match[1] ? Number(match[1]) : Math.max(0, size - Number(match[2]));
    const end = match[1] && match[2] ? Math.min(Number(match[2]), size - 1) : size - 1;

    if (start >= size || start > end) { throw fail('InvalidRange', { RangeRequested: header, ActualObjectSize: size }, { 'Content-Range': `bytes */${size}` }); }

    return { start, end };
}

route('GET', '/:bucket/:key*', async (ctx, bucket, key) => {
    if (ctx.query.uploadId) { throw fail('NotImplemented'); }

    const object = await loadObject(bucket, key);
    const headers = objectHeaders(ctx, object);

    if (checkConditions(ctx, object)) { return reply(304, undefined, { ETag: object.etag, 'Last-Modified': headers['Last-Modified'] }); }

    const data = await readBlob(object.id);
    const range = ctx.headers.range && rangeOf(ctx.headers.range, data.length);

    // A part of the object doesn't carry the whole object's checksum (a client would check the part against it).
    if (range) {
        const partial = Object.fromEntries(Object.entries(headers).filter(([name]) => { return !name.startsWith('x-amz-checksum-'); }));

        return reply(206, data.subarray(range.start, range.end + 1), {
            ...partial, 'Content-Range': `bytes ${range.start}-${range.end}/${data.length}`, 'Content-Length': String(range.end - range.start + 1)
        });
    }

    return reply(200, data, { ...headers, 'Content-Length': String(data.length) });
});

route('HEAD', '/:bucket/:key*', async (ctx, bucket, key) => {
    const object = await loadObject(bucket, key);
    const headers = objectHeaders(ctx, object);

    if (checkConditions(ctx, object)) { return reply(304, undefined, { ETag: object.etag }); }

    return reply(200, undefined, { ...headers, 'Content-Length': String(object.size) });
});

async function copyObject (ctx, bucket, key) {
    const source = decodeURIComponent(ctx.headers['x-amz-copy-source'].split('?')[0]).replace(/^\//, '');
    const [sourceBucket, ...rest] = source.split('/');
    const sourceKey = rest.join('/');
    const original = await loadObject(sourceBucket, sourceKey);
    const replace = ctx.headers['x-amz-metadata-directive'] === 'REPLACE';

    if (sourceBucket === bucket && sourceKey === key && !replace) { throw fail('InvalidRequest'); }

    const fields = replace ? headersOf(ctx) : {
        contentType: original.contentType, cacheControl: original.cacheControl, contentDisposition: original.contentDisposition,
        contentEncoding: original.contentEncoding, contentLanguage: original.contentLanguage, expires: original.expires, metadata: original.metadata
    };
    const data = await readBlob(original.id);
    const copy = await saveObject(bucket, key, data, { ...fields, etag: original.parts ? original.etag : etagOf(data), checksums: original.checksums, parts: original.parts });

    return reply(200, document('CopyObjectResult', { LastModified: isoTime(copy.lastModified), ETag: copy.etag }), XML);
}

route('PUT', '/:bucket/:key*', async (ctx, bucket, key) => {
    await loadBucket(bucket);

    const q = ctx.query;

    if (q.uploadId) { return uploadPart(ctx, bucket, key); }
    if (['tagging', 'acl', 'retention', 'legal-hold'].some((sub) => { return sub in q; })) { throw fail('NotImplemented'); }
    if (ctx.headers['x-amz-copy-source']) { return copyObject(ctx, bucket, key); }

    const { data, trailers } = payload(ctx);

    if (ctx.headers['content-md5'] && ctx.headers['content-md5'] !== md5(data).toString('base64')) { throw fail('BadDigest'); }
    if (ctx.headers['if-none-match'] === '*' && await store.get('object', `${bucket}/${key}`)) { throw fail('PreconditionFailed', { Condition: 'If-None-Match' }); }

    const checksums = checksumsOf(ctx, trailers);
    const object = await saveObject(bucket, key, data, {
        ...headersOf(ctx), etag: etagOf(data), checksums,
        checksumAlgorithm: Object.keys(checksums)[0] ? Object.keys(checksums)[0].toUpperCase() : undefined
    });

    return reply(200, undefined, {
        ETag: object.etag,
        'x-amz-server-side-encryption': 'AES256',
        ...Object.fromEntries(Object.entries(checksums).map(([name, value]) => { return [`x-amz-checksum-${name}`, value]; }))
    });
});

route('DELETE', '/:bucket/:key*', async (ctx, bucket, key) => {
    await loadBucket(bucket);
    if (ctx.query.uploadId) { return abortUpload(ctx, bucket, key); }
    await removeObject(bucket, key);

    return reply(204);
});

// ─── Multipart uploads ───

async function loadUpload (bucket, key, id) {
    const upload = await store.get('upload', id);

    if (!upload || upload.bucket !== bucket || upload.key !== key) { throw fail('NoSuchUpload', { UploadId: id }); }

    return upload;
}

async function uploadPart (ctx, bucket, key) {
    const upload = await loadUpload(bucket, key, ctx.query.uploadId);
    const number = Number(ctx.query.partNumber);

    if (!Number.isInteger(number) || number < 1 || number > LIMITS.maxParts) {
        throw fail('InvalidArgument', { ArgumentName: 'partNumber', ArgumentValue: ctx.query.partNumber });
    }

    const { data } = payload(ctx);
    const etag = etagOf(data);

    await writeBlob(`part:${upload.id}:${number}`, data);
    await store.save({ id: `${upload.id}:${number}`, upload: upload.id, number, size: data.length, etag }, 'part');

    return reply(200, undefined, { ETag: etag, 'x-amz-server-side-encryption': 'AES256' });
}

async function abortUpload (ctx, bucket, key) {
    const upload = await loadUpload(bucket, key, ctx.query.uploadId);

    for (const part of await store.all('part')) {
        if (part.upload === upload.id) {
            await store.remove('part', part.id);
            await pm.state.delete(blobKey(`part:${upload.id}:${part.number}`));
        }
    }
    await store.remove('upload', upload.id);

    return reply(204);
}

route('POST', '/:bucket/:key*', async (ctx, bucket, key) => {
    await loadBucket(bucket);

    if ('uploads' in ctx.query) {
        const upload = await store.save({ id: randomBytes(48).toString('base64url'), bucket, key, initiated: Date.now(), ...headersOf(ctx) }, 'upload');

        return reply(200, document('InitiateMultipartUploadResult', { Bucket: bucket, Key: key, UploadId: upload.id }), XML);
    }
    if (!ctx.query.uploadId) { throw fail('MethodNotAllowed'); }

    // Complete: the listed parts, in ascending order, each but the last at least 5 MiB.
    const upload = await loadUpload(bucket, key, ctx.query.uploadId);
    const listed = contents(ctx.body.toString(), 'Part').map((part) => {
        return { number: Number(contents(part, 'PartNumber')[0]), etag: unquote(unescapeXml(contents(part, 'ETag')[0] || '')) };
    });

    if (!listed.length) { throw fail('MalformedXML'); }
    // The order is checked before any part is.
    if (listed.some((wanted, index) => { return index > 0 && wanted.number <= listed[index - 1].number; })) { throw fail('InvalidPartOrder'); }

    const parts = [];

    for (const [index, wanted] of listed.entries()) {
        const part = await store.get('part', `${upload.id}:${wanted.number}`);

        if (!part || unquote(part.etag) !== wanted.etag) { throw fail('InvalidPart', { UploadId: upload.id, PartNumber: wanted.number, ETag: wanted.etag }); }
        if (index < listed.length - 1 && part.size < LIMITS.minPartSize) {
            throw fail('EntityTooSmall', { ProposedSize: part.size, MinSizeAllowed: LIMITS.minPartSize, PartNumber: part.number, ETag: part.etag });
        }
        parts.push(part);
    }

    const data = Buffer.concat(await Promise.all(parts.map((part) => { return readBlob(`part:${upload.id}:${part.number}`); })));
    // A multipart ETag is the MD5 of the parts' MD5s, then a dash and the number of parts.
    const etag = `"${md5(Buffer.concat(parts.map((part) => { return Buffer.from(unquote(part.etag), 'hex'); }))).toString('hex')}-${parts.length}"`;
    const { id, bucket: uploadBucket, key: uploadKey, initiated, ...fields } = upload;

    await saveObject(bucket, key, data, { ...fields, etag, checksums: {}, parts: parts.length });
    await abortUpload(ctx, bucket, key);

    return reply(200, document('CompleteMultipartUploadResult', { Location: `${ctx.base}/${bucket}/${encodeURIComponent(key)}`, Bucket: bucket, Key: key, ETag: etag }), XML);
});

// ─── Auth ───

// SigV4 is accepted as sent: the mock has no secret to check a signature against. A header that
// isn't SigV4-shaped is refused. No header passes too (a presigned URL, or a deployed mock
// server, which strips the caller's Authorization header).
function authenticate (req) {
    const header = req.headers.authorization;

    if (!header || /redacted/i.test(header)) { return; }
    if (!/^AWS4-HMAC-SHA256 Credential=[^,]+,\s*SignedHeaders=[^,]+,\s*Signature=[0-9a-f]+$/.test(header)) { throw fail('AuthorizationHeaderMalformed'); }
}

// ─── Hooks the runtime calls ───

provider({
    // Extra per-request context: the request's ids, its headers, and the base URL for Location.
    context (req) {
        const host = req.headers['x-mock-host'] || req.headers['x-forwarded-host'] || req.headers.host || 'localhost';
        const local = /^(localhost|127\.0\.0\.1)(:|$)/.test(host);

        return {
            requestId: hex(16).toUpperCase(),
            hostId: randomBytes(48).toString('base64'),
            headers: req.headers,
            base: `${req.headers['x-forwarded-proto'] || (local ? 'http' : 'https')}://${host}`
        };
    },

    // A bucket named in the host (`bucket.s3.amazonaws.com`, `bucket.s3.us-west-2.amazonaws.com`,
    // `bucket.localhost`) moves to the path, as a path-style request names it.
    rewrite (req, url) {
        const host = String(req.headers.host || '').split(':')[0];
        const match = /^(.+?)\.(s3[.-][a-z0-9.-]*amazonaws\.com|s3\.amazonaws\.com|localhost)$/.exec(host);
        const path = match ? `/${match[1]}${url.pathname === '/' ? '' : url.pathname}` : url.pathname;

        return path.length > 1 ? path.replace(/^(\/[^/]+)\/$/, '$1') : path;
    },

    // Bodies are objects' bytes or S3's XML: handlers read ctx.body themselves.
    parseBody () { return {}; },

    authenticate,

    // Scenarios that fail every request (slow-down, access-denied, internal-error).
    beforeRoute () { if (SCENARIO.failAll) { throw fail(SCENARIO.failAll); } },

    unrecognized () { return fail('MethodNotAllowed'); },
    invalidBody () { return fail('MalformedXML'); },
    missingSession (message) { return fail('InvalidArgument', { Message: message, ArgumentName: 'x-mock-session', ArgumentValue: '' }); },
    internalError () { return fail('InternalError'); },

    responseHeaders (ctx) { return { 'x-amz-request-id': ctx.requestId, 'x-amz-id-2': ctx.hostId, Server: 'AmazonS3' }; }

    // No unknownParameter hook: S3 has no OpenAPI spec to check parameters against.
});

// ═══ RUNTIME ═════════════════════════════════════════════════════════════════════════════════════
/* global SCENARIO, SPEC, META, pm, renderDocs */
// The runtime: routing, state, request parsing, idempotency, the docs page and the server,
// the same for every API. The API section above registers its routes with route() and its
// hooks with provider(). Both are function declarations, so they work before this code runs.

const http = require('http');
const crypto = require('crypto');
const NodeBuffer = require('buffer').Buffer;

const PORT = process.env.PORT || 4609;

// What a hosted mock answers to an API request without x-mock-session, in the provider's error format.
const MISSING_SESSION = 'This hosted mock needs an x-mock-session header on every API request: send an id of ' +
    'your own, such as a random UUID. Each id gets its own data. The docs are at /.';

// ─── Routes and provider hooks ───

// `:name` matches one path segment; `:name*` the rest of the path, slashes included (an S3 key).
function route (method, path, handler) {
    route.table = route.table || [];
    route.table.push({ method, path, pattern: new RegExp(`^${path.replace(/:\w+\*/g, '(.+)').replace(/:\w+/g, '([^/]+)')}$`), handler });
}

function provider (hooks) {
    provider.hooks = hooks;
}

// An error the provider throws to answer with its own status and body (and `headers`, if any).
function isApiError (error) {
    return Boolean(error) && Number.isInteger(error.status) && error.body !== undefined;
}

// A handler returns its result for a 200 with a JSON body, or reply() for anything else:
// `return reply(202, undefined, { 'X-Message-Id': id })` answers 202 with no body.
function reply (status, body, headers = {}) {
    return { isReply: true, status, body, headers };
}

// ─── State (pm.state, shared by every scenario) ───

// Entities are kept by kind and id. The kind defaults to the entity's `object` field (as on
// Stripe); a provider whose objects have no such field passes the kind.
const store = {
    get (kind, id) {
        return pm.state.get(`${kind}:${id}`);
    },

    async save (entity, kind = entity.object) {
        if (entity._seq === undefined) { entity._seq = await pm.state.increment('seq'); }
        await pm.state.set(`${kind}:${entity.id}`, entity);

        return entity;
    },

    remove (kind, id) {
        return pm.state.delete(`${kind}:${id}`);
    },

    // Newest first.
    async all (kind) {
        const prefix = `${kind}:`,
            entities = [];

        for (const key of await pm.state.keys()) {
            if (key.startsWith(prefix)) { entities.push(await pm.state.get(key)); }
        }

        return entities.filter(Boolean).sort((a, b) => { return b._seq - a._seq; });
    }
};

function randomId (prefix, length = 24) {
    return `${prefix}_${crypto.randomBytes(length).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, length)}`;
}

function now () {
    return Math.floor(Date.now() / 1000);
}

// The fields of a stored object a response shows (internal ones start with `_`).
function view (entity) {
    return Object.fromEntries(Object.entries(entity).filter(([key]) => { return !key.startsWith('_'); }));
}

// ─── Requests ───

// Form bodies and query strings, with brackets: `metadata[order]=1`, `expand[]=x`, `items[0][price]=y`.
function parseParams (text) {
    const params = {};
    const decode = (value) => { return decodeURIComponent(value.replace(/\+/g, ' ')); };

    for (const pair of text.split('&')) {
        if (!pair) { continue; }

        const [rawKey, rawValue = ''] = pair.split(/=(.*)/s);
        const path = decode(rawKey).replace(/\]/g, '').split('[');
        let node = params;

        path.forEach((segment, index) => {
            const slot = segment === '' && Array.isArray(node) ? node.length : segment;

            if (index === path.length - 1) {
                node[slot] = decode(rawValue);

                return;
            }
            if (node[slot] === undefined) { node[slot] = /^\d*$/.test(path[index + 1]) ? [] : {}; }
            node = node[slot];
        });
    }

    return params;
}

// Form values arrive as strings: type them as the spec declares, leaving metadata as strings.
function coerce (params, types) {
    const nested = (node) => {
        for (const [key, value] of Object.entries(node)) {
            if (value === 'true' || value === 'false') { node[key] = value === 'true'; }
            else if (value && typeof value === 'object') { nested(value); }
        }
    };

    for (const [key, value] of Object.entries(params)) {
        if (types[key] === 'integer' && /^-?\d+$/.test(value)) { params[key] = Number(value); }
        else if (types[key] === 'boolean' && (value === 'true' || value === 'false')) { params[key] = value === 'true'; }
        else if (key !== 'metadata' && value && typeof value === 'object') { nested(value); }
    }

    return params;
}

// The handler reads the raw stream as bytes: `req.body` from the runtime is a lossy UTF-8 copy.
function readBody (req) {
    return new Promise((resolve, reject) => {
        const chunks = [];

        req.on('data', (chunk) => { chunks.push(NodeBuffer.from(chunk)); });
        req.on('end', () => { resolve(NodeBuffer.concat(chunks)); });
        req.on('error', reject);
    });
}

function parseRequest (req, raw, types) {
    if ((req.headers['content-type'] || '').includes('application/json') && raw) {
        try { return JSON.parse(raw); }
        catch (error) { throw provider.hooks.invalidBody(); }
    }

    return coerce(parseParams(raw), types);
}

// ─── Idempotency ───

// The first response to a repeated key is replayed for the window; the same key with a
// different request is a conflict. Rate limits and server errors are not saved, so a retry runs again.
async function idempotent (ctx, fingerprint, run) {
    const { windowMs } = provider.hooks.idempotency;
    const key = `idempotency:${ctx.idempotencyKey}`;
    const saved = await pm.state.get(key);

    if (saved && Date.now() - saved.at < windowMs) {
        if (saved.fingerprint !== fingerprint) { throw provider.hooks.idempotencyConflict(ctx.idempotencyKey); }

        return { ...saved.response, replayed: true };
    }

    const response = await run();

    if (response.status < 500 && response.status !== 429) {
        await pm.state.set(key, { at: Date.now(), fingerprint, response });
    }

    return response;
}

// ─── Docs at `/` ───

// A browser (Accept: text/html) gets the docs page; anything else at `/` gets the JSON
// descriptor, and `/llms.txt` the plain-text summary. API paths are never shadowed: when the
// API itself answers `GET /` (S3's ListBuckets), `/` is the docs page for browsers only, and
// the descriptor is at `/docs`.
function docsResponse (req, url) {
    if (req.method !== 'GET' || !['/', '/docs', '/llms.txt'].includes(url.pathname)) { return null; }

    const html = (req.headers.accept || '').includes('text/html');
    const apiRoot = (route.table || []).some((candidate) => { return candidate.method === 'GET' && candidate.pattern.test('/'); });

    if (url.pathname === '/' && apiRoot && !html) { return null; }

    // Behind the hosted gateway, Host is an internal address; x-mock-host is the public one.
    const host = req.headers['x-mock-host'] || req.headers['x-forwarded-host'] || req.headers.host || 'localhost';
    const local = /^(localhost|127\.0\.0\.1)(:|$)/.test(host);
    const base = `${req.headers['x-forwarded-proto'] || (local ? 'http' : 'https')}://${host}`;
    const docs = renderDocs({ base, host, scenario: SCENARIO.name, local });

    if (url.pathname === '/llms.txt') { return { status: 200, type: 'text/plain; charset=utf-8', body: docs.llms }; }

    return html ?
        { status: 200, type: 'text/html; charset=utf-8', body: docs.html } :
        { status: 200, type: 'application/json', body: JSON.stringify(docs.descriptor, null, 2) };
}

// ─── Dispatch ───

async function respond (req, ctx) {
    const hooks = provider.hooks;
    const url = new URL(req.url || '/', 'http://localhost');
    // A provider can route on another path than the request's: S3 moves a bucket named in the Host to the path.
    const pathname = hooks.rewrite ? hooks.rewrite(req, url) : url.pathname;
    const docs = pathname === url.pathname && docsResponse(req, url);

    if (docs) { return docs; }

    // A hosted mock is shared by everyone who calls its URL, so each caller names their own
    // state with x-mock-session; without one, every caller would share a single pool. The
    // gateway sets x-mock-host; a mock run locally has one caller and needs no session.
    if (req.headers['x-mock-host'] && !req.headers['x-mock-session']) { throw hooks.missingSession(MISSING_SESSION); }

    hooks.authenticate(req);
    if (hooks.beforeRoute) { await hooks.beforeRoute(ctx); }

    const match = (route.table || []).map((candidate) => {
        return candidate.method === req.method && { candidate, args: candidate.pattern.exec(pathname) };
    }).find((found) => { return found && found.args; });

    if (!match) { throw hooks.unrecognized(req, url); }

    // Which route answered, as `METHOD /path` (the provider's own spelling), for errors that name it.
    ctx.route = `${match.candidate.method} ${match.candidate.path}`;

    // A route the spec doesn't describe (one added by hand) skips the unknown-parameter check.
    const known = SPEC.params[`${match.candidate.method} ${match.candidate.path}`];
    const query = url.search.slice(1);
    ctx.body = ['GET', 'HEAD'].includes(req.method) ? NodeBuffer.alloc(0) : await readBody(req);
    // The parameters are the body's, or the query string's when there is no body.
    const raw = ctx.body.length ? ctx.body.toString('utf8') : query;
    const run = async () => {
        try {
            // A provider whose bodies aren't JSON or form data (XML, a file) parses them itself.
            ctx.params = hooks.parseBody ? hooks.parseBody(req, ctx.body) : parseRequest(req, raw, known || {});
            ctx.query = ctx.body.length || hooks.parseBody ? parseParams(query) : ctx.params;

            // A provider that ignores unknown parameters leaves out the unknownParameter hook.
            const named = ctx.params && typeof ctx.params === 'object' && !Array.isArray(ctx.params);
            const unknown = known && named && hooks.unknownParameter && Object.keys(ctx.params).find((name) => { return !(name in known); });

            if (unknown) { throw hooks.unknownParameter(unknown); }

            const result = await match.candidate.handler(ctx, ...match.args.slice(1).map(decodeURIComponent));
            const answer = result && result.isReply ? result : { status: 200, body: result, headers: {} };

            return {
                ...answer,
                body: hooks.render && answer.body !== undefined ? await hooks.render(ctx, answer.body) : answer.body
            };
        }
        catch (error) {
            if (isApiError(error)) { return { status: error.status, body: error.body, headers: error.headers || {} }; }
            throw error;
        }
    };

    if (req.method === 'POST' && ctx.idempotencyKey) {
        return idempotent(ctx, crypto.createHash('sha256').update(`${req.method} ${url.pathname} ${raw}`).digest('hex'), run);
    }

    return run();
}

// A JSON body; none when the handler replied without one (a 202 or 204); or, when the reply
// gives its own Content-Type, a string or bytes as they are (a text/event-stream, XML, a file).
function send (res, ctx, { status, body, headers = {}, replayed, type }) {
    if (type) {
        res.writeHead(status, { 'Content-Type': type });
        res.end(body);

        return;
    }
    const raw = (typeof body === 'string' || NodeBuffer.isBuffer(body)) && Object.keys(headers).some((name) => { return name.toLowerCase() === 'content-type'; });

    res.writeHead(status, {
        ...(body === undefined || raw ? {} : { 'Content-Type': 'application/json' }),
        ...(provider.hooks.responseHeaders ? provider.hooks.responseHeaders(ctx) : {}),
        ...headers,
        ...(ctx.idempotencyKey ? { 'Idempotency-Key': ctx.idempotencyKey } : {}),
        ...(replayed ? { 'Idempotent-Replayed': 'true' } : {})
    });
    res.end(body === undefined || raw ? body : JSON.stringify(body));
}

function start () {
    const hooks = provider.hooks;

    http.createServer((req, res) => {
        const idempotencyHeader = hooks.idempotency && hooks.idempotency.header;
        const ctx = {
            idempotencyKey: (idempotencyHeader && req.headers[idempotencyHeader]) || null,
            params: {},
            query: {},
            body: NodeBuffer.alloc(0),
            ...(hooks.context ? hooks.context(req) : {})
        };

        respond(req, ctx)
            .catch((error) => {
                // internalError returns the body of a 500, or an error of the provider's own (with its headers).
                const failure = isApiError(error) ? error : hooks.internalError(error);

                return isApiError(failure) ? { status: failure.status, body: failure.body, headers: failure.headers || {} } :
                    { status: 500, body: failure };
            })
            .then((response) => { send(res, ctx, response); });
    }).listen(PORT);
}

/* global META */
// ─── Docs at `/`: the page, the JSON descriptor and llms.txt, rendered from META ───
//
// META (bottom of the file) holds the provider's profile, the scenarios and the routes.
// {{BASE_URL}}, {{HOST}} and {{SCENARIO}} are filled in per request.

const escape = (text) => {
    return String(text).replace(/[&<>"]/g, (c) => { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; });
};

// Aether icons: icon-action-copy-stroke and icon-state-check-stroke (20x20), recoloured with currentColor.
const ICON_COPY = [
    '<svg class="icon-copy" width="16" height="16" viewBox="0 0 20 20" aria-hidden="true"><path fill=',
    '"currentColor" d="M13.7998 16V17H9.2002V16H13.7998ZM16 13.7998V9.2002C16 8.62364 15.9987 8.25111',
    ' 15.9756 7.96777C15.9534 7.69619 15.9158 7.59534 15.8906 7.5459C15.7948 7.35793 15.6421 7.20521 ',
    '15.4541 7.10938C15.4047 7.08419 15.3038 7.04661 15.0322 7.02441C14.7489 7.00126 14.3764 7 13.799',
    '8 7H9.2002C8.62364 7 8.25111 7.00126 7.96777 7.02441C7.69619 7.04661 7.59534 7.08419 7.5459 7.10',
    '938C7.35793 7.20521 7.20521 7.35793 7.10938 7.5459C7.08419 7.59534 7.04661 7.69619 7.02441 7.967',
    '77C7.00126 8.25111 7 8.62364 7 9.2002V13.7998C7 14.3764 7.00126 14.7489 7.02441 15.0322C7.04661 ',
    '15.3038 7.08419 15.4047 7.10938 15.4541C7.20521 15.6421 7.35793 15.7948 7.5459 15.8906C7.59534 1',
    '5.9158 7.69619 15.9534 7.96777 15.9756C8.25111 15.9987 8.62364 16 9.2002 16V17L8.45801 16.9971C7',
    '.91644 16.9886 7.55193 16.9578 7.25977 16.8535L7.0918 16.7822C6.76256 16.6145 6.48707 16.3592 6.',
    '29492 16.0459L6.21777 15.9082C5.99979 15.4804 6 14.9199 6 13.7998V9.2002C6 8.08009 5.99979 7.519',
    '62 6.21777 7.0918C6.40951 6.71554 6.71554 6.40951 7.0918 6.21777C7.41263 6.0543 7.80803 6.01315 ',
    '8.45801 6.00293L9.2002 6H13.7998C14.9199 6 15.4804 5.99979 15.9082 6.21777C16.2845 6.40951 16.59',
    '05 6.71554 16.7822 7.0918C17.0002 7.51962 17 8.08009 17 9.2002V13.7998C17 14.9199 17.0002 15.480',
    '4 16.7822 15.9082L16.7051 16.0459C16.5129 16.3592 16.2374 16.6145 15.9082 16.7822L15.7402 16.853',
    '5C15.3311 16.9995 14.7798 17 13.7998 17V16C14.3764 16 14.7489 15.9987 15.0322 15.9756C15.3038 15',
    '.9534 15.4047 15.9158 15.4541 15.8906C15.6421 15.7948 15.7948 15.6421 15.8906 15.4541C15.9158 15',
    '.4047 15.9534 15.3038 15.9756 15.0322C15.9987 14.7489 16 14.3764 16 13.7998Z"/><path fill="curre',
    'ntColor" d="M10.9902 4.39941C10.9437 4.17145 10.7417 4 10.5 4H5C4.44772 4 4 4.44772 4 5V10.5C4 1',
    '0.7417 4.17145 10.9437 4.39941 10.9902L4.60059 11.0098C4.82855 11.0563 5 11.2583 5 11.5C5 11.776',
    '1 4.77614 12 4.5 12C3.67157 12 3 11.3284 3 10.5V5C3 3.89543 3.89543 3 5 3H10.5C11.3284 3 12 3.67',
    '157 12 4.5C12 4.77614 11.7761 5 11.5 5C11.2583 5 11.0563 4.82855 11.0098 4.60059L10.9902 4.39941',
    'Z"/></svg>'
].join('');
const ICON_CHECK = [
    '<svg class="icon-check" width="16" height="16" viewBox="0 0 20 20" aria-hidden="true"><path fill',
    '="currentColor" d="M15.5918 3.71094C15.7514 3.48562 16.0637 3.43224 16.289 3.5918C16.5143 3.7514',
    '1 16.5677 4.06373 16.4082 4.28907L7.90817 16.2891C7.82301 16.4093 7.68875 16.4856 7.54195 16.498',
    '1C7.39523 16.5104 7.25057 16.4576 7.14645 16.3535L2.64645 11.8535C2.45118 11.6583 2.45118 11.341',
    '8 2.64645 11.1465C2.84171 10.9512 3.15822 10.9512 3.35348 11.1465L7.43356 15.2266L15.5918 3.7109',
    '4Z"/></svg>'
].join('');

const copyButton = (label) => {
    return `<button class="copy" type="button" aria-label="Copy ${escape(label)}" title="Copy">${ICON_COPY}${ICON_CHECK}</button>`;
};

// A code block with its copy button.
const codeBlock = (label, code) => {
    return `<div class="code"><div class="code-head"><span>${escape(label)}</span>${copyButton(label)}</div><pre>${escape(code)}</pre></div>`;
};

const METHOD_CLASS = { GET: 'm-get', HEAD: 'm-get', POST: 'm-post', PUT: 'm-put', PATCH: 'm-put', DELETE: 'm-delete' };

// Endpoints grouped by resource: the group the mock gives an endpoint, or the
// first path segment after the version (`/v1/payment_intents/...` -> payment_intents).
function groupRoutes (routes) {
    const groups = new Map();

    for (const route of routes) {
        const segments = route.path.split('/').filter(Boolean);
        const resource = route.group || (/^v\d/.test(segments[0]) ? segments[1] : segments[0]) || '/';

        if (!groups.has(resource)) { groups.set(resource, []); }
        groups.get(resource).push(route);
    }

    return [...groups.entries()];
}

function docsPage ({ manifest, profile, scenarios, routes, apiVersion, local }) {
    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escape(manifest.name)} mock · Postman</title>
<meta name="description" content="${escape(profile.summary)}">
<link rel="alternate" type="text/plain" href="/llms.txt" title="llms.txt">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap">
<style>
  /* Aether design tokens: light theme */
  :root {
    --base-color-brand: #FF6C37;
    --content-color-primary: #212121;
    --content-color-secondary: #6B6B6B;
    --content-color-tertiary: #A6A6A6;
    --content-color-brand: #D03E0A;
    --content-color-success: #247E4C;
    --content-color-warning: #A87D13;
    --content-color-error: #9F2F22;
    --content-color-info: #2552AA;
    --content-color-link: #2F67CC;
    --background-color-primary: #FFFFFF;
    --background-color-secondary: #F9F9F9;
    --background-color-tertiary: #F2F2F2;
    --background-color-brand: #FFF0EA;
    --border-color-default: #EDEDED;
    --border-color-strong: #E6E6E6;
    --header-background-color-primary: #212121;
    --header-color-content: #A6A6A6;
    --highlight-background-color-primary: #EDEDED;
    --shadow-focus: 0 0 0 1px #FFFFFF, 0 0 0 3px #9FC0FA;
    --text-family-default: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    --text-family-code: 'IBM Plex Mono', SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    color-scheme: light;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--background-color-primary); color: var(--content-color-primary);
    font: 400 13px/20px var(--text-family-default); }
  a { color: var(--content-color-link); text-decoration: none; }
  a:hover { text-decoration: underline; }
  header { background: var(--header-background-color-primary); color: var(--header-color-content); }
  header div { max-width: 880px; margin: 0 auto; padding: 0 16px; height: 48px; display: flex; align-items: center; gap: 8px; }
  /* Aether's icon-brandLogo-postman. */
  .logo { width: 20px; height: 20px; flex: none; }
  header b { color: #FFFFFF; font-weight: 600; }
  /* "Open in Postman", at the header's right. */
  .open { margin-left: auto; background: #FF6C37; color: #FFFFFF; font-weight: 600; white-space: nowrap; padding: 4px 12px; border-radius: 4px; }
  .open:hover { text-decoration: none; filter: brightness(1.08); }
  @media (max-width: 560px) { header span { display: none; } }
  /* One column no wider than the screen: a wide code block scrolls inside its box instead of widening the page. */
  main { max-width: 880px; margin: 0 auto; padding: 32px 16px 48px; display: grid; grid-template-columns: minmax(0, 1fr); gap: 32px; }
  h1 { margin: 0; font-size: 21px; line-height: 32px; font-weight: 600; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  h2 { margin: 0; font-size: 15px; line-height: 24px; font-weight: 600; }
  h3 { margin: 0; font-size: 12px; line-height: 16px; font-weight: 600; color: var(--content-color-secondary); text-transform: uppercase; letter-spacing: .04em; }
  p { margin: 0; }
  .secondary { color: var(--content-color-secondary); }
  .facts { display: grid; grid-template-columns: max-content 1fr; gap: 6px 20px; margin: 4px 0 0; }
  .facts dt { color: var(--content-color-secondary); }
  .facts dd { margin: 0; min-width: 0; }
  .facts code { white-space: nowrap; }
  @media (max-width: 560px) { .facts { grid-template-columns: 1fr; gap: 2px; } .facts dd { margin-bottom: 8px; } }
  .meta { display: flex; flex-wrap: wrap; gap: 4px 16px; color: var(--content-color-secondary); font-size: 12px; }
  .badge { font-size: 11px; line-height: 16px; font-weight: 600; padding: 2px 6px; border-radius: 4px;
    background: var(--background-color-brand); color: var(--content-color-brand); }
  section { display: grid; gap: 8px; min-width: 0; }
  code { font: 12px/16px var(--text-family-code); background: var(--background-color-tertiary); padding: 2px 4px; border-radius: 4px; }
  .copy { width: 28px; height: 28px; display: inline-grid; place-items: center; flex: none; border: 0; border-radius: 4px;
    background: transparent; color: var(--content-color-secondary); cursor: pointer; }
  .copy:hover { background: var(--highlight-background-color-primary); color: var(--content-color-primary); }
  .copy:focus-visible { outline: none; box-shadow: var(--shadow-focus); }
  .copy .icon-check, .copy.copied .icon-copy { display: none; }
  .copy.copied .icon-check { display: block; color: var(--content-color-success); }
  .field { display: flex; align-items: center; gap: 4px; height: 36px; padding: 0 4px 0 12px;
    background: var(--background-color-secondary); border: 1px solid var(--border-color-strong); border-radius: 4px; }
  .field span { flex: 1; min-width: 0; font: 13px var(--text-family-code); overflow-wrap: anywhere; }
  .code { border: 1px solid var(--border-color-default); border-radius: 4px; overflow: hidden; min-width: 0; }
  .code-head { display: flex; align-items: center; justify-content: space-between; height: 32px; padding: 0 4px 0 12px;
    background: var(--background-color-secondary); border-bottom: 1px solid var(--border-color-default);
    font-size: 12px; font-weight: 500; color: var(--content-color-secondary); }
  pre { margin: 0; font: 12px/20px var(--text-family-code); padding: 12px; overflow-x: auto; }
  .stack { display: grid; grid-template-columns: minmax(0, 1fr); gap: 12px; }
  .table { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-size: 12px; font-weight: 500; color: var(--content-color-secondary);
    padding: 6px 8px; border-bottom: 1px solid var(--border-color-strong); }
  td { padding: 8px; border-bottom: 1px solid var(--border-color-default); vertical-align: top; }
  td:first-child { width: 45%; }
  tr.current td { background: var(--background-color-secondary); }
  .now { margin-left: 8px; font-size: 11px; color: var(--content-color-secondary); }
  .tone-success { color: var(--content-color-success); }
  .tone-warning { color: var(--content-color-warning); }
  .tone-error { color: var(--content-color-error); }
  .groups { display: grid; gap: 20px; }
  .group { display: grid; gap: 4px; min-width: 0; overflow-x: auto; }
  h3 { text-transform: none; letter-spacing: 0; font-size: 13px; color: var(--content-color-primary); }
  .endpoints td { padding: 6px 8px; }
  .endpoints td.method { width: 64px; padding-left: 0; font: 500 12px/20px var(--text-family-code); }
  .endpoints td.path { width: 46%; font: 12px/20px var(--text-family-code); overflow-wrap: anywhere; }
  .endpoints td.summary { color: var(--content-color-secondary); }
  .sources td:first-child { width: 220px; }
  .m-get { color: var(--content-color-success); }
  .m-post { color: var(--content-color-warning); }
  .m-put { color: var(--content-color-info); }
  .m-delete { color: var(--content-color-error); }
  .sources { display: grid; gap: 4px; padding: 0; margin: 0; list-style: none; }
  footer { border-top: 1px solid var(--border-color-default); padding-top: 16px; display: flex; flex-wrap: wrap; gap: 4px 16px;
    font-size: 12px; color: var(--content-color-secondary); }
</style>
</head>
<body>
<header><div><svg class="logo" viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path d="M9.01896 0.0651652C7.44955 -0.136374 5.85563 0.132009 4.43876 0.836374C3.02189 1.54074 1.84572 2.64945 1.05898 4.02229C0.272243 5.39513 -0.089721 6.97044 0.0188639 8.549C0.127449 10.1276 0.701705 11.6385 1.66901 12.8907C2.63632 14.1428 3.95322 15.0801 5.45319 15.5838C6.95316 16.0875 8.56882 16.1351 10.0958 15.7206C11.6229 15.306 12.9927 14.448 14.032 13.2549C15.0714 12.0619 15.7336 10.5874 15.9349 9.01796C16.2049 6.91365 15.6279 4.78828 14.331 3.10934C13.034 1.4304 11.1232 0.33539 9.01896 0.0651652Z" fill="white"/><path d="M9.01896 0.0651652C7.44955 -0.136374 5.85563 0.132009 4.43876 0.836374C3.02189 1.54074 1.84572 2.64945 1.05898 4.02229C0.272243 5.39513 -0.089721 6.97044 0.0188639 8.549C0.127449 10.1276 0.701705 11.6385 1.66901 12.8907C2.63632 14.1428 3.95322 15.0801 5.45319 15.5838C6.95316 16.0875 8.56882 16.1351 10.0958 15.7206C11.6229 15.306 12.9927 14.448 14.032 13.2549C15.0714 12.0619 15.7336 10.5874 15.9349 9.01796C16.2049 6.91365 15.6279 4.78828 14.331 3.10934C13.034 1.4304 11.1232 0.33539 9.01896 0.0651652Z" fill="#FF6C37"/><path d="M5.78377 8.5056C5.78687 8.51193 5.79207 8.517 5.7985 8.51992C5.80492 8.52283 5.81215 8.52343 5.81897 8.5216L7.09896 8.2456L6.56056 7.7L5.79337 8.4672C5.78731 8.47128 5.78298 8.47747 5.7812 8.48456C5.77943 8.49165 5.78034 8.49914 5.78377 8.5056Z" fill="white"/><path d="M11.7774 3.0096C11.599 3.00979 11.4229 3.04997 11.2621 3.12721C11.1013 3.20444 10.9599 3.31676 10.8483 3.45589C10.7366 3.59501 10.6576 3.75741 10.617 3.93111C10.5765 4.10482 10.5754 4.28541 10.6138 4.45959C10.6523 4.63378 10.7293 4.79712 10.8393 4.93759C10.9492 5.07806 11.0893 5.19208 11.2491 5.27126C11.409 5.35043 11.5845 5.39275 11.7629 5.3951C11.9413 5.39744 12.1179 5.35975 12.2798 5.2848L11.4686 4.4736C11.4592 4.46431 11.4519 4.45328 11.4468 4.44113C11.4418 4.42898 11.4392 4.41596 11.4392 4.4028C11.4392 4.38965 11.4418 4.37662 11.4468 4.36448C11.4519 4.35233 11.4592 4.34129 11.4686 4.332L12.5286 3.2728C12.3157 3.10164 12.0505 3.00874 11.7774 3.0096Z" fill="white"/><path d="M12.6741 3.4104L11.6805 4.4L12.4597 5.1792C12.5171 5.13888 12.5707 5.09336 12.6197 5.0432C12.8333 4.8282 12.9576 4.54036 12.9677 4.23749C12.9778 3.93461 12.8729 3.63914 12.6741 3.4104Z" fill="white"/><path d="M10.6862 5.2368H10.6686C10.6479 5.23664 10.6273 5.23852 10.607 5.2424H10.5998C10.5775 5.24721 10.5555 5.25362 10.5342 5.2616L10.5174 5.2696C10.5013 5.27632 10.4857 5.28435 10.471 5.2936L10.4534 5.3048C10.434 5.31816 10.4158 5.33315 10.399 5.3496L7.45256 8.2968L7.81736 8.6616L10.9374 5.9232C10.955 5.90773 10.9711 5.89058 10.9854 5.872L10.999 5.8544C11.0096 5.83878 11.0192 5.82248 11.0278 5.8056C11.0326 5.796 11.0366 5.7864 11.0406 5.7768C11.0459 5.76404 11.0505 5.75094 11.0542 5.7376C11.0542 5.728 11.0598 5.7184 11.0622 5.7088C11.0661 5.68899 11.0688 5.66895 11.0702 5.6488V5.6224C11.0702 5.608 11.0702 5.5936 11.0702 5.5792C11.0702 5.5648 11.0702 5.56 11.0662 5.5504C11.0514 5.4749 11.0145 5.40549 10.9602 5.35095C10.906 5.2964 10.8368 5.25918 10.7614 5.244H10.7462C10.7263 5.24019 10.7063 5.23778 10.6862 5.2368Z" fill="white"/><path d="M6.69817 7.5584L7.30297 8.16L10.2574 5.2056C10.3535 5.11162 10.4788 5.05321 10.6126 5.04C10.0902 4.64 9.52056 4.7448 6.69817 7.5584Z" fill="white"/><path d="M11.1037 6.0384L11.0677 6.0736L7.94775 8.81119L8.47815 9.34079C9.79335 8.0968 10.9605 6.912 11.1037 6.0384Z" fill="white"/><path d="M3.32137 12.452C3.323 12.4577 3.32632 12.4627 3.3309 12.4664C3.33548 12.4701 3.34109 12.4724 3.34697 12.4728L4.70697 12.5664L3.94457 11.804L3.32777 12.42C3.32378 12.4242 3.32105 12.4294 3.31992 12.4351C3.31878 12.4407 3.31929 12.4466 3.32137 12.452Z" fill="white"/><path d="M4.08696 11.6624L4.89096 12.4664C4.9005 12.4766 4.91327 12.4832 4.92711 12.4851C4.94095 12.487 4.95502 12.4841 4.96696 12.4768C4.97942 12.4706 4.98935 12.4603 4.99504 12.4476C5.00073 12.4349 5.00183 12.4206 4.99816 12.4072L4.86296 11.8296C4.8542 11.7922 4.85818 11.7529 4.87427 11.718C4.89035 11.683 4.91762 11.6545 4.95176 11.6368C6.36136 10.9304 7.49815 10.2032 8.33255 9.47679L7.77255 8.91679L6.57256 9.17519L4.08696 11.6624Z" fill="white"/><path d="M7.60055 8.7472L7.29975 8.4464L6.88375 8.8616C6.88076 8.86519 6.87912 8.86972 6.87912 8.8744C6.87912 8.87908 6.88076 8.88361 6.88375 8.8872C6.88569 8.89147 6.88911 8.89488 6.89339 8.89679C6.89766 8.89871 6.90248 8.89899 6.90695 8.8976L7.60055 8.7472Z" fill="white"/><path d="M12.7022 4.0552C12.698 4.04261 12.6913 4.03104 12.6824 4.02128C12.6734 4.01151 12.6625 4.00378 12.6503 3.99858C12.6381 3.99339 12.625 3.99087 12.6117 3.99118C12.5985 3.99149 12.5855 3.99463 12.5736 4.00039C12.5616 4.00615 12.5511 4.0144 12.5426 4.02458C12.5341 4.03475 12.5279 4.04662 12.5244 4.05939C12.5209 4.07216 12.5202 4.08553 12.5223 4.09861C12.5244 4.11168 12.5292 4.12416 12.5366 4.1352C12.5604 4.18331 12.5699 4.23731 12.5638 4.29069C12.5577 4.34406 12.5363 4.39453 12.5022 4.436C12.4909 4.44955 12.4838 4.46601 12.4816 4.48346C12.4793 4.50091 12.4821 4.51863 12.4896 4.53457C12.497 4.5505 12.5089 4.56398 12.5237 4.57344C12.5385 4.5829 12.5558 4.58795 12.5734 4.588C12.5869 4.58785 12.6003 4.58478 12.6126 4.57898C12.6249 4.57318 12.6358 4.5648 12.6446 4.5544C12.7012 4.48556 12.7367 4.40184 12.7469 4.31329C12.7571 4.22474 12.7416 4.13513 12.7022 4.0552Z" fill="#FF6C37"/></svg><b>Postman</b><span>/ API mocks / ${escape(manifest.name)}</span><a class="open" href="{{OPEN_URL}}">Open in Postman</a></div></header>
<main>
  <section>
    <h1>${escape(manifest.name)} <span class="badge">MOCK</span></h1>
    <p class="secondary">${escape(profile.summary)}</p>
    <div class="meta">
      <span>API version ${profile.versionDocs ?
        `<a href="${escape(profile.versionDocs)}" rel="noopener" title="How ${escape(profile.provider)} versions its API"><code>${escape(apiVersion)}</code></a>` :
        `<code>${escape(apiVersion)}</code>`}</span>
      <span>${routes.length} endpoints</span>
      <span>${scenarios.length} scenarios</span>
      <span>Maintained by Postman</span>
    </div>
  </section>

  <section>
    <h2>Base URL</h2>
    <div class="field"><span data-copy>{{BASE_URL}}</span>${copyButton('base URL')}</div>
    <dl class="facts">
      <dt>Stands in for</dt><dd>${manifest.origins.map((host) => { return `<code>${escape(host)}</code>`; }).join(' and ')}</dd>
      <dt>Credentials</dt><dd>${profile.auth}</dd>
      <dt>Session</dt><dd>{{SESSION_NOTE}}</dd>
    </dl>
  </section>

  <section>
    <h2>Run it locally</h2>
    <div class="stack">
      ${codeBlock('Run it', local.run.join('\n'))}
      ${codeBlock('Add it to your project', local.project.join('\n'))}
    </div>
    <p class="secondary">Adding it records the mock in <code>.postman/resources.yaml</code>, so teammates and CI get the same one with <code>postman dependency install</code>.</p>
  </section>

  <section>
    <h2>{{CALL_TITLE}}</h2>
    <div class="stack">${profile.snippets.map((s) => { return codeBlock(s.label, s.code); }).join('')}</div>
  </section>

  <section>
    <h2>Scenarios</h2>
    <p class="secondary">Send the <code>x-mock-scenario</code> header to switch. All scenarios share a session's data. This page is served by <b>{{SCENARIO}}</b>.</p>
    <div class="table"><table>
      <thead><tr><th>Header value</th><th>Behaviour</th></tr></thead>
      <tbody>${scenarios.map((s) => { return `<tr data-scenario="${escape(s.name)}"><td><code>${escape(s.name)}</code></td><td>${escape(s.title)}</td></tr>`; }).join('')}</tbody>
    </table></div>
  </section>

  ${profile.dataSections.map((section) => {
        return `<section>
    <h2>${escape(section.title)}</h2>
    ${section.description ? `<p class="secondary">${section.description}</p>` : ''}
    <div class="table"><table>
      <thead><tr>${section.columns.map((c) => { return `<th>${escape(c)}</th>`; }).join('')}</tr></thead>
      <tbody>${section.rows.map((row) => {
            return `<tr>${row.cells.map((cell, i) => {
                return i === 0 ? `<td><code>${escape(cell)}</code></td>` : `<td class="tone-${row.tone || 'none'}">${escape(cell)}</td>`;
            }).join('')}</tr>`;
        }).join('')}</tbody>
    </table></div>
  </section>`;
    }).join('\n  ')}

  <section>
    <h2>Endpoints</h2>
    <p class="secondary">${profile.coverage}</p>
    <div class="groups">${groupRoutes(routes).map(([resource, items]) => {
        const title = resource.replace(/_/g, ' ');

        return `<div class="group"><h3>${escape(title.charAt(0).toUpperCase() + title.slice(1))}</h3><table class="endpoints">${items.map((r) => {
            return `<tr><td class="method ${METHOD_CLASS[r.method] || ''}">${escape(r.method)}</td><td class="path">${escape(r.path)}</td><td class="summary">${escape(r.summary || '')}</td></tr>`;
        }).join('')}</table></div>`;
    }).join('')}</div>
  </section>

  <section>
    <h2>Source of truth</h2>
    <p class="secondary">The mock is built from these and tested against them.</p>
    <div class="table"><table class="sources">${profile.sources.map((s) => {
        return `<tr><td><a href="${escape(s.href)}" rel="noopener">${escape(s.label)}</a></td><td class="secondary">${escape(s.detail || '')}</td></tr>`;
    }).join('')}</table></div>
  </section>

  <footer><span>Postman API mocks</span><span>For agents: <a href="/llms.txt">llms.txt</a>, or <code>GET /docs</code> with <code>Accept: application/json</code></span></footer>
</main>
<script>
  // Mark the scenario that served this page, in a neutral tone: the table also lists failure scenarios.
  document.querySelectorAll('tr[data-scenario="{{SCENARIO}}"]').forEach(function (row) {
    row.className = 'current';
    var tag = document.createElement('span');
    tag.className = 'now';
    tag.textContent = 'this page';
    row.firstChild.appendChild(tag);
  });
  document.querySelectorAll('.copy').forEach(function (button) {
    button.addEventListener('click', function () {
      var holder = button.closest('.field') || button.closest('.code');
      var source = holder.querySelector('[data-copy]') || holder.querySelector('pre');
      var text = source.textContent;
      var done = function () {
        button.classList.add('copied');
        setTimeout(function () { button.classList.remove('copied'); }, 1500);
      };
      if (navigator.clipboard) { navigator.clipboard.writeText(text).then(done, function () {}); }
    });
  });
</script>
</body>
</html>`;
}

function buildDocs ({ manifest, profile, scenarios, routes, apiVersion }) {
    // Run it once straight from Postman, or add it to a project so teammates and CI get the same mock.
    // {{MOCK_ID}} is this environment's id for the mock, filled in per request.
    const local = {
        run: ['postman mock run {{MOCK_ID}}'],
        project: [
            'postman dependency add mock {{MOCK_ID}}',
            `postman mock run "postman/.dependencies/mocks/${manifest.name}"`
        ]
    };

    const descriptor = {
        name: `${manifest.name} mock`,
        provider: profile.provider,
        maintainedBy: `Postman (not affiliated with ${profile.provider})`,
        apiVersion,
        standsInFor: manifest.origins,
        baseUrl: '{{BASE_URL}}',
        currentScenario: '{{SCENARIO}}',
        session: { header: 'x-mock-session', required: '{{SESSION_REQUIRED}}' },
        mockId: '{{MOCK_ID}}',
        scenarios: scenarios.map((s) => {
            return { name: s.name, title: s.title, description: s.description, select: { header: 'x-mock-scenario', value: s.name } };
        }),
        endpoints: routes.map((r) => { return `${r.method} ${r.path}`; }),
        testData: profile.testData,
        sources: profile.sources,
        useLocally: local
    };

    const llms = [
        `# ${manifest.name} mock`,
        '',
        `> ${profile.summary} Maintained by Postman; not affiliated with ${profile.provider}.`,
        '',
        `Base URL: {{BASE_URL}} (stands in for ${manifest.origins.join(' and ')})`,
        'Scenario: send the x-mock-scenario header. Current: {{SCENARIO}}.',
        '{{SESSION_LLMS}}',
        '',
        '## Scenarios',
        ...scenarios.map((s) => { return `- ${s.name}: ${s.description}`; }),
        '',
        '## Endpoints',
        ...routes.map((r) => { return `- ${r.method} ${r.path}`; }),
        '',
        '## Test data',
        ...profile.testData.map((t) => { return `- ${t.id}: ${t.result}`; }),
        '',
        '## Run it locally',
        `- Run it: ${local.run[0]}`,
        `- Add it to a project (restored with \`postman dependency install\`): ${local.project.join(' && ')}`,
        '',
        '## Source of truth',
        ...profile.sources.map((s) => { return `- ${s.label}: ${s.href}`; }),
        ''
    ].join('\n');

    const html = docsPage({ manifest, profile, scenarios, routes, apiVersion, local });

    return { html, descriptor, llms };
}

// The environment a hosted mock is served from, by its host; a local run takes the first one it is published to.
function envFor (host, local) {
    const ids = META.mockIds || {};
    const name = String(host).split(':')[0];

    return local ? ['prod', 'stage', 'beta'].find((candidate) => { return ids[candidate]; }) || 'prod' :
        /postman-stage\.dev$/.test(name) ? 'stage' : /postman-beta\.dev$/.test(name) ? 'beta' : 'prod';
}

// The app in each environment. "Open in Postman" opens the mock server there; Postman asks a signed-out
// visitor to sign in or sign up first and then lands them on it, so the page needs no sign-up link of its own.
const APP = { prod: 'https://go.postman.co', stage: 'https://go.postman-stage.co', beta: 'https://go.postman-beta.co' };

// The header's link for an environment, tagged so visits and sign-ups from these pages can be counted.
function linksFor (env) {
    const server = (META.serverIds || {})[env];
    const workspace = (META.workspaceIds || {})[env];
    const open = server && workspace ? `${APP[env]}/workspace/${workspace}/mock-server/${server}` :
        'https://www.postman.com/postman/popular-mocks-catalog/overview';
    const utm = new URLSearchParams({ utm_source: 'mock-docs', utm_medium: 'referral', utm_campaign: 'popular-mocks', utm_content: META.manifest.name });

    return { open: `${open}?${utm}` };
}

// Rendered once, then filled in for each request's host and scenario.
function renderDocs ({ base, host, scenario, local }) {
    renderDocs.cache = renderDocs.cache || buildDocs(META);
    const env = envFor(host, local);
    const mockId = (META.mockIds || {})[env] || '<mockId>';
    const links = linksFor(env);

    // The example request goes to this page's own base URL: the hosted mock, unless it is run locally.
    const callTitle = local ? 'Call it' : 'Call the hosted mock';
    // A hosted mock is shared, so its API requests must name their state; a local one need not.
    const session = local ?
        {
            note: 'Optional here. Send <code>x-mock-session</code> to keep separate sets of data.',
            llms: 'Session: optional here; send x-mock-session to keep separate sets of data.',
            required: 'false'
        } :
        {
            note: 'Required. Send <code>x-mock-session</code> with an id of your own, such as a random UUID; ' +
                'each id gets its own data. The examples read it from <code>$MOCK_SESSION</code>.',
            llms: 'Session: required. Send the x-mock-session header on every API request, with an id of your own, such as a ' +
                'random UUID; each id gets its own data.',
            required: 'true'
        };
    const fill = (text) => {
        return text.replace(/\{\{BASE_URL\}\}/g, base).replace(/\{\{HOST\}\}/g, host).replace(/\{\{SCENARIO\}\}/g, scenario)
            .replace(/\{\{MOCK_ID\}\}/g, mockId).replace(/\{\{CALL_TITLE\}\}/g, callTitle).replace(/\{\{SESSION_NOTE\}\}/g, session.note)
            .replace(/\{\{OPEN_URL\}\}/g, escape(links.open))
            .replace(/\{\{SESSION_LLMS\}\}/g, session.llms).replace(/"\{\{SESSION_REQUIRED\}\}"/g, session.required);
    };
    const { html, descriptor, llms } = renderDocs.cache;

    return { html: fill(html), llms: fill(llms), descriptor: JSON.parse(fill(JSON.stringify(descriptor))) };
}

// ═══ META: what the docs page shows ══════════════════════════════════════════════════════════════
const META = {
  "manifest": {
    "name": "Amazon S3",
    "origins": [
      "s3.amazonaws.com",
      "s3.us-east-1.amazonaws.com"
    ]
  },
  "apiVersion": "2006-03-01",
  "mockIds": {
    "beta": "b36efef8-0b81-4175-9dbe-5f4a2bca7a54",
    "stage": "4e55fb01-c9f8-473a-9896-6f9e3755952a",
    "prod": "e897e0aa-64be-43b5-a845-1d6fc738e953"
  },
  "serverIds": {
    "beta": "01a1b094-7474-742a-8394-b8a6137635c8",
    "stage": "01a1ccc5-1a53-7349-b14b-8126b8f8dee5",
    "prod": "01a1cccd-c6fc-744f-a744-8ab7bd3b63a7"
  },
  "workspaceIds": {
    "beta": "5036b5b6-2d7b-402e-93d3-2e04c8af733a",
    "stage": "c03ad9e5-0dc4-4c23-a499-c7f887863959",
    "prod": "58d3a3f3-5efe-4212-92d6-fa6a6691d712"
  },
  "profile": {
    "provider": "AWS",
    "summary": "A stateful mock of Amazon S3. Use the AWS SDK as usual, with forcePathStyle: objects keep their bytes, ETags and metadata, listings page and group, multipart uploads assemble, and nothing reaches AWS.",
    "auth": "No real keys needed: sign as usual with any, like <code>test</code> and <code>test</code>. The signature isn't checked.",
    "versionDocs": "https://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html",
    "snippets": [
      {
        "label": "Postman CLI",
        "code": "postman request PUT {{BASE_URL}}/my-bucket -H \"x-mock-session: $MOCK_SESSION\"\npostman request PUT {{BASE_URL}}/my-bucket/hello.txt \\\n  -H \"x-mock-session: $MOCK_SESSION\" -H \"Content-Type:text/plain\" -d \"Hello, S3\"\npostman request GET \"{{BASE_URL}}/my-bucket?list-type=2\" -H \"x-mock-session: $MOCK_SESSION\""
      }
    ],
    "dataSections": [
      {
        "title": "Limits it enforces",
        "description": "As S3 does, with S3's error codes.",
        "columns": [
          "Rule",
          "Error"
        ],
        "rows": [
          {
            "cells": [
              "Bucket names: 3–63 lowercase letters, digits, dots and hyphens",
              "InvalidBucketName"
            ],
            "tone": "error"
          },
          {
            "cells": [
              "Deleting a bucket that still has objects",
              "BucketNotEmpty"
            ],
            "tone": "error"
          },
          {
            "cells": [
              "Multipart parts except the last under 5 MiB",
              "EntityTooSmall"
            ],
            "tone": "error"
          },
          {
            "cells": [
              "Parts listed out of order, or with the wrong ETag",
              "InvalidPartOrder, InvalidPart"
            ],
            "tone": "error"
          },
          {
            "cells": [
              "A Range past the end of the object",
              "InvalidRange (416)"
            ],
            "tone": "error"
          },
          {
            "cells": [
              "If-Match / If-None-Match: * on put, If-Unmodified-Since",
              "PreconditionFailed (412)"
            ],
            "tone": "warning"
          },
          {
            "cells": [
              "If-None-Match / If-Modified-Since on get when unchanged",
              "304 Not Modified"
            ],
            "tone": "success"
          }
        ]
      }
    ],
    "coverage": "Also follows S3's XML and errors, ETags (multipart ones too), checksums sent by the SDK, aws-chunked uploads, presigned URLs (accepted; the signature isn't checked) and virtual-host-style requests. Not covered yet: versioning, ACLs and policies, tagging, lifecycle, encryption options, event notifications, Object Lock and S3 Select.",
    "sources": [
      {
        "label": "S3 Smithy model",
        "href": "https://github.com/aws/api-models-aws/tree/main/models/s3",
        "detail": "AWS publishes no OpenAPI spec"
      },
      {
        "label": "Amazon S3 API reference",
        "href": "https://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html"
      },
      {
        "label": "Error responses",
        "href": "https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html",
        "detail": "error codes and messages"
      }
    ],
    "testData": [
      {
        "id": "forcePathStyle: true",
        "result": "how the AWS SDK should be configured for the mock's URL"
      },
      {
        "id": "GET /docs (Accept: application/json)",
        "result": "this descriptor (GET / is ListBuckets)"
      }
    ]
  },
  "scenarios": [
    {
      "name": "default",
      "title": "S3 in one region",
      "description": "Buckets and objects behave as on S3 in us-east-1: objects come back byte for byte with their ETag, metadata and checksums, listings page and group by delimiter, and multipart uploads assemble."
    },
    {
      "name": "slow-down",
      "title": "Every request is throttled",
      "description": "Every request is a 503 SlowDown, as S3 answers a prefix receiving too many requests. Nothing is stored or changed."
    },
    {
      "name": "access-denied",
      "title": "The credentials have no access",
      "description": "Every request is a 403 AccessDenied, as for a policy or role that doesn't allow it."
    },
    {
      "name": "internal-error",
      "title": "S3 is failing",
      "description": "Every request is a 500 InternalError."
    }
  ],
  "routes": [
    {
      "method": "GET",
      "path": "/",
      "summary": "ListBuckets.",
      "group": "buckets"
    },
    {
      "method": "PUT",
      "path": "/:bucket",
      "summary": "CreateBucket.",
      "group": "buckets"
    },
    {
      "method": "HEAD",
      "path": "/:bucket",
      "summary": "HeadBucket.",
      "group": "buckets"
    },
    {
      "method": "DELETE",
      "path": "/:bucket",
      "summary": "DeleteBucket (only when empty).",
      "group": "buckets"
    },
    {
      "method": "GET",
      "path": "/:bucket",
      "summary": "ListObjectsV2 (list-type=2), ListObjects, GetBucketLocation (?location), ListMultipartUploads (?uploads).",
      "group": "buckets"
    },
    {
      "method": "POST",
      "path": "/:bucket",
      "summary": "DeleteObjects (?delete).",
      "group": "buckets"
    },
    {
      "method": "GET",
      "path": "/:bucket/:key*",
      "summary": "GetObject, with Range and conditional requests.",
      "group": "objects"
    },
    {
      "method": "HEAD",
      "path": "/:bucket/:key*",
      "summary": "HeadObject.",
      "group": "objects"
    },
    {
      "method": "PUT",
      "path": "/:bucket/:key*",
      "summary": "PutObject, CopyObject (x-amz-copy-source), UploadPart (?partNumber&uploadId).",
      "group": "objects"
    },
    {
      "method": "DELETE",
      "path": "/:bucket/:key*",
      "summary": "DeleteObject, AbortMultipartUpload (?uploadId).",
      "group": "objects"
    },
    {
      "method": "POST",
      "path": "/:bucket/:key*",
      "summary": "CreateMultipartUpload (?uploads), CompleteMultipartUpload (?uploadId).",
      "group": "objects"
    }
  ]
};

// ═══ SPEC: the API version ═══════════════════════════════════════════════════════════════════════
const SPEC = {
  "version": "2006-03-01",
  "params": {}
};

start();
