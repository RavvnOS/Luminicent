import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  classifyProjectFile,
  readProjectFile
} from './projectFileReader.js';

const makeRoot = () => fs.mkdtempSync(path.join(os.tmpdir(), 'luminicent-project-reader-'));

const writeFile = (root, name, contents) => {
  const filePath = path.join(root, name);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, contents);
  return filePath;
};

test('classifies source, configuration, documentation, binary, ignored, and unsupported files', () => {
  assert.equal(classifyProjectFile('src/app.ts'), 'source');
  assert.equal(classifyProjectFile('package.json'), 'configuration');
  assert.equal(classifyProjectFile('Pipfile.lock'), 'configuration');
  assert.equal(classifyProjectFile('README.md'), 'document');
  assert.equal(classifyProjectFile('assets/logo.png'), 'binary');
  assert.equal(classifyProjectFile('Thumbs.db'), 'ignored');
  assert.equal(classifyProjectFile('service.unknown'), 'unsupported');
});

test('strictly decodes Unicode, strips a UTF-8 BOM, and treats empty files as readable', (t) => {
  const root = makeRoot();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const unicodePath = writeFile(root, 'nested/unicode.ts', Buffer.concat([
    Buffer.from([0xEF, 0xBB, 0xBF]),
    Buffer.from('export const greeting = "こんにちは 🌍";\n', 'utf8')
  ]));
  const emptyPath = writeFile(root, 'empty.py', Buffer.alloc(0));

  const unicode = readProjectFile(fs, unicodePath, { maxBytes: 1024, rootPath: root });
  const empty = readProjectFile(fs, emptyPath, { maxBytes: 0, rootPath: root });

  assert.equal(unicode.content, 'export const greeting = "こんにちは 🌍";\n');
  assert.equal(unicode.hadUtf8Bom, true);
  assert.equal(unicode.status, 'decoded');
  assert.equal(empty.content, '');
  assert.equal(empty.byteLength, 0);
});

test('distinguishes invalid UTF-8, UTF-16, binary controls, and oversized files', (t) => {
  const root = makeRoot();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const invalidUtf8 = writeFile(root, 'invalid.js', Buffer.from([0x66, 0x80]));
  const utf16 = writeFile(root, 'utf16.json', Buffer.from([0xFF, 0xFE, 0x7B, 0x00]));
  const binary = writeFile(root, 'binary.js', Buffer.from([0x7B, 0x01, 0x7D]));
  const large = writeFile(root, 'large.py', Buffer.from('12345'));

  assert.throws(
    () => readProjectFile(fs, invalidUtf8, { maxBytes: 1024, rootPath: root }),
    (error) => error.code === 'PROJECT_FILE_INVALID_UTF8' && error.relativePath === 'invalid.js'
  );
  assert.throws(
    () => readProjectFile(fs, utf16, { maxBytes: 1024, rootPath: root }),
    (error) => error.code === 'PROJECT_FILE_UNSUPPORTED_ENCODING'
  );
  assert.throws(
    () => readProjectFile(fs, binary, { maxBytes: 1024, rootPath: root }),
    (error) => error.code === 'PROJECT_FILE_BINARY'
  );
  assert.throws(
    () => readProjectFile(fs, large, { maxBytes: 4, rootPath: root }),
    (error) => error.code === 'PROJECT_FILE_TOO_LARGE'
  );
});

test('rejects files outside the supplied root and reports read failures as typed errors', (t) => {
  const root = makeRoot();
  const outsideRoot = makeRoot();
  t.after(() => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(outsideRoot, { recursive: true, force: true });
  });
  const outsidePath = writeFile(outsideRoot, 'outside.js', 'export const value = 1;\n');

  assert.throws(
    () => readProjectFile(fs, outsidePath, { maxBytes: 1024, rootPath: root }),
    (error) => error.code === 'PROJECT_FILE_OUTSIDE_ROOT'
  );
});
