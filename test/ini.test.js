const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

const ini = require('../ini');

function tempFile(content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'winapi-ini-'));
  const filePath = path.join(dir, 'test.ini');
  if (content !== undefined) fs.writeFileSync(filePath, content);
  return filePath;
}

const SAMPLE = Buffer.from(
  '; leading comment\r\n'
  + '[General]\r\n'
  + 'sLanguage = ENGLISH\r\n'
  + '; inner comment\r\n'
  + 'sQuoted="quoted value"\r\n'
  + 'noValue\r\n'
  + '\r\n'
  + '[ Display ]\r\n'
  + 'iSize W=1920\r\n'
  + '[general]\r\n'
  + 'sShadowed=1\r\n',
  'latin1');

test('lists named sections', () => {
  const filePath = tempFile(SAMPLE);
  assert.deepStrictEqual(ini.GetPrivateProfileSectionNames(filePath), ['General', 'Display', 'general']);
});

test('reads the first matching section without comments or bare keys', () => {
  const filePath = tempFile(SAMPLE);
  assert.deepStrictEqual(ini.GetPrivateProfileSection('GENERAL', filePath), {
    sLanguage: 'ENGLISH',
    sQuoted: '"quoted value"',
  });
  assert.deepStrictEqual(ini.GetPrivateProfileSection('display', filePath), { 'iSize W': '1920' });
});

test('reads single values with quotes stripped and defaults', () => {
  const filePath = tempFile(SAMPLE);
  assert.deepStrictEqual(ini.GetPrivateProfileString('General', 'squoted', '', filePath), ['quoted value']);
  assert.deepStrictEqual(ini.GetPrivateProfileString('General', 'missing', 'fallback  ', filePath), ['fallback']);
  assert.deepStrictEqual(ini.GetPrivateProfileString('General', 'missing', '', filePath), []);
});

test('treats a missing file as empty', () => {
  const filePath = tempFile();
  assert.deepStrictEqual(ini.GetPrivateProfileSectionNames(filePath), []);
  assert.deepStrictEqual(ini.GetPrivateProfileSection('General', filePath), {});
});

test('updates, adds and deletes keys while keeping comments', () => {
  const filePath = tempFile(SAMPLE);
  ini.WritePrivateProfileString('general', 'slanguage', '  FRENCH', filePath);
  ini.WritePrivateProfileString('General', 'bNew', '1', filePath);
  ini.WritePrivateProfileString('General', 'noValue', null, filePath);
  ini.WritePrivateProfileString('Archive', 'bInvalidateOlderFiles', '1', filePath);
  assert.strictEqual(fs.readFileSync(filePath, 'latin1'),
    '; leading comment\r\n'
    + '[General]\r\n'
    + 'sLanguage=FRENCH\r\n'
    + '; inner comment\r\n'
    + 'sQuoted="quoted value"\r\n'
    + 'bNew=1\r\n'
    + '[Display]\r\n'
    + 'iSize W=1920\r\n'
    + '[general]\r\n'
    + 'sShadowed=1\r\n'
    + '[Archive]\r\n'
    + 'bInvalidateOlderFiles=1\r\n');
});

test('creates missing files', () => {
  const filePath = tempFile();
  ini.WritePrivateProfileString('Display', 'iSize H', '1080', filePath);
  assert.strictEqual(fs.readFileSync(filePath, 'latin1'), '[Display]\r\niSize H=1080\r\n');
});

test('keeps the encoding of the file', () => {
  const ansi = tempFile(Buffer.from('[General]\r\nsName=caf\xe9\r\n', 'latin1'));
  assert.deepStrictEqual(ini.GetPrivateProfileSection('General', ansi), { sName: 'café' });
  ini.WritePrivateProfileString('General', 'sOther', 'é€', ansi);
  assert.deepStrictEqual(fs.readFileSync(ansi), Buffer.from([
    ...Buffer.from('[General]\r\nsName=caf\xe9\r\nsOther=\xe9', 'latin1'), 0x80, 0x0d, 0x0a]));

  const utf16 = tempFile(Buffer.concat([Buffer.from([0xFF, 0xFE]), Buffer.from('[A]\r\nk=é\r\n', 'utf16le')]));
  assert.deepStrictEqual(ini.GetPrivateProfileSection('A', utf16), { k: 'é' });
  ini.WritePrivateProfileString('A', 'k', 'ü', utf16);
  assert.deepStrictEqual(fs.readFileSync(utf16),
    Buffer.concat([Buffer.from([0xFF, 0xFE]), Buffer.from('[A]\r\nk=ü\r\n', 'utf16le')]));
});
