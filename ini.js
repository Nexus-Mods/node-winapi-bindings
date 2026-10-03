// Pure JS versions of the private profile functions for platforms without the
// native module. They follow the behaviour of the Windows (and Wine)
// implementation so files written by the game or Wine stay compatible.

const fs = require('fs');

const BOM_UTF8 = Buffer.from([0xEF, 0xBB, 0xBF]);

const cp1252 = new TextDecoder('windows-1252');
const cp1252Reverse = new Map();
for (let byte = 0; byte < 256; ++byte) {
  cp1252Reverse.set(cp1252.decode(Buffer.from([byte])), byte);
}

function isSpace(char) {
  const code = char.charCodeAt(0);
  return (code >= 0x09 && code <= 0x0d) || code === 0x1a || code === 0x20;
}

function trim(input) {
  let start = 0;
  let end = input.length;
  while (start < end && isSpace(input[start])) ++start;
  while (end > start && isSpace(input[end - 1])) --end;
  return input.slice(start, end);
}

function decode(buffer) {
  if (buffer.subarray(0, 3).equals(BOM_UTF8)) {
    return { encoding: 'utf8', text: buffer.subarray(3).toString('utf8') };
  }
  if (buffer[0] === 0xFF && buffer[1] === 0xFE) {
    return { encoding: 'utf16le', text: buffer.subarray(2).toString('utf16le') };
  }
  if (buffer[0] === 0xFE && buffer[1] === 0xFF) {
    return { encoding: 'utf16be', text: Buffer.from(buffer.subarray(2)).swap16().toString('utf16le') };
  }
  return { encoding: 'ansi', text: cp1252.decode(buffer) };
}

function encode(text, encoding) {
  switch (encoding) {
    case 'utf8': return Buffer.concat([BOM_UTF8, Buffer.from(text, 'utf8')]);
    case 'utf16le': return Buffer.concat([Buffer.from([0xFF, 0xFE]), Buffer.from(text, 'utf16le')]);
    case 'utf16be': return Buffer.concat([Buffer.from([0xFE, 0xFF]), Buffer.from(text, 'utf16le').swap16()]);
    default:
      // characters missing from the code page become '?', like WideCharToMultiByte
      return Buffer.from(Array.from(text, (char) => cp1252Reverse.get(char) ?? 0x3F));
  }
}

function load(fileName) {
  let buffer;
  try {
    buffer = fs.readFileSync(fileName);
  } catch (err) {
    if (err.code === 'ENOENT') {
      return { encoding: 'ansi', sections: [{ name: '', keys: [] }] };
    }
    throw err;
  }

  const { encoding, text } = decode(buffer);
  const sections = [{ name: '', keys: [] }];
  for (const rawLine of text.split(/[\r\n]+/)) {
    const line = trim(rawLine);
    if (line.length === 0) continue;

    const closing = line.lastIndexOf(']');
    if (line[0] === '[' && closing > 0) {
      sections.push({ name: trim(line.slice(1, closing)), keys: [] });
      continue;
    }

    const keys = sections[sections.length - 1].keys;
    const eqPos = line.indexOf('=');
    const name = eqPos === -1 ? line : trim(line.slice(0, eqPos));
    const value = eqPos === -1 ? null : trim(line.slice(eqPos + 1));
    const prev = keys[keys.length - 1];
    // consecutive lines with an empty name collapse into one
    if (name.length > 0 || prev === undefined || prev.name.length > 0) {
      keys.push({ name, value });
    }
  }
  return { encoding, sections };
}

function save(fileName, profile) {
  const text = profile.sections.map((section) => {
    const header = section.name.length > 0 ? `[${section.name}]\r\n` : '';
    const keys = section.keys.map((key) => (key.value === null ? key.name : `${key.name}=${key.value}`) + '\r\n');
    return header + keys.join('');
  }).join('');
  fs.writeFileSync(fileName, encode(text, profile.encoding));
}

function sameName(lhs, rhs) {
  return lhs.toLowerCase() === trim(rhs).toLowerCase();
}

function findSection(profile, sectionName) {
  return profile.sections.find((section) => sameName(section.name, sectionName));
}

function stripQuotes(value) {
  const quote = value[0];
  if ((quote === '"' || quote === "'") && value.length > 1 && value[value.length - 1] === quote) {
    return value.slice(1, -1);
  }
  return value;
}

function GetPrivateProfileSection(sectionName, fileName) {
  const result = {};
  const section = findSection(load(fileName), sectionName);
  for (const key of section?.keys ?? []) {
    if (key.value !== null && key.name[0] !== ';') {
      result[key.name] = key.value;
    }
  }
  return result;
}

function GetPrivateProfileSectionNames(fileName) {
  return load(fileName).sections
    .map((section) => section.name)
    .filter((name) => name.length > 0);
}

function GetPrivateProfileString(sectionName, keyName, defaultValue, fileName) {
  const section = findSection(load(fileName), sectionName);
  const key = section?.keys.find((iter) => sameName(iter.name, keyName));
  const value = key?.value ?? (defaultValue ?? '').replace(/ +$/, '');
  const result = stripQuotes(value);
  return result.length > 0 ? [result] : [];
}

function WritePrivateProfileString(sectionName, keyName, value, fileName) {
  const profile = load(fileName);
  const sectionTrimmed = trim(sectionName);
  const keyTrimmed = trim(keyName);

  if (value === null || value === undefined) {
    for (const section of profile.sections.filter((iter) => sameName(iter.name, sectionTrimmed))) {
      const idx = section.keys.findIndex((key) => sameName(key.name, keyTrimmed));
      if (idx !== -1) {
        section.keys.splice(idx, 1);
        save(fileName, profile);
        return;
      }
    }
    return;
  }

  const newValue = value.replace(/^[\t\n\v\f\r\x1a ]+/, '');
  let section = findSection(profile, sectionTrimmed);
  if (section === undefined) {
    section = { name: sectionTrimmed, keys: [] };
    profile.sections.push(section);
  }
  let key = section.keys.find((iter) => sameName(iter.name, keyTrimmed));
  if (key === undefined) {
    key = { name: keyTrimmed, value: null };
    section.keys.push(key);
  } else if (key.value === newValue) {
    return;
  }
  key.value = newValue;
  save(fileName, profile);
}

module.exports = {
  GetPrivateProfileSection,
  GetPrivateProfileSectionNames,
  GetPrivateProfileString,
  WritePrivateProfileString,
};
