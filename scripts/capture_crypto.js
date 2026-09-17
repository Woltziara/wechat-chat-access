'use strict';

const installed = new Set();
const emitted = new Set();

function toHex(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  let result = '';
  for (let i = 0; i < bytes.length; i++) {
    result += bytes[i].toString(16).padStart(2, '0');
  }
  return result;
}

function emitCandidate(pointer, length) {
  if (length !== 32 || pointer.isNull()) return;
  try {
    const value = toHex(pointer.readByteArray(32));
    if (emitted.has(value)) return;
    emitted.add(value);
    send({ kind: 'candidate', value: value });
  } catch (_) {
    // An unreadable candidate is ignored without logging memory details.
  }
}

function findExport(name) {
  try {
    return Module.findGlobalExportByName(name);
  } catch (_) {
    return null;
  }
}

function installCCCrypt() {
  const name = 'CCCrypt';
  if (installed.has(name)) return;
  const address = findExport(name);
  if (address === null) return;
  Interceptor.attach(address, {
    onEnter(args) {
      if (args[1].toInt32() === 0) emitCandidate(args[3], args[4].toInt32());
    }
  });
  installed.add(name);
}

function installCCCryptorCreate() {
  const name = 'CCCryptorCreate';
  if (installed.has(name)) return;
  const address = findExport(name);
  if (address === null) return;
  Interceptor.attach(address, {
    onEnter(args) {
      if (args[1].toInt32() === 0) emitCandidate(args[3], args[4].toInt32());
    }
  });
  installed.add(name);
}

function installCCCryptorCreateWithMode() {
  const name = 'CCCryptorCreateWithMode';
  if (installed.has(name)) return;
  const address = findExport(name);
  if (address === null) return;
  Interceptor.attach(address, {
    onEnter(args) {
      if (args[2].toInt32() === 0) emitCandidate(args[5], args[6].toInt32());
    }
  });
  installed.add(name);
}

function installPBKDF() {
  const name = 'CCKeyDerivationPBKDF';
  if (installed.has(name)) return;
  const address = findExport(name);
  if (address === null) return;
  Interceptor.attach(address, {
    onEnter(args) {
      emitCandidate(args[1], args[2].toInt32());
      this.output = args[7];
      this.outputLength = args[8].toInt32();
    },
    onLeave(retval) {
      if (retval.toInt32() === 0) emitCandidate(this.output, this.outputLength);
    }
  });
  installed.add(name);
}

function installAvailable() {
  const before = installed.size;
  try { installCCCrypt(); } catch (_) {}
  try { installCCCryptorCreate(); } catch (_) {}
  try { installCCCryptorCreateWithMode(); } catch (_) {}
  try { installPBKDF(); } catch (_) {}
  if (installed.size !== before || before === 0) {
    send({ kind: 'readiness', hooked: installed.size });
  }
}

// Registration happens while a spawned process is still suspended.  Frida's
// module observer invokes onAdded immediately after a module is loaded, before
// application code has had a chance to use it, so late-loaded CommonCrypto
// exports can be hooked without restarting the target.
Process.attachModuleObserver({
  onAdded(_module) {
    installAvailable();
  }
});

installAvailable();
