import { Buffer } from 'buffer';
import process from 'process';

// @ts-ignore
window.global = window;
window.Buffer = window.Buffer || Buffer;
window.process = window.process || process;

if (window.process && !window.process.nextTick) {
  // @ts-ignore
  window.process.nextTick = (fn, ...args) => setTimeout(() => fn(...args), 0);
}

// Some libraries expect process.env to be defined
if (window.process && !window.process.env) {
  window.process.env = {};
}
