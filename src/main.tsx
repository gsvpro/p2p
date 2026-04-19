import { Buffer } from 'buffer';
import process from 'process';

window.Buffer = window.Buffer || Buffer;
window.process = window.process || process;

import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import './index.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
