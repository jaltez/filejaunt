// Minimal DOM helpers: logging, pairing step text, badge, file lists.

export function qs<T extends HTMLElement>(sel: string): T {
  const el = document.querySelector<T>(sel);
  if (!el) throw new Error(`missing element ${sel}`);
  return el;
}

export function log(line: string): void {
  const el = qs<HTMLElement>('#log');
  const stamp = new Date().toISOString().slice(11, 23);
  el.textContent += `[${stamp}] ${line}\n`;
  el.scrollTop = el.scrollHeight;
}

export function setStep(text: string): void {
  qs<HTMLElement>('#pair-step').textContent = text;
}

export function badge(text: string, color: string): void {
  const el = qs<HTMLElement>('#badge');
  el.textContent = text;
  el.style.color = color;
}

export interface QueueItem {
  id: number;
  name: string;
  progress: number; // 0..100
  detail: string; // % / MiB/s
  paused: boolean;
  onPause(): void;
  onCancel(): void;
}

export function renderQueue(items: QueueItem[]): void {
  const ul = qs<HTMLElement>('#queue');
  ul.textContent = '';
  for (const it of items) {
    const li = document.createElement('li');
    const name = document.createElement('span');
    name.textContent = it.name + ' ';
    const prog = document.createElement('progress');
    prog.max = 100;
    prog.value = it.progress;
    const det = document.createElement('span');
    det.textContent = ` ${it.detail}`;
    const pause = document.createElement('button');
    pause.className = 'pause';
    pause.textContent = it.paused ? 'Resume' : 'Pause';
    pause.onclick = it.onPause;
    const cancel = document.createElement('button');
    cancel.className = 'cancel';
    cancel.textContent = 'Cancel';
    cancel.onclick = it.onCancel;
    li.append(name, prog, det, pause, cancel);
    ul.append(li);
  }
}

export interface FileItemView {
  name: string;
  progress: number;
  detail: string;
}

export function renderFiles(items: FileItemView[]): void {
  const ul = qs<HTMLElement>('#files');
  ul.textContent = '';
  for (const it of items) {
    const li = document.createElement('li');
    const name = document.createElement('span');
    name.textContent = it.name + ' ';
    const prog = document.createElement('progress');
    prog.max = 100;
    prog.value = it.progress;
    const det = document.createElement('span');
    det.textContent = ` ${it.detail}`;
    li.append(name, prog, det);
    ul.append(li);
  }
}

export function appendText(text: string): void {
  const el = qs<HTMLElement>('#text-log');
  el.textContent += text + '\n';
}
