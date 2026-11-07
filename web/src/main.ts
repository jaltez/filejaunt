// Minimal DOM adapter for the filejaunt library: the reference implementation
// behind web/index.html. Every engine event maps to one element update, and
// every button maps to one library call. Copy this file as a starting point;
// it intentionally keeps no state of its own beyond the last passphrase.

import { Jaunt, doctorProbe, type FileView, type IceConfig, type PathInfo } from './library';
import { StreamPlayer } from './media';
import * as ui from './ui';

type Role = 'sender' | 'receiver';

let jaunt: Jaunt;
let role: Role | null = null;
let lastPassphrase = '';

function iceConfig(): IceConfig {
  const stun = ui
    .qs<HTMLInputElement>('#stun')
    .value.split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const turnUrl = ui.qs<HTMLInputElement>('#turn-url').value.trim();
  const turnUser = ui.qs<HTMLInputElement>('#turn-user').value.trim();
  const turnPass = ui.qs<HTMLInputElement>('#turn-pass').value;
  return stun.length || turnUrl
    ? {
        stunUrls: stun,
        turn: turnUrl ? { urls: [turnUrl], username: turnUser, credential: turnPass } : undefined,
      }
    : { stunUrls: [] };
}

function fmtBytes(n: number): string {
  return n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MiB` : `${(n / 1024).toFixed(1)} KiB`;
}

function renderBadge(info: PathInfo | null): void {
  if (!info) return;
  if (info.kind === 'relay') ui.badge('RELAY', '#b8860b');
  else if (info.kind === 'unknown') ui.badge(info.text, '#555');
  else ui.badge(info.text, '#0a7d0a');
}

function renderFiles(files: FileView[]): void {
  if (role === 'sender') {
    ui.renderQueue(
      files.map((f) => ({
        id: f.id,
        name: f.name,
        progress: f.progress,
        detail: `${f.progress}% ${fmtBytes(f.wireBytes)} on wire${f.verified ? ' verified' : ''}`,
        paused: !!f.paused,
        onPause: () => void jaunt.togglePause(f.id),
        onCancel: () => void jaunt.cancel(f.id),
      })),
    );
  } else {
    ui.renderFiles(
      files.map((f) => ({
        name: f.name,
        progress: f.progress,
        detail: `${f.progress}% ${fmtBytes(f.wireBytes)}${f.verified ? ' verified' : ''}`,
      })),
    );
  }
}

async function boot(): Promise<void> {
  jaunt = await Jaunt.create({
    getIce: iceConfig,
    createPlayer: () => {
      ui.qs<HTMLElement>('#video').classList.remove('hide');
      return new StreamPlayer(ui.qs<HTMLVideoElement>('#video'));
    },
    events: {
      log: (line) => ui.log(line),
      step: (text) => ui.setStep(text),
      passphrase: (text) => {
        lastPassphrase = text;
        ui.qs<HTMLElement>('#passphrase-wrap').classList.remove('hide');
        ui.qs<HTMLElement>('#passphrase-out').textContent = text;
      },
      blobOut: (blob) => {
        ui.qs<HTMLTextAreaElement>('#blob-out').value = blob;
      },
      files: (files) => renderFiles(files),
      text: (line) => ui.appendText(line),
      path: (info) => renderBadge(info),
      download: (name, blob) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = name;
        a.textContent = `download ${name}`;
        a.rel = 'noopener';
        ui.qs<HTMLElement>('#files').append(a);
      },
      doctor: (r) => {
        ui.qs<HTMLElement>('#doctor-out').textContent = r.detail;
      },
      reset: () => {
        ui.qs<HTMLElement>('#files').replaceChildren();
        ui.qs<HTMLElement>('#queue').replaceChildren();
        ui.qs<HTMLElement>('#video').classList.add('hide');
      },
    },
  });
  window.__fj = jaunt.hook;
  ui.badge('—', '#555');

  ui.qs<HTMLElement>('#btn-send').onclick = () => {
    role = 'sender';
    jaunt.setRole('sender');
    ui.qs<HTMLElement>('#send-panel').classList.remove('hide');
    ui.qs<HTMLElement>('#pair').classList.remove('hide');
    ui.setStep('pick files to send');
  };
  ui.qs<HTMLElement>('#btn-recv').onclick = () => {
    role = 'receiver';
    jaunt.setRole('receiver');
    ui.qs<HTMLElement>('#recv-panel').classList.remove('hide');
    ui.qs<HTMLElement>('#pair').classList.remove('hide');
    ui.setStep('paste blob-1 and the passphrase, then press Process');
  };
  ui.qs<HTMLInputElement>('#file-input').addEventListener('change', (e) => {
    const input = e.target as HTMLInputElement;
    const files = [...(input.files ?? [])];
    void jaunt
      .send(files, {
        words: Number(ui.qs<HTMLInputElement>('#words').value) || 6,
        privatePairing: ui.qs<HTMLInputElement>('#private3').checked,
        channels: Number(ui.qs<HTMLSelectElement>('#channels').value) || 1,
        gzip: ui.qs<HTMLSelectElement>('#gzip').value as 'auto' | 'on' | 'off',
        live: ui.qs<HTMLInputElement>('#live').checked,
      })
      .catch((e) => ui.log(`error: ${e}`));
  });
  ui.qs<HTMLInputElement>('#append-input').addEventListener('change', (e) => {
    const input = e.target as HTMLInputElement;
    const files = [...(input.files ?? [])];
    input.value = '';
    void jaunt.appendFiles(files).then((ok) => {
      if (!ok) ui.setStep('append needs a live share with a paired peer');
    });
  });
  ui.qs<HTMLElement>('#end-share').onclick = () => jaunt.endSession();
  ui.qs<HTMLElement>('#process').onclick = () => {
    void jaunt
      .process(ui.qs<HTMLTextAreaElement>('#blob-in').value, ui.qs<HTMLInputElement>('#pass-in').value)
      .catch((e) => ui.log(`error: ${e}`));
  };
  ui.qs<HTMLElement>('#restart').onclick = () => {
    void jaunt.restart().catch((e) => ui.log(`error: ${e}`));
  };
  ui.qs<HTMLElement>('#copy-pass').onclick = () => void navigator.clipboard?.writeText(lastPassphrase);
  ui.qs<HTMLElement>('#copy-blob').onclick = () =>
    void navigator.clipboard?.writeText(ui.qs<HTMLTextAreaElement>('#blob-out').value);
  ui.qs<HTMLElement>('#text-send-btn').onclick = () => {
    const input = ui.qs<HTMLInputElement>('#text-send');
    const text = input.value;
    void jaunt.sendText(text).then((ok) => {
      if (ok) input.value = '';
    });
  };
  ui.qs<HTMLElement>('#choose-dir').onclick = () => {
    if (!window.showDirectoryPicker) {
      ui.qs<HTMLElement>('#dir-note').textContent = 'will save via private storage / browser download';
      return;
    }
    void window
      .showDirectoryPicker()
      .then((d) => {
        jaunt.setDir(d);
        ui.qs<HTMLElement>('#dir-note').textContent = `saving into ${d.name}/`;
        ui.log(`output folder: ${d.name}`);
      })
      .catch(() => ui.log('folder picker cancelled/unavailable; using private storage'));
  };
  ui.qs<HTMLElement>('#doctor').onclick = () => {
    void doctorProbe(
      ui.qs<HTMLInputElement>('#stun')
        .value.split(',')
        .map((s) => s.trim())
        .filter(Boolean),
    ).then((r) => {
      jaunt.hook.doctor = r;
      ui.qs<HTMLElement>('#doctor-out').textContent = r.detail;
      ui.log(r.detail);
    });
  };
  ui.log('ready');
}

void boot();
