import { config } from '../config';

interface BootLine {
    label: string;
    value: string;
    ok: boolean;
}

const lines: BootLine[] = [];
let flushed = false;

function addLine(label: string, value: string, ok = true): void {
    lines.push({ label, value, ok });
}

function flush(): void {
    if (flushed) return;
    flushed = true;

    const w = 48;
    const bar = (c: string) => c.repeat(w);

    const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, '');

    console.log('');
    console.log(`  ╔${bar('═')}╗`);
    console.log(`  ║${' '.repeat(w)}║`);
    console.log(`  ║${center('UAM BACKEND', w)}║`);
    console.log(`  ║${' '.repeat(w)}║`);
    console.log(`  ╠${bar('═')}╣`);

    for (const l of lines) {
        const icon = l.ok ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m';
        const raw = `  ${icon}  ${l.label.padEnd(14)} ${l.value}`;
        const visibleLen = strip(raw).length;
        const pad = Math.max(0, w - visibleLen);
        console.log(`  ║${raw}${' '.repeat(pad)}║`);
    }

    console.log(`  ║${' '.repeat(w)}║`);
    console.log(`  ╠${bar('═')}╣`);
    console.log(`  ║${center(`${config.nodeEnv} | port ${config.port}`, w)}║`);
    console.log(`  ╚${bar('═')}╝`);
    console.log('');
}

function center(text: string, width: number): string {
    const left = Math.floor((width - text.length) / 2);
    const right = width - text.length - left;
    return ' '.repeat(Math.max(0, left)) + text + ' '.repeat(Math.max(0, right));
}

export const boot = {
    postgres(connected: boolean, poolMax: number) {
        addLine('PostgreSQL', connected ? `connected (pool max=${poolMax})` : 'FAILED', connected);
    },

    migrations(count: number) {
        if (count > 0) addLine('Migrations', `${count} applied`);
    },

    backfill(scanned: number, synced: number) {
        if (scanned > 0) addLine('Backfill', `${synced}/${scanned} users`);
    },

    redis(role: string, connected: boolean, viaUrl = false) {
        if (connected) {
            addLine('Redis', `${role} ready${viaUrl ? ' (URL)' : ''}`);
        }
    },

    rateLimit(mode: 'distributed' | 'fallback' | 'memory') {
        const label = mode === 'distributed'
            ? 'distributed (Redis)'
            : mode === 'fallback'
                ? 'fallback (in-memory)'
                : 'local (in-memory)';
        addLine('Rate Limit', label, mode !== 'fallback');
    },

    flush,
};
