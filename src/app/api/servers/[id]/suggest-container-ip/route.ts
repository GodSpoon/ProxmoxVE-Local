import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { getDatabase } from '../../../../../server/database-prisma';
import { getSSHExecutionService } from '../../../../../server/ssh-execution-service';
import type { Server } from '../../../../../types/server';
import { buildIpCandidates, extractIpFromAddress, parseContainerIpRange } from '../../../../../lib/containerIpRange';

const DEFAULT_CONTAINER_IP_RANGE = '192.168.70.1-254';
const PROBE_ATTEMPTS = 3;
const IPV4_PATTERN =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

function runRemoteCommand(
  server: Server,
  command: string,
  timeoutMs: number,
): Promise<{ stdout: string; exitCode: number }> {
  const ssh = getSSHExecutionService();
  return new Promise((resolve, reject) => {
    const chunks: string[] = [];
    let settled = false;

    const finish = (stdout: string, exitCode: number) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ stdout, exitCode });
    };

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error('IP suggestion probe timed out'));
    }, timeoutMs);

    ssh
      .executeCommand(
        server,
        command,
        (data: string) => chunks.push(data),
        (_stderr: string) => { /* ignored */ },
        (code: number) => finish(chunks.join(''), code),
      )
      .catch((err) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(err instanceof Error ? err : new Error(String(err)));
        }
      });
  });
}

async function probeIpUsage(server: Server, ip: string): Promise<number | null> {
  if (!IPV4_PATTERN.test(ip)) return null;
  try {
    let hitCount = 0;
    for (let i = 0; i < PROBE_ATTEMPTS; i += 1) {
      const { exitCode } = await runRemoteCommand(
        server,
        `ping -c 1 -W 1 ${ip}`,
        5000,
      );
      if (exitCode === 0) {
        hitCount += 1;
      }
    }
    return hitCount;
  } catch {
    return null;
  }
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id: idParam } = await params;
    const id = parseInt(idParam, 10);
    if (Number.isNaN(id)) {
      return NextResponse.json({ error: 'Invalid server ID' }, { status: 400 });
    }

    const includeIntermittent =
      request.nextUrl.searchParams.get('includeIntermittent') === 'true';

    const db = getDatabase();
    const server = (await db.getServerById(id)) as Server | null;
    if (!server) {
      return NextResponse.json({ error: 'Server not found' }, { status: 404 });
    }

    const configuredRangeRaw = server.container_ip_range?.trim();
    const configuredRange =
      configuredRangeRaw && configuredRangeRaw.length > 0
        ? configuredRangeRaw
        : DEFAULT_CONTAINER_IP_RANGE;
    const parsedRange = parseContainerIpRange(configuredRange);
    if (!parsedRange) {
      return NextResponse.json(
        { error: 'Configured container IP range is invalid' },
        { status: 400 },
      );
    }

    const installed = (await db.getInstalledScriptsByServer(id)) as Array<{
      lxc_config?: { net_ip?: string | null } | null;
    }>;
    const reservedIps = new Set<string>();
    for (const script of installed) {
      const ip = extractIpFromAddress(script.lxc_config?.net_ip);
      if (ip) reservedIps.add(ip);
    }

    const candidates = buildIpCandidates(parsedRange);
    let skippedIntermittent = 0;

    for (const ip of candidates) {
      if (reservedIps.has(ip)) continue;

      const probeHits = await probeIpUsage(server, ip);
      const isProbeUnavailable = probeHits === null;
      const isInUse = probeHits === PROBE_ATTEMPTS;
      const isIntermittent = probeHits !== null && probeHits > 0 && probeHits < PROBE_ATTEMPTS;

      if (isInUse) continue;
      if (isIntermittent && !includeIntermittent) {
        skippedIntermittent += 1;
        continue;
      }

      const status = isProbeUnavailable
        ? 'unverified'
        : isIntermittent
          ? 'intermittent'
          : 'available';

      return NextResponse.json({
        success: true,
        configuredRange: parsedRange.normalized,
        suggestedIp: ip,
        suggestedCidr: `${ip}/${parsedRange.cidr}`,
        status,
        skippedIntermittent,
      });
    }

    return NextResponse.json(
      {
        success: false,
        configuredRange: parsedRange.normalized,
        error: 'No available IP found in configured range',
      },
      { status: 409 },
    );
  } catch (error) {
    console.error('Error suggesting container IP:', error);
    return NextResponse.json(
      { error: 'Failed to suggest container IP' },
      { status: 500 },
    );
  }
}
