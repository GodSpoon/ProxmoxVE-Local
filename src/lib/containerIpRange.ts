export interface ParsedContainerIpRange {
  prefix: string;
  startHost: number;
  endHost: number;
  cidr: number;
  normalized: string;
}

const RANGE_PATTERN =
  /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})-(\d{1,3})(?:\/(\d|[12]\d|3[0-2]))?$/;

export function parseContainerIpRange(
  range: string,
): ParsedContainerIpRange | null {
  const trimmed = range.trim();
  const match = RANGE_PATTERN.exec(trimmed);
  if (!match) return null;

  const o1 = Number(match[1]);
  const o2 = Number(match[2]);
  const o3 = Number(match[3]);
  const startHost = Number(match[4]);
  const endHost = Number(match[5]);
  const cidr = match[6] ? Number(match[6]) : 24;

  const octets = [o1, o2, o3, startHost, endHost];
  if (octets.some((octet) => Number.isNaN(octet) || octet < 0 || octet > 255)) {
    return null;
  }
  if (startHost > endHost) return null;
  if (startHost === 0 || endHost === 0) return null;
  if (cidr < 0 || cidr > 32) return null;

  return {
    prefix: `${o1}.${o2}.${o3}`,
    startHost,
    endHost,
    cidr,
    normalized: `${o1}.${o2}.${o3}.${startHost}-${endHost}${match[6] ? `/${cidr}` : ""}`,
  };
}

export function isValidContainerIpRange(range: string | undefined): boolean {
  if (!range?.trim()) return true;
  return parseContainerIpRange(range) !== null;
}

export function buildIpCandidates(parsed: ParsedContainerIpRange): string[] {
  const candidates: string[] = [];
  for (let host = parsed.startHost; host <= parsed.endHost; host += 1) {
    candidates.push(`${parsed.prefix}.${host}`);
  }
  return candidates;
}

export function extractIpFromAddress(value: string | null | undefined): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  const [ip] = trimmed.split("/");
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ip || !ipv4Pattern.test(ip)) return null;
  const octets = ip.split(".").map(Number);
  if (octets.some((octet) => Number.isNaN(octet) || octet < 0 || octet > 255)) {
    return null;
  }
  return ip;
}
