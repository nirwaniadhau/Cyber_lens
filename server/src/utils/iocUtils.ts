import { IocType } from "../constants/provider.interface";

function detectIocType(ioc: string): IocType | null {
    /*
          The utility must support:
              - ip
              - domain
              - url
              - hash
      */
    const value = ioc.trim();

    // ---------- IP (IPv4) ----------
    const ipRegex =
        /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

    if (ipRegex.test(value)) {
        return "ip";
    }

    // ---------- URL ----------
    try {
        const url = new URL(value);
        if (url.protocol === "http:" || url.protocol === "https:") {
            return "url";
        }
    } catch {
        // not a URL
    }

    // ---------- Domain ----------
    const domainRegex =
        /^(?!:\/\/)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;

    if (domainRegex.test(value)) {
        return "domain";
    }

    // ---------- Hash (MD5 / SHA1 / SHA256) ----------
    const hashRegex =
        /^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/;

    if (hashRegex.test(value)) {
        return "hash";
    }

    // ------- Does not match anything -------
    return null;
}

function validateIocType(
    ioc: string,
    selectedType: IocType
): { isValid: boolean; detectedType: IocType | null } {
    const detectedType: IocType | null = detectIocType(ioc);

    return {
        isValid: detectedType === selectedType,
        detectedType,
    };
}

export { detectIocType, validateIocType };
