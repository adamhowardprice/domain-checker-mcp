#!/usr/bin/env python3
"""
Domain Availability Checker MCP Server
This server accepts domain queries and checks availability using RDAP.
"""

import logging
import sys
import httpx
from mcp.server import Server
import mcp.types as types
import asyncio
import aiodns
import argparse
from enum import Enum

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format="%(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logging.getLogger("httpx").setLevel(logging.WARNING)

logger = logging.getLogger("domain_checker")

# Constants
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
USER_AGENT = "DomainCheckerBot/1.0"

# Top TLDs to check
TOP_TLDS = [
    "com",
    "net",
    "org",
    "io",
    "co",
    "app",
    "dev",
    "ai",
    "me",
    "info",
    "xyz",
    "online",
    "site",
    "tech",
    # Add more TLDs as needed
]

# TLDs with unreliable RDAP (always return 404 even for registered domains)
UNRELIABLE_RDAP_TLDS = [
    "co",
    "me",
    "io",
    "sh",
    "ac",
]  # There are probably more of these

# Concurrency limit for domain checks
MAX_CONCURRENT_CHECKS = 100

# Initialize the server
app = Server("domain-checker")

# Global HTTP client
client = None


# Helper functions
async def get_rdap_data(domain):
    """Get RDAP data for a domain using httpx.AsyncClient. Returns (json, status_code)"""
    global client
    try:
        tld = domain.split(".")[-1].lower()
        if tld in ["ch", "li"]:
            rdap_url = f"https://rdap.nic.{tld}/domain/{domain}"
        else:
            if tld in ["com", "net"]:
                rdap_url = f"https://rdap.verisign.com/{tld}/v1/domain/{domain}"
            elif tld == "org":
                rdap_url = (
                    f"https://rdap.publicinterestregistry.org/rdap/domain/{domain}"
                )
            else:
                rdap_url = f"https://rdap.org/domain/{domain}"

        headers = {"Accept": "application/rdap+json", "User-Agent": USER_AGENT}
        response = await client.get(rdap_url, headers=headers, timeout=5)
        try:
            data = response.json()
        except Exception:
            data = None

        # Prefer errorCode from body if present
        if data and isinstance(data, dict) and "errorCode" in data:
            status_code = data["errorCode"]
        else:
            status_code = response.status_code

        return data, status_code
    except Exception as e:
        logger.error(f"RDAP error for {domain}: {e}")
        return None, None


# Remove global resolver
def get_resolver():
    loop = asyncio.get_running_loop()
    if not hasattr(get_resolver, "_resolvers"):
        get_resolver._resolvers = {}
    if loop not in get_resolver._resolvers:
        get_resolver._resolvers[loop] = aiodns.DNSResolver()
    return get_resolver._resolvers[loop]


async def check_dns(domain):
    """Check if a domain has DNS records using aiodns (async)"""
    resolver = get_resolver()
    try:
        await resolver.query(domain, "A")
        logger.debug(f"Found DNS records for {domain}")
        return True
    except Exception as e:
        logger.debug(f"No A record for {domain}: {e}")
        try:
            await resolver.query(domain, "NS")
            logger.debug(f"Found DNS records for {domain}")
            return True
        except Exception as e2:
            logger.debug(f"No NS record for {domain}: {e2}")
            logger.debug(f"No DNS records for {domain}")
            return False


class DomainStatus(Enum):
    AVAILABLE = "available"
    REGISTERED = "registered"
    UNKNOWN = "unknown"


async def check_single_domain_availability(domain):
    tld = domain.split(".")[-1].lower()
    has_dns = await check_dns(domain)
    rdap_data, rdap_status = await get_rdap_data(domain)

    if tld in UNRELIABLE_RDAP_TLDS:
        if has_dns:
            return (DomainStatus.REGISTERED, domain)
        else:
            return (DomainStatus.UNKNOWN, domain)

    # 404 means available (from HTTP or errorCode)
    if rdap_status == 404:
        return (DomainStatus.AVAILABLE, domain)
    # 200 and no errorCode means registered
    elif rdap_status == 200 and (not rdap_data or "errorCode" not in rdap_data):
        return (DomainStatus.REGISTERED, domain)
    # All other cases are unknown
    else:
        return (DomainStatus.UNKNOWN, domain)


async def check_domain_tool(domain):
    """Check if a domain is available for registration"""
    logger.info(f"Checking domain: {domain}")

    # First check DNS
    has_dns = await check_dns(domain)

    if has_dns:
        # Domain exists, get RDAP data if possible
        rdap_data, rdap_status = await get_rdap_data(domain)

        if rdap_status == 200 and rdap_data:
            # Extract data from RDAP
            registrar = "Unknown"
            reg_date = "Unknown"
            exp_date = "Unknown"

            # Extract registrar
            entities = rdap_data.get("entities", [])
            for entity in entities:
                if "registrar" in entity.get("roles", []):
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1 and isinstance(vcard[1], list):
                        for entry in vcard[1]:
                            if entry[0] in ["fn", "org"] and len(entry) > 3:
                                registrar = entry[3]
                                break

            # Extract dates
            events = rdap_data.get("events", [])
            for event in events:
                if event.get("eventAction") == "registration":
                    reg_date = event.get("eventDate", "Unknown")
                elif event.get("eventAction") == "expiration":
                    exp_date = event.get("eventDate", "Unknown")

            result = f"""
Domain: {domain}
Status: Registered
Registrar: {registrar}
Registration Date: {reg_date}
Expiration Date: {exp_date}
"""
            summary = "------------------------------------\nSummary:\n\nFound 0 Available domains."
            return result + "\n" + summary
        elif rdap_status == 404:
            result = f"""
Domain: {domain}
Status: Available
Note: No RDAP data found (404 Not Found)
"""
            summary = f"------------------------------------\nSummary:\n\nFound 1 Available domain:\n- {domain}"
            return result + "\n" + summary
        else:
            result = f"""
Domain: {domain}
Status: Registered
Note: Domain has DNS records but RDAP data couldn't be retrieved (status: {rdap_status})
"""
            summary = "------------------------------------\nSummary:\n\nFound 0 Available domains."
            return result + "\n" + summary

    # Try RDAP one more time even if DNS not found
    rdap_data, rdap_status = await get_rdap_data(domain)
    if rdap_data is None and rdap_status is None:
        result = f"""
Domain: {domain}
Status: Unknown
Note: Could not determine availability due to RDAP lookup failure
"""
        summary = "------------------------------------\nSummary:\n\nFound 0 Available domains."
        return result + "\n" + summary
    if rdap_status == 200 and rdap_data:
        # Process RDAP data even when DNS check failed
        registrar = "Unknown"
        entities = rdap_data.get("entities", [])
        for entity in entities:
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    for entry in vcard[1]:
                        if entry[0] in ["fn", "org"] and len(entry) > 3:
                            registrar = entry[3]
                            break

        result = f"""
Domain: {domain}
Status: Registered
Registrar: {registrar}
Note: Domain found in RDAP registry
"""
        summary = "------------------------------------\nSummary:\n\nFound 0 Available domains."
        return result + "\n" + summary
    elif rdap_status == 404:
        result = f"""
Domain: {domain}
Status: Available
Note: No RDAP data found (404 Not Found)
"""
        summary = f"------------------------------------\nSummary:\n\nFound 1 Available domain:\n- {domain}"
        return result + "\n" + summary

    # If we get here, the domain is likely not available
    result = f"""
Domain: {domain}
Status: Registered
Note: No DNS records or RDAP data found, but not a 404 response
"""
    summary = (
        "------------------------------------\nSummary:\n\nFound 0 Available domains."
    )
    return result + "\n" + summary


async def check_keyword_tool(keyword, tlds=None):
    """Check a keyword across top TLDs (parallelized, with concurrency limit)"""
    logger.info(f"Checking keyword: {keyword} across TLDs {tlds}")
    tlds_to_check = tlds if tlds else TOP_TLDS
    domains = [f"{keyword}.{tld}" for tld in tlds_to_check]
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)

    async def sem_checked(domain):
        async with semaphore:
            return await check_single_domain_availability(domain)

    results = await asyncio.gather(*(sem_checked(domain) for domain in domains))
    available = [
        domain for (status, domain) in results if status == DomainStatus.AVAILABLE
    ]
    unknown = [domain for (status, domain) in results if status == DomainStatus.UNKNOWN]
    unavailable = [
        domain
        for (status, domain) in results
        if status not in (DomainStatus.AVAILABLE, DomainStatus.UNKNOWN)
    ]

    response = "Unavailable domains:\n"
    for domain in unavailable:
        response += f"- {domain}\n"
    response += "\nUnknown domains:\n"
    for domain in unknown:
        response += f"- {domain}\n"
    response += "\nAvailable domains:\n"
    for domain in available:
        response += f"- {domain}\n"
    response += "\n------------------------------------\nSummary:\n\n"
    response += f"Found {len(available)} Available domains, {len(unavailable)} Unavailable domains, {len(unknown)} Unknown domains."
    return response


async def check_keywords_batch_tool(keywords, tlds=None):
    logger.info(f"Checking {len(keywords)} keywords across TLDs {tlds}")
    if not keywords:
        return "No keywords provided to check."
    tlds_to_check = tlds if tlds else TOP_TLDS
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    # Build all (keyword, domain) pairs
    keyword_domain_pairs = []
    for keyword in keywords:
        if not keyword:
            continue
        for tld in tlds_to_check:
            domain = f"{keyword}.{tld}"
            keyword_domain_pairs.append((keyword, domain))

    async def sem_checked(domain):
        async with semaphore:
            return await check_single_domain_availability(domain)

    results = await asyncio.gather(
        *(sem_checked(domain) for _, domain in keyword_domain_pairs)
    )
    all_domains = [domain for _, domain in keyword_domain_pairs]
    available = [
        domain for (status, domain) in results if status == DomainStatus.AVAILABLE
    ]
    unknown = [domain for (status, domain) in results if status == DomainStatus.UNKNOWN]
    unavailable = [
        domain
        for (status, domain) in results
        if status not in (DomainStatus.AVAILABLE, DomainStatus.UNKNOWN)
    ]

    response = "Unavailable domains:\n"
    for domain in unavailable:
        response += f"- {domain}\n"
    response += "\nUnknown domains:\n"
    for domain in unknown:
        response += f"- {domain}\n"
    response += "\nAvailable domains:\n"
    for domain in available:
        response += f"- {domain}\n"
    response += "\n------------------------------------\nSummary:\n\n"
    response += f"Found {len(available)} Available domains, {len(unavailable)} Unavailable domains, {len(unknown)} Unknown domains."
    return response


# Register tools using the older non-decorator syntax
@app.list_tools()
async def list_tools():
    return [
        types.Tool(
            name="check_domain",
            description="Check if a domain is available for registration",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain name to check (example: example.com)",
                    },
                },
                "required": ["domain"],
            },
        ),
        types.Tool(
            name="check_keyword",
            description="Check a keyword across TLDs",
            inputSchema={
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Keyword to check across TLDs",
                    },
                    "tlds": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional list of TLDs to check. Defaults to com, net, org, io, co, app, dev, ai, me, info, xyz, online, site, tech",
                    },
                },
                "required": ["keyword"],
            },
        ),
        types.Tool(
            name="check_keywords_batch",
            description="Check multiple keywords across top TLDs",
            inputSchema={
                "type": "object",
                "properties": {
                    "keywords": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of keywords to check across TLDs)",
                    },
                    "tlds": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional list of TLDs to check. Defaults to com, net, org, io, co, app, dev, ai, me, info, xyz, online, site, tech",
                    },
                },
                "required": ["keywords"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name, arguments):
    if name == "check_domain":
        domain = arguments.get("domain")
        result = await check_domain_tool(domain)
        return [types.TextContent(type="text", text=result)]
    elif name == "check_keyword":
        keyword = arguments.get("keyword")
        tlds = arguments.get("tlds")
        result = await check_keyword_tool(keyword, tlds)
        return [types.TextContent(type="text", text=result)]
    elif name == "check_keywords_batch":
        keywords = arguments.get("keywords")
        tlds = arguments.get("tlds")
        result = await check_keywords_batch_tool(keywords, tlds)
        return [types.TextContent(type="text", text=result)]
    else:
        return [types.TextContent(type="text", text=f"Unknown tool: {name}")]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Domain Checker MCP Server and CLI")
    subparsers = parser.add_subparsers(dest="command", help="Tool to run")

    # check_domain
    parser_domain = subparsers.add_parser(
        "check_domain", help="Check if a domain is available for registration"
    )
    parser_domain.add_argument(
        "--domain", required=True, help="Domain name to check (example: example.com)"
    )
    parser_domain.add_argument(
        "--tlds", nargs="*", help="Optional list of TLDs to check (example: com ai)"
    )

    # check_keyword
    parser_keyword = subparsers.add_parser(
        "check_keyword", help="Check a keyword across TLDs"
    )
    parser_keyword.add_argument(
        "--keyword",
        required=True,
        help="Keyword to check across TLDs (example: example)",
    )
    parser_keyword.add_argument(
        "--tlds", nargs="*", help="Optional list of TLDs to check (example: com ai)"
    )

    # check_keywords_batch
    parser_batch = subparsers.add_parser(
        "check_keywords_batch", help="Check multiple keywords across top TLDs"
    )
    parser_batch.add_argument(
        "--keywords",
        nargs="+",
        required=True,
        help="List of keywords to check across TLDs (example: example1 example2)",
    )
    parser_batch.add_argument(
        "--tlds", nargs="*", help="Optional list of TLDs to check (example: com ai)"
    )

    args = parser.parse_args()

    import httpx
    import asyncio

    async def cli_main():
        global client
        async with httpx.AsyncClient() as c:
            client = c
            if args.command == "check_domain":
                result = await check_domain_tool(args.domain)
                print(result)
            elif args.command == "check_keyword":
                tlds = args.tlds if args.tlds else None
                result = await check_keyword_tool(args.keyword, tlds)
                print(result)
            elif args.command == "check_keywords_batch":
                tlds = args.tlds if args.tlds else None
                # Support comma-separated or space-separated keywords
                if len(args.keywords) == 1 and "," in args.keywords[0]:
                    keywords = [
                        k.strip() for k in args.keywords[0].split(",") if k.strip()
                    ]
                else:
                    keywords = args.keywords
                result = await check_keywords_batch_tool(keywords, tlds)
                print(result)
            else:
                # No command provided, run as MCP server
                from mcp.server.stdio import stdio_server

                async with stdio_server() as streams:
                    await app.run(
                        streams[0], streams[1], app.create_initialization_options()
                    )

    if len(sys.argv) > 1:
        asyncio.run(cli_main())
    else:
        from mcp.server.stdio import stdio_server

        async def main():
            logger.info("Starting Domain Checker MCP Server")
            global client
            async with httpx.AsyncClient() as c:
                client = c
                async with stdio_server() as streams:
                    await app.run(
                        streams[0], streams[1], app.create_initialization_options()
                    )

        asyncio.run(main())
