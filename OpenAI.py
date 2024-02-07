import sys
import asyncio
import aiohttp

class APIKey:
    def __init__(self, api_key):
        self.api_key = api_key
        self.model = None
        self.organizations = []
        self.default_org = None
        self.has_quota = True
        self.rpm = None
        self.tier = None
        self.trial = False

oai_api_url = "https://api.openai.com/v1"
oai_t1_rpm_limits = {"gpt-3.5-turbo": 3500, "gpt-4": 500, "gpt-4-32k": 20}
oai_tiers = {40000: 'Free', 60000: 'Tier1', 80000: 'Tier2', 160000: 'Tier3', 1000000: 'Tier4', 2000000: 'Tier5'}

async def get_oai_model(key: APIKey, session):
    async with session.get(f'{oai_api_url}/models', headers={'Authorization': f'Bearer {key.api_key}'}) as response:
        if response.status != 200:
            return
        else:
            data = await response.json()
            models = data["data"]
            top_model = "gpt-3.5-turbo"
            for model in models:
                if model["id"] == "gpt-4-32k":
                    top_model = model["id"]
                    break
                elif model["id"] == "gpt-4":
                    top_model = model["id"]
            key.model = top_model
            return True

async def get_oai_key_attribs(key: APIKey, session):
    chat_object = {"model": f'{key.model}', "messages": [{"role": "user", "content": ""}], "max_tokens": 0}
    async with session.post(f'{oai_api_url}/chat/completions',
                            headers={'Authorization': f'Bearer {key.api_key}', 'accept': 'application/json'},
                            json=chat_object) as response:
        if response.status in [400, 429]:
            data = await response.json()
            message = data["error"]["type"]
            if message is None:
                return
            match message:
                case "access_terminated":
                    return
                case "billing_not_active":
                    return
                case "insufficient_quota":
                    key.has_quota = False
                case "invalid_request_error":
                    key.has_quota = True
                    key.rpm = int(response.headers.get("x-ratelimit-limit-requests")) if response.headers.get("x-ratelimit-limit-requests") else None
                    if key.rpm and key.rpm < oai_t1_rpm_limits[key.model]:  # Add a check for key.rpm before comparison
                        key.trial = True
                    key.tier = await get_oai_key_tier(key, session)
        else:
            return
        return True


async def get_oai_key_tier(key: APIKey, session):
    if key.trial:
        return 'Free'
    chat_object = {"model": f'gpt-3.5-turbo', "messages": [{"role": "user", "content": ""}], "max_tokens": 0}
    for _ in range(3):
        async with session.post(f'{oai_api_url}/chat/completions',
                                headers={'Authorization': f'Bearer {key.api_key}', 'accept': 'application/json'},
                                json=chat_object) as response:
            if response.status in [400, 429]:
                try:
                    return oai_tiers[int(response.headers.get("x-ratelimit-limit-tokens"))]
                except (KeyError, TypeError, ValueError):
                    continue
            else:
                return
    return

async def get_oai_org(key: APIKey, session):
    async with session.get(f'{oai_api_url}/organizations', headers={'Authorization': f'Bearer {key.api_key}'}) as response:
        if response.status != 200:
            return

        data = await response.json()
        orgs = data["data"]

        for org in orgs:
            if not org["personal"]:
                if org["is_default"]:
                    key.default_org = org["name"]
                key.organizations.append(org["name"])
        return True

def check_manual_increase(key: APIKey):
    if key.model == 'gpt-3.5-turbo' and key.rpm is not None and key.rpm > 3500:
        return True
    elif key.tier == 'Tier1' and key.model != 'gpt-3.5-turbo' and key.rpm is not None and key.rpm > 500:
        return True
    elif key.tier in ['Tier2', 'Tier3'] and key.rpm is not None and key.rpm > 5000:
        return True
    elif key.tier in ['Tier3', 'Tier4'] and key.rpm is not None and key.rpm > 10000:
        return True
    return False


def pretty_print_oai_keys(keys):
    print('-' * 90)
    org_count = 0
    quota_count = 0
    no_quota_count = 0
    t5_count = 0

    key_groups = {
        "gpt-3.5-turbo": {
            "has_quota": [],
            "no_quota": []
        },
        "gpt-4": {
            "has_quota": [],
            "no_quota": []
        },
        "gpt-4-32k": {
            "has_quota": [],
            "no_quota": []
        }
    }

    for key in keys:
        if key.organizations:
            org_count += 1
        if key.tier == 'Tier5':
            t5_count += 1
        if key.has_quota:
            key_groups[key.model]['has_quota'].append(key)
            quota_count += 1
        else:
            key_groups[key.model]['no_quota'].append(key)
            no_quota_count += 1

    print(f'Validated {len(key_groups["gpt-3.5-turbo"]["has_quota"])} Turbo keys with quota:')
    for key in key_groups["gpt-3.5-turbo"]["has_quota"]:
        print(f"{key.api_key}"
              + (f" | default org - {key.default_org}" if key.default_org else "")
              + (f" | other orgs - {key.organizations}" if len(key.organizations) > 1 else "")
              + f" | {key.rpm} RPM" + (f" - {key.tier}" if key.tier else "")
              + (" (RPM increased via request)" if check_manual_increase(key) else "")
              + (f" | TRIAL KEY" if key.trial else ""))

    print(f'\nValidated {len(key_groups["gpt-3.5-turbo"]["no_quota"])} Turbo keys with no quota:')
    for key in key_groups["gpt-3.5-turbo"]["no_quota"]:
        print(f"{key.api_key}"
              + (f" | default org - {key.default_org}" if key.default_org else "")
              + (f" | other orgs - {key.organizations}" if len(key.organizations) > 1 else ""))

    print(f'\nValidated {len(key_groups["gpt-4"]["has_quota"])} gpt-4 keys with quota:')
    for key in key_groups["gpt-4"]["has_quota"]:
        print(f"{key.api_key}"
              + (f" | default org - {key.default_org}" if key.default_org else "")
              + (f" | other orgs - {key.organizations}" if len(key.organizations) > 1 else "")
              + f" | {key.rpm} RPM" + (f" - {key.tier}" if key.tier else "")
              + (" (RPM increased via request)" if check_manual_increase(key) else "")
              + (f" | TRIAL KEY" if key.trial else ""))

    print(f'\nValidated {len(key_groups["gpt-4"]["no_quota"])} gpt-4 keys with no quota:')
    for key in key_groups["gpt-4"]["no_quota"]:
        print(f"{key.api_key}"
              + (f" | default org - {key.default_org}" if key.default_org else "")
              + (f" | other orgs - {key.organizations}" if len(key.organizations) > 1 else ""))

    print(f'\nValidated {len(key_groups["gpt-4-32k"]["has_quota"])} gpt-4-32k keys with quota:')
    for key in key_groups["gpt-4-32k"]["has_quota"]:
        print(f"{key.api_key}"
              + (f" | default org - {key.default_org}" if key.default_org else "")
              + (f" | other orgs - {key.organizations}" if len(key.organizations) > 1 else "")
              + f" | {key.rpm} RPM" + (f" - {key.tier}" if key.tier else "")
              + (" (RPM increased via request)" if check_manual_increase(key) else "")
              + (f" | TRIAL KEY" if key.trial else ""))

    print(f'\nValidated {len(key_groups["gpt-4-32k"]["no_quota"])} gpt-4-32k keys with no quota:')
    for key in key_groups["gpt-4-32k"]["no_quota"]:
        print(f"{key.api_key}"
              + (f" | default org - {key.default_org}" if key.default_org else "")
              + (f" | other orgs - {key.organizations}" if len(key.organizations) > 1 else ""))

    print(f'\n--- Total Valid OpenAI Keys: {len(keys)} ({quota_count} in quota, {no_quota_count} no quota, {org_count} orgs, {t5_count} Tier5) ---\n')

async def main():  # Declare main as an asynchronous function
    if len(sys.argv) != 3 or sys.argv[1] != "-file":
        print("Usage: python example.py -file <filename>")
        sys.exit(1)

    filename = sys.argv[2]
    try:
        with open(filename, "r") as file:
            api_keys = [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        print("File not found.")
        sys.exit(1)

    keys = []
    session = aiohttp.ClientSession()  # Assuming you are using aiohttp for async http requests
    for api_key in api_keys:
        key = APIKey(api_key)  # Instantiate APIKey objects
        if await get_oai_model(key, session):  # Assuming get_oai_model is the function to check OpenAI key
            keys.append(key)

    pretty_print_oai_keys(keys)
    await session.close()  # Don't forget to close the session when you're done

if __name__ == "__main__":
    asyncio.run(main())
