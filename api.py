from fastapi import FastAPI
from schemas.policy import Policy
from translator import (
    translate_to_aws,
    translate_to_azure,
    translate_to_pfsense
)

app = FastAPI(title="Cloud Connector")


@app.get("/")
def home():
    return {"message": "Cloud Connector is running"}


@app.post("/deploy/{provider}")
def deploy(provider: str, policy: Policy):

    if provider.lower() == "aws":
        translated_policy = translate_to_aws(policy)

    elif provider.lower() == "azure":
        translated_policy = translate_to_azure(policy)

    elif provider.lower() == "pfsense":
        translated_policy = translate_to_pfsense(policy)

    else:
        return {
            "status": "error",
            "message": "Unsupported provider"
        }

    return {
        "status": "success",
        "provider": provider,
        "translated_policy": translated_policy
    }