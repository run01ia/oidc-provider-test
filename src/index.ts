
import * as oidc from "oidc-provider";

const issuer = "http://localhost:3000";

const configuration: oidc.Configuration = {
  clients: [
    {
      client_id: "test-client",
      client_secret: "test-secret",
      redirect_uris: [
        "http://localhost:8080/callback",
      ],
      response_types: ["code"],
      grant_types: ["authorization_code"],
    },
  ],
};

const provider = new oidc.Provider(
  issuer,
  configuration,
);

provider.listen(3000, () => {
  console.log(`OIDC Provider listening at ${issuer}`);
});

