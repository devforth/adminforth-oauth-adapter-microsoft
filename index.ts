import type { OAuth2Adapter, OAuth2UserInfo } from "adminforth";
import { createRemoteJWKSet, jwtVerify } from "jose";


const microsoftJWKS = createRemoteJWKSet(new URL("https://login.microsoftonline.com/common/discovery/v2.0/keys"));

function isValidMicrosoftIssuer(payload: Record<string, unknown>) {
  return typeof payload.iss === 'string'
    && typeof payload.tid === 'string'
    && payload.iss === `https://login.microsoftonline.com/${payload.tid}/v2.0`;
}

export default class AdminForthAdapterMicrosoftOauth2 implements OAuth2Adapter {
    private clientID: string;
    private clientSecret: string;
    private useOpenIdConnect: boolean;

    constructor(options: {
      clientID: string;
      clientSecret: string;
      useOpenID?: boolean;
      useOpenIdConnect?: boolean;
    }) {
      if (options.useOpenID !== undefined ) {
        console.error("AdminForthAdapterMicrosoftOauth2: 'useOpenID' is deprecated, please use 'useOpenIdConnect' instead");
      }
      this.clientID = options.clientID;
      this.clientSecret = options.clientSecret;
      this.useOpenIdConnect = (!!options.useOpenIdConnect || !!options.useOpenID) ?? true;
    }
  
    getAuthUrl(): string {
      const params = new URLSearchParams({
        client_id: this.clientID,
        response_type: 'code',
        scope: 'openid email profile https://graph.microsoft.com/user.read',
        response_mode: 'query',
        redirect_uri: 'http://localhost:3000/oauth/callback',
      });
      return `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?${params.toString()}`;
    }
  
    async getTokenFromCode(code: string, redirect_uri: string): Promise<OAuth2UserInfo> {
      const tokenResponse = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: this.clientID,
          client_secret: this.clientSecret,
          redirect_uri,
          grant_type: 'authorization_code',
        }),
      });
  
      const tokenData = await tokenResponse.json();
      
      if (tokenData.error) {
        console.error('Token error:', tokenData);
        throw new Error(tokenData.error_description || tokenData.error);
      }

      if (this.useOpenIdConnect && tokenData.id_token) {
        try {
          const { payload } = await jwtVerify(tokenData.id_token, microsoftJWKS, {
            audience: this.clientID,
            algorithms: ["RS256"],
          });

          if (!isValidMicrosoftIssuer(payload)) {
            throw new Error(`Microsoft OAuth id_token has invalid issuer "${payload.iss}"`);
          }

          const email = typeof payload.email === 'string' ? payload.email : undefined;
          if (email) {
            return {
              provider: this.constructor.name,
              subject: typeof payload.oid === 'string' ? payload.oid : payload.sub,
              email,
              fullName: typeof payload.name === 'string' ? payload.name : undefined,
              profilePictureUrl: typeof payload.picture === 'string' ? payload.picture : undefined,
            };
          }
        } catch (error) {
          console.error("Error verifying token:", error);
          throw error;
        }
      }
  
      const userResponse = await fetch('https://graph.microsoft.com/v1.0/me', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });
      
      const userData = await userResponse.json();
  
      if (userData.error) {
        throw new Error(userData.error.message || 'Failed to fetch user data');
      }
  
      return {
        provider: this.constructor.name,
        subject: userData.id,
        email: userData.mail || userData.userPrincipalName,
        fullName: userData.displayName,
        profilePictureUrl: typeof userData.picture === 'string' ? userData.picture : undefined
      };
    }

    getName(): string {
      return 'Microsoft';
    }

    getIcon(): string {
      return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 21 21" fill="none">
<path d="M0 0H10V10H0V0Z" fill="#F35325"/>
<path d="M11 0H21V10H11V0Z" fill="#81BC06"/>
<path d="M0 11H10V21H0V11Z" fill="#05A6F0"/>
<path d="M11 11H21V21H11V11Z" fill="#FFBA08"/>
</svg>`;
    }
}
