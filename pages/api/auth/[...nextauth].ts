import NextAuth, { User } from "next-auth";
import { JWT } from "next-auth/jwt";
import SpotifyProvider from "next-auth/providers/spotify";

interface JTWEx extends JWT {
  accessToken: string;
  refreshToken: string;
  accessTokenExpires: number;
  user: User;
  error: any;
}

interface ISpotifyTokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
}

/**
 * Takes a token, and returns a new token with updated
 * `accessToken` and `accessTokenExpires`. If an error occurs,
 * returns the old token and an error property
 */
async function refreshAccessToken(token: JTWEx) {
  try {
    const url = "https://accounts.spotify.com/api/token?" +
      new URLSearchParams({
        client_id: process.env.SPOTIFY_CLIENT_ID,
        client_secret: process.env.SPOTIFY_CLIENT_SECRET,
        grant_type: "refresh_token",
        refresh_token: token.refreshToken,
      });

    const response = await fetch(url, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      method: "POST",
    });

    const refreshedTokens: ISpotifyTokenResponse = await response.json();

    if (!response.ok) {
      throw refreshedTokens;
    }

    return {
      ...token,
      accessToken: refreshedTokens.access_token,
      accessTokenExpires: Date.now() + refreshedTokens.expires_in * 1000,
      refreshToken: refreshedTokens.refresh_token ?? token.refreshToken, // Fall back to old refresh token
    };
  } catch (error) {
    console.log(error);

    return {
      ...token,
      error: "RefreshAccessTokenError",
    };
  }
}

export default NextAuth({
  providers: [
    SpotifyProvider({
      clientId: process.env.SPOTIFY_CLIENT_ID,
      clientSecret: process.env.SPOTIFY_CLIENT_SECRET,
      authorization:
        "https://accounts.spotify.com/authorize?scope=user-read-email,playlist-read-private,user-read-email,streaming,user-read-private,user-library-read,user-library-modify,user-read-playback-state,user-modify-playback-state,user-read-recently-played,user-follow-read",
    }),
  ],

  callbacks: {
    async jwt(responseData) {
      let { token, account, user } = responseData;
      const realToken = token as JTWEx;
      const realAccount = account as ISpotifyTokenResponse;
 
      // Initial sign in
      if (realAccount && user) {
        return {
          accessToken: realAccount.access_token,
          accessTokenExpires: Date.now() + realAccount.expires_in * 1000,
          refreshToken: realAccount.refresh_token,
          user,
        };
      }

      // Return previous token if the access token has not expired yet
      if (Date.now() < realToken.accessTokenExpires) {
        return realToken;
      }

      // Access token has expired, try to update it
      return refreshAccessToken(realToken);
    },

    async session(responseData) {
      let { session, token } = responseData;
      const realToken = token as JTWEx; 

      session.user = realToken.user;
      session.accessToken = realToken.accessToken;
      session.error = realToken.error;

      return session;
    },
  },
});
