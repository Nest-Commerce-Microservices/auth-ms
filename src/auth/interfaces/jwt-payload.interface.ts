export interface JwtPayload {
  id: string;
  email: string;
  name: string;
}

export type Registered = { sub?: string; iat?: number; exp?: number };
