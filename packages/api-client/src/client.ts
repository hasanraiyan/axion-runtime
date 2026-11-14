import type { ApiResponse, AuthUser } from "@platform/types";

export interface ApiClientConfig {
  baseUrl?: string;
  getToken?: () => Promise<string | null> | string | null;
  headers?: Record<string, string>;
}

export class ApiClientError extends Error {
  public status: number;
  public code: string;
  public details?: unknown[];

  constructor(status: number, code: string, message: string, details?: unknown[]) {
    super(message);
    this.name = "ApiClientError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export class ApiClient {
  private baseUrl: string;
  private getToken?: () => Promise<string | null> | string | null;
  private customHeaders: Record<string, string>;

  constructor(config: ApiClientConfig = {}) {
    this.baseUrl = (config.baseUrl || "http://localhost:8000").replace(/\/$/, "");
    this.getToken = config.getToken;
    this.customHeaders = config.headers || {};
  }

  public async request<T = unknown>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${path.startsWith("/") ? path : `/${path}`}`;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...this.customHeaders,
      ...((options.headers as Record<string, string>) || {}),
    };

    if (this.getToken) {
      const token = await this.getToken();
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }
    }

    const response = await fetch(url, {
      ...options,
      headers,
    });

    let payload: any;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }

    if (!response.ok) {
      const err = payload?.error || {};
      throw new ApiClientError(
        response.status,
        err.code || `HTTP_${response.status}`,
        err.message || response.statusText || "Request failed",
        err.details
      );
    }

    return payload as T;
  }

  public async get<T = unknown>(path: string, options: RequestInit = {}): Promise<T> {
    return this.request<T>(path, { ...options, method: "GET" });
  }

  public async post<T = unknown>(
    path: string,
    body?: unknown,
    options: RequestInit = {}
  ): Promise<T> {
    return this.request<T>(path, {
      ...options,
      method: "POST",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  }

  public async put<T = unknown>(
    path: string,
    body?: unknown,
    options: RequestInit = {}
  ): Promise<T> {
    return this.request<T>(path, {
      ...options,
      method: "PUT",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  }

  public async delete<T = unknown>(path: string, options: RequestInit = {}): Promise<T> {
    return this.request<T>(path, { ...options, method: "DELETE" });
  }

  public readonly health = {
    check: async (): Promise<
      ApiResponse<{ status: string; version: string; uptime_seconds: number }>
    > => {
      return this.get("/health");
    },
    v1Check: async (): Promise<
      ApiResponse<{ status: string; version: string; uptime_seconds: number }>
    > => {
      return this.get("/api/v1/health");
    },
  };

  public readonly auth = {
    me: async (): Promise<ApiResponse<AuthUser>> => {
      return this.get("/api/v1/auth/me");
    },
  };
}

export function createApiClient(config?: ApiClientConfig): ApiClient {
  return new ApiClient(config);
}
