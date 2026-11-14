/**
 * System authorization roles
 */
export type UserRole = "admin" | "user";

/**
 * Auth user profile and session representation
 */
export interface AuthUser {
  id: string;
  clerk_id: string;
  email?: string | null;
  first_name?: string | null;
  last_name?: string | null;
  image_url?: string | null;
  role: UserRole;
  roles?: string[];
  is_active?: boolean;
  is_authenticated?: boolean;
  created_at?: string | null;
  updated_at?: string | null;
}

/**
 * Request payload to change a user's role
 */
export interface UpdateUserRoleRequest {
  role: UserRole;
}
