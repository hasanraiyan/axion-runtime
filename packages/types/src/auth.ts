/**
 * Auth user profile and session representation
 */
export interface AuthUser {
  id: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  imageUrl?: string;
  roles?: string[];
}
