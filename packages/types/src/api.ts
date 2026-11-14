/**
 * Standard API error detail structure
 */
export interface ApiErrorDetail {
  field?: string;
  message: string;
  code?: string;
}

/**
 * Standard API error payload
 */
export interface ApiError {
  code: string;
  message: string;
  details?: ApiErrorDetail[];
}

/**
 * Standard API successful envelope
 */
export interface ApiResponse<T = unknown> {
  success: true;
  data: T;
  message: string;
}

/**
 * Standard API error envelope
 */
export interface ApiErrorResponse {
  success: false;
  error: ApiError;
}

/**
 * Combined API result envelope
 */
export type ApiResult<T> = ApiResponse<T> | ApiErrorResponse;

/**
 * Pagination metadata format
 */
export interface PaginationMeta {
  page: number;
  pageSize: number;
  totalRecords: number;
  totalPages: number;
  hasNextPage: boolean;
  hasPreviousPage: boolean;
}

/**
 * Standard Paginated Response
 */
export interface PaginatedData<T> {
  items: T[];
  pagination: PaginationMeta;
}

export type PaginatedResponse<T> = ApiResponse<PaginatedData<T>>;
