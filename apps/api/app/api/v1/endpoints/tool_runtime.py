"""Runtime endpoints (SRS-07 Section 9.4): resolve a toolset, invoke a tool, issue call approvals."""
from fastapi import APIRouter, Path, status

from app.api.v1.endpoints.tools_deps import AdminCaller, InvokeCaller, ToolsetCaller, ToolsDep
from app.core.tools.types import InvocationRequest
from app.models.project import ProjectRole
from app.schemas.common import ApiErrorResponse, ApiResponse
from app.schemas.tools import (
    ApprovalIssueRequest,
    ApprovalIssueResponse,
    AuthRequiredEntry,
    ContentBlockResponse,
    InvokeRequest,
    InvokeResponse,
    ModelVisibleTool,
    ToolsetExclusion,
    ToolsetRequest,
    ToolsetResponse,
)
from app.models.tool import ApprovalPolicy

router = APIRouter()


def to_invoke_response(result) -> InvokeResponse:
    return InvokeResponse(
        status=result.status,
        is_error=result.is_error,
        content=[ContentBlockResponse(type=b.type, text=b.text, data=b.data, mime_type=b.mime_type) for b in result.content],
        structured_content=result.structured_content,
        error_code=result.error_code,
        message=result.message,
        retryable=result.retryable,
        model_correctable=result.model_correctable,
        latency_ms=result.latency_ms,
        invocation_id=result.invocation_id,
        ui=result.ui,
        extra=result.extra,
    )

PID = Path(..., description="Project id or slug")
ERRORS = {
    status.HTTP_401_UNAUTHORIZED: {"model": ApiErrorResponse},
    status.HTTP_403_FORBIDDEN: {"model": ApiErrorResponse},
    status.HTTP_404_NOT_FOUND: {"model": ApiErrorResponse},
}


@router.post(
    "/runtime/toolset",
    response_model=ApiResponse[ToolsetResponse],
    operation_id="resolve_toolset",
    summary="Resolve the tools available to the caller (and optionally an end user)",
    responses=ERRORS,
)
async def resolve_toolset(body: ToolsetRequest, project_id: str = PID, caller: ToolsetCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    principal = await tools.principals.resolve(
        caller.actor,
        caller.project,
        caller.role,
        end_user_external_id=body.end_user_external_id,
        agent_id=body.agent_id,
        request_id=caller.request_id,
        min_member_role=ProjectRole.VIEWER,
    )
    toolset = await tools.toolset.resolve_toolset(principal)
    return ApiResponse(
        data=ToolsetResponse(
            toolset_version=toolset.version,
            tools=[
                ModelVisibleTool(
                    tool_key=t.tool_key,
                    description=t.description,
                    input_schema=t.visible_schema,
                    annotations=dict(t.annotations),
                    approval_policy=ApprovalPolicy(t.approval_policy),
                    ui=t.ui,
                )
                for t in toolset.tools
            ],
            excluded=[ToolsetExclusion(tool_key=e.tool_key, integration=e.integration, reason=e.reason) for e in toolset.excluded],
            auth_required=[
                AuthRequiredEntry(
                    integration_id=a.integration_id, integration=a.integration, reason=a.reason, connect_available=a.connect_available
                )
                for a in toolset.auth_required
            ],
        )
    )


@router.post(
    "/runtime/invoke",
    response_model=ApiResponse[InvokeResponse],
    operation_id="invoke_tool",
    summary="Invoke a tool through the execution gateway",
    description="Always returns HTTP 200 with the uniform result envelope; inspect `status` and `is_error`.",
    responses=ERRORS,
)
async def invoke_tool(body: InvokeRequest, project_id: str = PID, caller: InvokeCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    principal = await tools.principals.resolve(
        caller.actor,
        caller.project,
        caller.role,
        end_user_external_id=body.end_user_external_id,
        agent_id=body.agent_id,
        run_id=body.run_id,
        request_id=caller.request_id,
        min_member_role=ProjectRole.MEMBER,
    )
    result = await tools.gateway.invoke(
        InvocationRequest(
            project_id=str(caller.project.id),
            tool_key=body.tool_key,
            arguments=body.arguments,
            principal=principal,
            idempotency_key=body.idempotency_key,
            timeout_override_seconds=body.timeout_seconds,
            dry_run=body.dry_run,
            approval_token=body.approval_token,
        )
    )
    return ApiResponse(data=to_invoke_response(result), message="Tool invocation processed")


@router.post(
    "/runtime/approvals",
    response_model=ApiResponse[ApprovalIssueResponse],
    operation_id="issue_tool_call_approval",
    summary="Approve one exact tool call",
    description="Issues a short-lived token bound to the tool, the exact arguments, and the subject.",
    responses=ERRORS,
)
async def issue_approval(body: ApprovalIssueRequest, project_id: str = PID, caller: AdminCaller = None, tools: ToolsDep = None):  # type: ignore[assignment]
    token = await tools.approvals.issue(
        caller.project,
        body.tool_key,
        body.arguments,
        end_user_external_id=body.end_user_external_id,
        member_id=body.member_id,
        ttl_seconds=body.ttl_seconds,
        actor_id=caller.actor_id,
    )
    return ApiResponse(data=ApprovalIssueResponse(approval_token=token, expires_in=body.ttl_seconds))
