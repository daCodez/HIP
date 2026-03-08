using HIP.Admin.Models;
using HIP.Admin.Services;
using Microsoft.AspNetCore.Mvc;

namespace HIP.Admin.Controllers;

[ApiController]
[Route("api/admin/simulator")]
public sealed class SimulatorAutomationController(SimulatorAutoHardeningService autoHardeningService) : ControllerBase
{
    [HttpGet("{runId}/recommendations")]
    public ActionResult<SimulatorRecommendationResponse> GetRecommendations(string runId)
    {
        if (string.IsNullOrWhiteSpace(runId))
        {
            return BadRequest("Run id is required.");
        }

        var response = autoHardeningService.GetRecommendations(runId);
        return Ok(response);
    }

    [HttpPost("{runId}/auto-fix-all")]
    public async Task<ActionResult<AutoFixAllApplySummary>> AutoFixAll(string runId, [FromBody] AutoFixAllRequest? request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(runId))
        {
            return BadRequest("Run id is required.");
        }

        var summary = await autoHardeningService.AutoFixAllAsync(runId, request?.IdempotencyKey, cancellationToken);
        return Ok(summary);
    }

    [HttpPost("{runId}/generate-scenarios")]
    public async Task<ActionResult<AutoFixAllApplySummary>> GenerateScenarios(string runId, [FromBody] AutoFixAllRequest? request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(runId))
        {
            return BadRequest("Run id is required.");
        }

        var summary = await autoHardeningService.GenerateScenarioDraftsAsync(runId, request?.IdempotencyKey, cancellationToken);
        return Ok(summary);
    }

    [HttpPost("{runId}/add-telemetry")]
    public async Task<ActionResult<AutoFixAllApplySummary>> AddTelemetry(string runId, [FromBody] AutoFixAllRequest? request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(runId))
        {
            return BadRequest("Run id is required.");
        }

        var summary = await autoHardeningService.AddTelemetryDraftsAsync(runId, request?.IdempotencyKey, cancellationToken);
        return Ok(summary);
    }

    [HttpPost("{runId}/auto-harden-system")]
    public Task<ActionResult<AutoFixAllApplySummary>> AutoHardenSystem(string runId, [FromBody] AutoFixAllRequest? request, CancellationToken cancellationToken)
        => AutoFixAll(runId, request, cancellationToken);
}
