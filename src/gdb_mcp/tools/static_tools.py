"""3.5 static bridge: Ghidra headless analysis tools.

Revived from the archived reverse-tools work with the dashboard/live
components stripped: everything here operates on the SHA-256-addressed
analysis cache produced by the Ghidra headless exporter
(``src/gdb_mcp/reverse/`` + ``ghidra_scripts/ExportAnalysis.java``).
"""

from __future__ import annotations

import asyncio

from mcp.server.fastmcp import Context

from ._common import analysis_from


def register(app, registry, config) -> None:
    @app.tool()
    async def analyze_binary(
        path: str,
        force: bool = False,
        language_id: str | None = None,
        distro: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Queue a binary for Ghidra Headless analysis. Results are
        cached by SHA-256; force refreshes in the background while old
        results remain readable. Requires analyzeHeadless
        (GDB_MCP_GHIDRA_HEADLESS)."""
        record = await analysis_from(ctx).queue_analysis(
            path, distro=distro, force=force, language_id=language_id
        )
        return record.public()

    @app.tool()
    def list_analyses(ctx: Context) -> dict:
        """List cached and in-progress binary analyses, newest first."""
        return {"analyses": analysis_from(ctx).list_analyses()}

    @app.tool()
    def get_analysis_status(analysis_id: str, ctx: Context) -> dict:
        """Return lifecycle, counts, partial-result state, and errors
        for an analysis."""
        return analysis_from(ctx).get_record(analysis_id).public()

    @app.tool()
    async def get_binary_overview(analysis_id: str, ctx: Context) -> dict:
        """Return format, architecture, image base, entry points, and
        result counts."""
        return await asyncio.to_thread(analysis_from(ctx).overview, analysis_id)

    @app.tool()
    async def list_sections(
        analysis_id: str,
        query: str | None = None,
        offset: int = 0,
        limit: int = 100,
        ctx: Context = None,
    ) -> dict:
        """List binary sections with permissions and address ranges."""
        return await asyncio.to_thread(
            analysis_from(ctx).list_items,
            analysis_id,
            "sections",
            query,
            offset,
            limit,
        )

    @app.tool()
    async def list_symbols(
        analysis_id: str,
        query: str | None = None,
        offset: int = 0,
        limit: int = 100,
        ctx: Context = None,
    ) -> dict:
        """List symbols discovered by Ghidra; optionally filter their
        fields."""
        return await asyncio.to_thread(
            analysis_from(ctx).list_items,
            analysis_id,
            "symbols",
            query,
            offset,
            limit,
        )

    @app.tool()
    async def list_functions(
        analysis_id: str,
        query: str | None = None,
        offset: int = 0,
        limit: int = 100,
        ctx: Context = None,
    ) -> dict:
        """List discovered functions and decompilation status."""
        return await asyncio.to_thread(
            analysis_from(ctx).list_items,
            analysis_id,
            "functions",
            query,
            offset,
            limit,
        )

    @app.tool()
    async def decompile_function(
        analysis_id: str,
        function: str | int,
        ctx: Context = None,
    ) -> dict:
        """Return pseudocode, line address ranges, assembly, call
        relations, and annotations for one function."""
        return await asyncio.to_thread(
            analysis_from(ctx).decompile, analysis_id, function
        )

    @app.tool()
    async def get_static_disassembly(
        analysis_id: str,
        address: str | int,
        count: int = 32,
        ctx: Context = None,
    ) -> dict:
        """Return Ghidra instructions beginning at a link-time address
        or function."""
        return await asyncio.to_thread(
            analysis_from(ctx).static_disassembly, analysis_id, address, count
        )

    @app.tool()
    async def list_strings(
        analysis_id: str,
        query: str | None = None,
        offset: int = 0,
        limit: int = 100,
        ctx: Context = None,
    ) -> dict:
        """List strings identified by Ghidra, with address and byte
        length."""
        return await asyncio.to_thread(
            analysis_from(ctx).list_items,
            analysis_id,
            "strings",
            query,
            offset,
            limit,
        )

    @app.tool()
    async def get_xrefs(
        analysis_id: str,
        address: str | int,
        direction: str = "both",
        ctx: Context = None,
    ) -> dict:
        """Return references to and/or from the function containing an
        address."""
        return await asyncio.to_thread(
            analysis_from(ctx).xrefs, analysis_id, address, direction
        )

    @app.tool()
    async def get_call_graph(
        analysis_id: str,
        function: str | int,
        direction: str = "both",
        depth: int = 2,
        ctx: Context = None,
    ) -> dict:
        """Return a bounded caller/callee graph rooted at a function."""
        return await asyncio.to_thread(
            analysis_from(ctx).call_graph, analysis_id, function, direction, depth
        )

    @app.tool()
    async def search_decompiled_code(
        analysis_id: str,
        query: str,
        regex: bool = False,
        limit: int = 100,
        ctx: Context = None,
    ) -> dict:
        """Search decompiled pseudocode, returning up to 200 matching
        lines."""
        return await asyncio.to_thread(
            analysis_from(ctx).search_code, analysis_id, query, regex, limit
        )

    @app.tool()
    async def annotate_code(
        analysis_id: str,
        address: str | int,
        label: str | None = None,
        comment: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Persist a display-only label/comment for a static address."""
        return await asyncio.to_thread(
            analysis_from(ctx).annotate, analysis_id, address, label, comment
        )

    @app.tool()
    async def remove_code_annotation(
        analysis_id: str,
        address: str | int,
        ctx: Context = None,
    ) -> dict:
        """Remove a display-only annotation without changing the binary
        or the Ghidra project."""
        return await asyncio.to_thread(
            analysis_from(ctx).remove_annotation, analysis_id, address
        )
