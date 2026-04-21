# 04 — Standards Ingestion

How normative source documents become typed `Clause` values.

## Principles

- **Any means**: the transcriber trait is open-ended. PDF, HTML, Markdown, OCR, audio — all are acceptable sources as long as they produce a structured `TranscriptionResult`.
- **Provenance everywhere**: every byte of downstream output links back to (source file, source hash, page / block id, transcriber id, transcriber version).
- **Reproducibility**: given the same source and the same transcriber version, transcription is bit-identical. Cache artefacts keyed on source hash.
- **Hand-corrections are layered**, not mutated in-place. Patches sit beside the raw transcription; the build step applies them deterministically.
- **Stages are pluggable and composable**: transcribers can chain (PDF → text + OCR-fallback per page), slicers can stack (heading-boundary + manual-override), transformers can fall through (pattern-match → table-lift → hand-authored).

## Traits

```rust
pub trait Transcriber {
    type Source;
    fn id(&self) -> TranscriberId;
    fn version(&self) -> &'static str;
    fn transcribe(&self, src: Self::Source) -> TranscriptionResult;
}

pub trait Slicer {
    fn id(&self) -> SlicerId;
    fn slice(&self, t: &TranscriptionResult) -> Vec<Slice>;
}

pub trait Transformer {
    fn id(&self) -> TransformerId;
    fn transform(&self, slice: &Slice) -> TransformResult<Constraint>;
}
```

## Provenance types

```rust
pub struct SourceProvenance {
    pub file_path: &'static str,
    pub file_hash: Sha256,
    pub transcriber: TranscriberId,
    pub transcriber_version: &'static str,
    pub pages: Option<Range<u32>>,
}

pub struct SliceProvenance {
    pub transcription: SourceProvenance,
    pub blocks: Vec<BlockRef>,
    pub overrides: Vec<PatchRef>,
    pub slicer: SlicerId,
}

pub struct TransformProvenance {
    pub slice: SliceProvenance,
    pub transformer: TransformerId,
    pub pattern_or_manual: TransformKind,
}
```

## Extensibility

A new source kind (e.g. a standards-body video transcript) needs only to
provide a `Transcriber` crate. The rest of the pipeline does not care.

## Transformation rules are normative

Each pattern transformer is an ADR-governed artefact. "The prose
`shall return SW {hex}` maps to `Constraint::ExpectSw(hex)`" is a
*decision* we own — citable, versionable, reviewable. Building this into
the pipeline rather than into one-off scripts is the discipline that
makes the whole chain auditable.

## Testing

Each transcriber, slicer, transformer has unit tests over fixtures:
- Transcriber: canonical PDF excerpts → expected `TranscriptionResult`.
- Slicer: canonical transcription → expected `Slice` boundaries.
- Transformer: canonical slice → expected `Constraint`.

Golden-file snapshots in `insta` for the canonical outputs.
