/* Tiny, dependency-free markdown renderer for assistant replies.
 *
 * Covers exactly what the Security-Ops engine emits: headings, paragraphs,
 * bullet / numbered lists, blockquotes, **bold**, _italic_, `inline code`,
 * [links](href), and ```fenced code blocks``` (with a copy button). It builds
 * React nodes — never dangerouslySetInnerHTML — so assistant output can never
 * inject markup. External links open in a new tab with rel hardening. */
import React from 'react';
import { CopyButton } from '../../components/ui.jsx';

/* ---- Block segmentation (fenced code is lifted out first) ------------------ */
function segment(src) {
  const text = (src || '').replace(/\r\n/g, '\n');
  const out = [];
  const lines = text.split('\n');
  let i = 0;
  let para = [];

  const flushPara = () => {
    if (!para.length) return;
    // Group consecutive list / heading / quote lines into structured blocks.
    out.push(...parseFlow(para));
    para = [];
  };

  while (i < lines.length) {
    const fence = /^```(.*)$/.exec(lines[i].trim());
    if (fence) {
      flushPara();
      const lang = fence[1].trim();
      const body = [];
      i += 1;
      while (i < lines.length && !/^```/.test(lines[i].trim())) { body.push(lines[i]); i += 1; }
      i += 1; // consume closing fence
      out.push({ type: 'code', lang, text: body.join('\n') });
      continue;
    }
    para.push(lines[i]);
    i += 1;
  }
  flushPara();
  return out;
}

/* Parse non-code lines into paragraphs, headings, lists, quotes. */
function parseFlow(lines) {
  const blocks = [];
  let cur = null;
  const push = () => { if (cur && cur.lines && cur.lines.length) blocks.push(cur); cur = null; };

  for (const raw of lines) {
    const line = raw.replace(/\s+$/, '');
    if (line.trim() === '') { push(); continue; }
    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    const bullet = /^\s*[-*+]\s+(.*)$/.exec(line);
    const ordered = /^\s*\d+[.)]\s+(.*)$/.exec(line);
    const quote = /^\s*>\s?(.*)$/.exec(line);

    if (heading) {
      push();
      blocks.push({ type: 'h', level: Math.min(heading[1].length, 4), text: heading[2] });
    } else if (bullet) {
      if (!cur || cur.type !== 'ul') { push(); cur = { type: 'ul', lines: [] }; }
      cur.lines.push(bullet[1]);
    } else if (ordered) {
      if (!cur || cur.type !== 'ol') { push(); cur = { type: 'ol', lines: [] }; }
      cur.lines.push(ordered[1]);
    } else if (quote) {
      if (!cur || cur.type !== 'quote') { push(); cur = { type: 'quote', lines: [] }; }
      cur.lines.push(quote[1]);
    } else {
      if (!cur || cur.type !== 'p') { push(); cur = { type: 'p', lines: [] }; }
      cur.lines.push(line);
    }
  }
  push();
  return blocks;
}

/* ---- Inline: bold, italic, code, links ------------------------------------ */
const INLINE = /(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\([^)\s]+\)|(?:\b_[^_]+_\b))/g;

function renderInline(text, keyBase) {
  const nodes = [];
  let last = 0;
  let m;
  let n = 0;
  INLINE.lastIndex = 0;
  while ((m = INLINE.exec(text)) !== null) {
    if (m.index > last) nodes.push(<React.Fragment key={`${keyBase}-t${n}`}>{text.slice(last, m.index)}</React.Fragment>);
    const tok = m[0];
    if (tok.startsWith('**')) {
      nodes.push(<strong key={`${keyBase}-b${n}`}>{tok.slice(2, -2)}</strong>);
    } else if (tok.startsWith('`')) {
      nodes.push(<code key={`${keyBase}-c${n}`} className="sa-md-code">{tok.slice(1, -1)}</code>);
    } else if (tok.startsWith('[')) {
      const lm = /^\[([^\]]+)\]\(([^)\s]+)\)$/.exec(tok);
      const href = lm ? lm[2] : '#';
      const safe = /^(https?:|mailto:|\/)/i.test(href) ? href : '#';
      nodes.push(
        <a key={`${keyBase}-l${n}`} className="sa-md-link" href={safe} target="_blank" rel="noopener noreferrer">{lm ? lm[1] : tok}</a>,
      );
    } else {
      nodes.push(<em key={`${keyBase}-i${n}`}>{tok.slice(1, -1)}</em>);
    }
    last = m.index + tok.length;
    n += 1;
  }
  if (last < text.length) nodes.push(<React.Fragment key={`${keyBase}-t${n}`}>{text.slice(last)}</React.Fragment>);
  return nodes;
}

export default function Markdown({ content }) {
  if (!content) return null;
  const blocks = segment(content);
  return (
    <div className="sa-md">
      {blocks.map((b, bi) => {
        const key = `b${bi}`;
        if (b.type === 'code') {
          return (
            <div className="sa-md-pre" key={key}>
              <div className="sa-md-pre__bar">
                <span className="sa-md-pre__lang">{b.lang || 'code'}</span>
                <CopyButton text={b.text} className="sa-md-pre__copy" />
              </div>
              <pre><code>{b.text}</code></pre>
            </div>
          );
        }
        if (b.type === 'h') {
          const Tag = `h${b.level < 3 ? 3 : b.level}`;
          return <Tag className="sa-md-h" key={key}>{renderInline(b.text, key)}</Tag>;
        }
        if (b.type === 'ul') {
          return <ul key={key}>{b.lines.map((l, li) => <li key={`${key}-${li}`}>{renderInline(l, `${key}-${li}`)}</li>)}</ul>;
        }
        if (b.type === 'ol') {
          return <ol key={key}>{b.lines.map((l, li) => <li key={`${key}-${li}`}>{renderInline(l, `${key}-${li}`)}</li>)}</ol>;
        }
        if (b.type === 'quote') {
          return <blockquote className="sa-md-quote" key={key}>{b.lines.map((l, li) => <p key={`${key}-${li}`}>{renderInline(l, `${key}-${li}`)}</p>)}</blockquote>;
        }
        return (
          <p key={key}>
            {b.lines.map((l, li) => (
              <React.Fragment key={`${key}-${li}`}>
                {renderInline(l, `${key}-${li}`)}
                {li < b.lines.length - 1 ? <br /> : null}
              </React.Fragment>
            ))}
          </p>
        );
      })}
    </div>
  );
}
