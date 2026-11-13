import { useEffect, useMemo, useState } from 'react';
import type { CSSProperties } from 'react';
import { scenarios } from '../data/architecture';
import type {
  ArchEdge,
  ArchNode,
  ArchScenario,
  NodeState,
} from '../data/architecture';
import './ArchitectureExplorer.css';

const CANVAS_WIDTH = 1080;
const CANVAS_HEIGHT = 540;
const NODE_WIDTH = 216;
const NODE_HEIGHT = 92;
const ROUTE_MARGIN = 12;
const ROUTE_GAP = 18;

type Point = { x: number; y: number };
type EdgeSide = 'top' | 'right' | 'bottom' | 'left';
type Rect = { left: number; top: number; right: number; bottom: number };
type EdgeRoute = { points: Point[]; label: Point };

type RouteCandidate = {
  points: Point[];
  score: number;
};

const stateLabels: Record<NodeState, string> = {
  idle: 'รอ',
  running: 'กำลังทำงาน',
  done: 'เสร็จแล้ว',
  warning: 'มีคำเตือน',
  error: 'ผิดพลาด',
  skipped: 'ข้าม',
  cancelled: 'ยกเลิก',
};

const kindLabels: Record<ArchNode['kind'], string> = {
  input: 'รับเข้า',
  control: 'ควบคุม',
  worker: 'ประมวลผล',
  parser: 'parser',
  evidence: 'หลักฐาน',
  optional: 'ทางเลือก',
  output: 'ผลลัพธ์',
};

const outcomeLabels: Record<ArchScenario['outcomeTone'], string> = {
  success: 'สำเร็จ',
  warning: 'มีข้อควรระวัง',
  error: 'หยุดด้วยข้อผิดพลาด',
  neutral: 'สรุปผล',
};

const speedOptions = [0.5, 1, 2] as const;
type PlaybackSpeed = (typeof speedOptions)[number];

function prefersReducedMotion(): boolean {
  return typeof window !== 'undefined'
    && typeof window.matchMedia === 'function'
    && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function rectFor(node: ArchNode): Rect {
  return {
    left: node.x,
    top: node.y,
    right: node.x + NODE_WIDTH,
    bottom: node.y + NODE_HEIGHT,
  };
}

function expandRect(rect: Rect, margin: number): Rect {
  return {
    left: rect.left - margin,
    top: rect.top - margin,
    right: rect.right + margin,
    bottom: rect.bottom + margin,
  };
}

function centerFor(node: ArchNode): Point {
  return { x: node.x + NODE_WIDTH / 2, y: node.y + NODE_HEIGHT / 2 };
}

function endpointFor(rect: Rect, side: EdgeSide): Point {
  switch (side) {
    case 'top':
      return { x: (rect.left + rect.right) / 2, y: rect.top };
    case 'right':
      return { x: rect.right, y: (rect.top + rect.bottom) / 2 };
    case 'bottom':
      return { x: (rect.left + rect.right) / 2, y: rect.bottom };
    case 'left':
    default:
      return { x: rect.left, y: (rect.top + rect.bottom) / 2 };
  }
}

function sideIsHorizontal(side: EdgeSide): boolean {
  return side === 'left' || side === 'right';
}

function uniqueSorted(values: number[]): number[] {
  return Array.from(new Set(values.map((value) => Math.round(value * 10) / 10)))
    .filter((value) => value >= 8 && value <= CANVAS_WIDTH - 8)
    .sort((a, b) => a - b);
}

function routeAxisValues(nodes: ArchNode[], axis: 'x' | 'y'): number[] {
  const values = axis === 'x'
    ? [18, CANVAS_WIDTH - 18]
    : [18, CANVAS_HEIGHT - 18];

  nodes.forEach((node) => {
    if (axis === 'x') {
      values.push(node.x - ROUTE_GAP, node.x + NODE_WIDTH + ROUTE_GAP);
    } else {
      values.push(node.y - ROUTE_GAP, node.y + NODE_HEIGHT + ROUTE_GAP);
    }
  });

  return uniqueSorted(values);
}

function outwardAxisValues(
  values: number[],
  rect: Rect,
  side: EdgeSide,
  endpointAxis: number,
): number[] {
  return values.filter((value) => {
    if (Math.abs(value - endpointAxis) < 0.5) return true;
    if (side === 'right') return value >= rect.right + ROUTE_MARGIN;
    if (side === 'left') return value <= rect.left - ROUTE_MARGIN;
    if (side === 'bottom') return value >= rect.bottom + ROUTE_MARGIN;
    return value <= rect.top - ROUTE_MARGIN;
  });
}

function segmentIsBlocked(start: Point, end: Point, obstacles: Rect[]): boolean {
  if (Math.abs(start.x - end.x) > 0.5 && Math.abs(start.y - end.y) > 0.5) {
    return true;
  }

  if (Math.abs(start.x - end.x) < 0.5 && Math.abs(start.y - end.y) < 0.5) {
    return false;
  }

  const isHorizontal = Math.abs(start.y - end.y) < 0.5;
  const minAxis = isHorizontal
    ? Math.min(start.x, end.x)
    : Math.min(start.y, end.y);
  const maxAxis = isHorizontal
    ? Math.max(start.x, end.x)
    : Math.max(start.y, end.y);
  const fixedAxis = isHorizontal ? start.y : start.x;

  return obstacles.some((obstacle) => {
    const crossesFixedAxis = isHorizontal
      ? fixedAxis >= obstacle.top && fixedAxis <= obstacle.bottom
      : fixedAxis >= obstacle.left && fixedAxis <= obstacle.right;
    const overlapsAxis = isHorizontal
      ? maxAxis >= obstacle.left && minAxis <= obstacle.right
      : maxAxis >= obstacle.top && minAxis <= obstacle.bottom;
    return crossesFixedAxis && overlapsAxis;
  });
}

function cleanPoints(points: Point[]): Point[] {
  return points.filter((point, index) => {
    if (index === 0) return true;
    const previous = points[index - 1];
    return Math.abs(previous.x - point.x) > 0.5 || Math.abs(previous.y - point.y) > 0.5;
  });
}

function routeIsClear(points: Point[], obstacles: Rect[]): boolean {
  return points.every((point, index) => index === 0 || !segmentIsBlocked(points[index - 1], point, obstacles));
}

function routeScore(points: Point[]): number {
  let distance = 0;
  let turns = 0;
  let previousDirection: 'horizontal' | 'vertical' | null = null;

  points.forEach((point, index) => {
    if (index === 0) return;
    const previous = points[index - 1];
    const isHorizontal = Math.abs(previous.y - point.y) < 0.5;
    const direction = isHorizontal ? 'horizontal' : 'vertical';
    distance += Math.abs(previous.x - point.x) + Math.abs(previous.y - point.y);
    if (previousDirection && previousDirection !== direction) turns += 1;
    previousDirection = direction;
  });

  return distance + turns * 24;
}

function labelPointFor(points: Point[]): Point {
  const totalDistance = points.reduce((total, point, index) => {
    if (index === 0) return total;
    const previous = points[index - 1];
    return total + Math.abs(previous.x - point.x) + Math.abs(previous.y - point.y);
  }, 0);

  let distance = totalDistance / 2;
  for (let index = 1; index < points.length; index += 1) {
    const previous = points[index - 1];
    const current = points[index];
    const segmentDistance = Math.abs(previous.x - current.x) + Math.abs(previous.y - current.y);
    if (distance <= segmentDistance) {
      const ratio = segmentDistance === 0 ? 0 : distance / segmentDistance;
      const point = {
        x: previous.x + (current.x - previous.x) * ratio,
        y: previous.y + (current.y - previous.y) * ratio,
      };
      if (Math.abs(previous.y - current.y) < 0.5) point.y -= 7;
      else point.x += 7;
      return point;
    }
    distance -= segmentDistance;
  }

  return points[0] ?? { x: 0, y: 0 };
}

function polylinePath(points: Point[]): string {
  return points.map((point, index) => `${index === 0 ? 'M' : 'L'} ${point.x} ${point.y}`).join(' ');
}

function buildEdgeRoute(edge: ArchEdge, nodes: ArchNode[]): EdgeRoute {
  const source = nodes.find((node) => node.id === edge.from);
  const target = nodes.find((node) => node.id === edge.to);

  if (!source || !target) {
    const fallback = [{ x: 0, y: 0 }, { x: 0, y: 0 }];
    return { points: fallback, label: labelPointFor(fallback) };
  }

  const sourceRect = rectFor(source);
  const targetRect = rectFor(target);
  const sourceCenter = centerFor(source);
  const targetCenter = centerFor(target);
  const deltaX = targetCenter.x - sourceCenter.x;
  const deltaY = targetCenter.y - sourceCenter.y;
  const useHorizontal = Math.abs(deltaX) >= Math.abs(deltaY);
  let sourceSide: EdgeSide = useHorizontal
    ? (deltaX >= 0 ? 'right' : 'left')
    : (deltaY >= 0 ? 'bottom' : 'top');
  let targetSide: EdgeSide = useHorizontal
    ? (deltaX >= 0 ? 'left' : 'right')
    : (deltaY >= 0 ? 'top' : 'bottom');

  const sameRowIntermediates = useHorizontal && Math.abs(deltaY) < 0.5
    ? nodes.filter((node) => {
      if (node.id === source.id || node.id === target.id || Math.abs(node.y - source.y) > 0.5) return false;
      const nodeCenterX = node.x + NODE_WIDTH / 2;
      const minCenterX = Math.min(sourceCenter.x, targetCenter.x);
      const maxCenterX = Math.max(sourceCenter.x, targetCenter.x);
      return nodeCenterX > minCenterX && nodeCenterX < maxCenterX;
    })
    : [];

  if (sameRowIntermediates.length > 0) {
    const rowNodes = [source, target, ...sameRowIntermediates];
    const bottomGutter = Math.max(...rowNodes.map((node) => node.y + NODE_HEIGHT)) + ROUTE_GAP;
    const topGutter = Math.min(...rowNodes.map((node) => node.y)) - ROUTE_GAP;
    const canUseBottomGutter = bottomGutter <= CANVAS_HEIGHT - 8;
    const canUseTopGutter = topGutter >= 8;
    if (canUseBottomGutter || !canUseTopGutter) {
      sourceSide = 'bottom';
      targetSide = 'bottom';
    } else {
      sourceSide = 'top';
      targetSide = 'top';
    }
  }

  const start = endpointFor(sourceRect, sourceSide);
  const end = endpointFor(targetRect, targetSide);
  const obstacleRects = nodes
    .filter((node) => node.id !== source.id && node.id !== target.id)
    .map((node) => expandRect(rectFor(node), ROUTE_MARGIN));
  const xValues = routeAxisValues(nodes, 'x');
  const yValues = routeAxisValues(nodes, 'y');
  const sourceXLanes = outwardAxisValues(xValues, sourceRect, sourceSide, start.x);
  const targetXLanes = outwardAxisValues(xValues, targetRect, targetSide, end.x);
  const sourceYLanes = outwardAxisValues(yValues, sourceRect, sourceSide, start.y);
  const targetYLanes = outwardAxisValues(yValues, targetRect, targetSide, end.y);
  const candidates: RouteCandidate[] = [];

  const consider = (candidatePoints: Point[]) => {
    const points = cleanPoints(candidatePoints);
    if (points.length < 2 || !routeIsClear(points, obstacleRects)) return;
    candidates.push({ points, score: routeScore(points) });
  };

  const startIsHorizontal = sideIsHorizontal(sourceSide);
  const endIsHorizontal = sideIsHorizontal(targetSide);

  if (startIsHorizontal && endIsHorizontal) {
    if (Math.abs(start.y - end.y) < 0.5) consider([start, end]);

    sourceXLanes.forEach((laneX) => {
      consider([start, { x: laneX, y: start.y }, { x: laneX, y: end.y }, end]);
    });

    sourceXLanes.forEach((laneX) => {
      targetXLanes.forEach((targetLaneX) => {
        yValues.forEach((laneY) => {
          consider([
            start,
            { x: laneX, y: start.y },
            { x: laneX, y: laneY },
            { x: targetLaneX, y: laneY },
            { x: targetLaneX, y: end.y },
            end,
          ]);
        });
      });
    });
  } else if (!startIsHorizontal && !endIsHorizontal) {
    if (Math.abs(start.x - end.x) < 0.5) consider([start, end]);

    sourceYLanes.forEach((laneY) => {
      consider([start, { x: start.x, y: laneY }, { x: end.x, y: laneY }, end]);
    });

    sourceYLanes.forEach((laneY) => {
      targetYLanes.forEach((targetLaneY) => {
        xValues.forEach((laneX) => {
          consider([
            start,
            { x: start.x, y: laneY },
            { x: laneX, y: laneY },
            { x: laneX, y: targetLaneY },
            { x: end.x, y: targetLaneY },
            end,
          ]);
        });
      });
    });
  } else if (startIsHorizontal) {
    const sourceLanes = sourceXLanes.length > 0 ? sourceXLanes : [start.x];
    const targetLanes = targetYLanes.length > 0 ? targetYLanes : [end.y];
    consider([start, { x: end.x, y: start.y }, end]);
    sourceLanes.forEach((laneX) => {
      targetLanes.forEach((laneY) => {
        consider([
          start,
          { x: laneX, y: start.y },
          { x: laneX, y: laneY },
          { x: end.x, y: laneY },
          end,
        ]);
      });
    });
  } else {
    const sourceLanes = sourceYLanes.length > 0 ? sourceYLanes : [start.y];
    const targetLanes = targetXLanes.length > 0 ? targetXLanes : [end.x];
    consider([start, { x: start.x, y: end.y }, end]);
    sourceLanes.forEach((laneY) => {
      targetLanes.forEach((laneX) => {
        consider([
          start,
          { x: start.x, y: laneY },
          { x: laneX, y: laneY },
          { x: laneX, y: end.y },
          end,
        ]);
      });
    });
  }

  const best = candidates.sort((a, b) => a.score - b.score)[0]?.points;
  const points = best ?? (startIsHorizontal
    ? [start, { x: end.x, y: start.y }, end]
    : [start, { x: start.x, y: end.y }, end]);

  return { points, label: labelPointFor(points) };
}

function nodePositionStyle(node: ArchNode): CSSProperties {
  return {
    '--archx-left': `${(node.x / CANVAS_WIDTH) * 100}%`,
    '--archx-top': `${(node.y / CANVAS_HEIGHT) * 100}%`,
  } as CSSProperties;
}

function ArchitectureExplorer() {
  const [scenarioId, setScenarioId] = useState(scenarios[0]?.id ?? '');
  const [stepIndex, setStepIndex] = useState(0);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [isPlaying, setIsPlaying] = useState(() => !prefersReducedMotion());
  const [speed, setSpeed] = useState<PlaybackSpeed>(1);
  const [reducedMotion, setReducedMotion] = useState(() => prefersReducedMotion());

  const scenario = useMemo<ArchScenario | undefined>(
    () => scenarios.find((item) => item.id === scenarioId) ?? scenarios[0],
    [scenarioId],
  );
  const steps = scenario?.steps ?? [];
  const currentStepIndex = steps.length > 0 ? Math.min(stepIndex, steps.length - 1) : 0;
  const currentStep = steps[currentStepIndex];

  const edgeRoutes = useMemo(() => {
    if (!scenario) return [];
    return scenario.edges.map((edge, index) => ({
      edge,
      key: `${edge.id}-${index}`,
      route: buildEdgeRoute(edge, scenario.nodes),
    }));
  }, [scenario]);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return undefined;

    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    const onPreferenceChange = (event: MediaQueryListEvent) => {
      setReducedMotion(event.matches);
      if (event.matches) setIsPlaying(false);
    };

    mediaQuery.addEventListener?.('change', onPreferenceChange);
    return () => mediaQuery.removeEventListener?.('change', onPreferenceChange);
  }, []);

  useEffect(() => {
    setStepIndex(0);
    setSelectedNodeId(null);
    setIsPlaying(!reducedMotion);
  }, [scenarioId, reducedMotion]);

  useEffect(() => {
    if (!scenario || steps.length < 2 || reducedMotion || !isPlaying || currentStepIndex >= steps.length - 1) {
      if (isPlaying && steps.length > 0 && currentStepIndex >= steps.length - 1) setIsPlaying(false);
      return undefined;
    }

    const timer = window.setTimeout(() => {
      setStepIndex((previous) => Math.min(previous + 1, steps.length - 1));
    }, 1500 / speed);

    return () => window.clearTimeout(timer);
  }, [currentStepIndex, isPlaying, reducedMotion, scenario, speed, steps.length]);

  if (!scenario) {
    return (
      <section className="archx-root" aria-label="Architecture explorer">
        <div className="archx-empty-state">
          <strong>ยังไม่มีข้อมูลสถาปัตยกรรม</strong>
          <span>เพิ่ม scenarios เพื่อเริ่มดูเส้นทางการประมวลผล</span>
        </div>
      </section>
    );
  }

  const selectedNode = scenario.nodes.find((node) => node.id === selectedNodeId);
  const selectedNodeState = selectedNode
    ? currentStep?.nodeStates[selectedNode.id] ?? 'idle'
    : null;
  const isAtLastStep = steps.length === 0 || currentStepIndex >= steps.length - 1;

  const resetAndPlay = () => {
    setStepIndex(0);
    setSelectedNodeId(null);
    setIsPlaying(!reducedMotion);
  };

  const goToStep = (index: number) => {
    setStepIndex(Math.max(0, Math.min(index, Math.max(steps.length - 1, 0))));
    setIsPlaying(false);
  };

  return (
    <section className={`archx-root ${isPlaying ? 'archx-playing' : 'archx-paused'} ${reducedMotion ? 'archx-reduced' : ''}`} style={{ '--archx-flow-duration': `${1.05 / speed}s` } as CSSProperties} aria-label="สำรวจสถาปัตยกรรมระบบ">
      <div className="archx-header">
        <div>
          <p className="archx-kicker">ARCHITECTURE EXPLORER / SIMULATION</p>
          <h2>เส้นทางการประมวลผล</h2>
          <p className="archx-intro">เลือกกรณีเพื่อดูว่าระบบคัดกรอง วิเคราะห์ และส่งต่อหลักฐานอย่างไรในแต่ละเส้นทาง</p>
        </div>
        <div className="archx-caveat" role="note">
          <span className="archx-caveat-dot" aria-hidden="true" />
          <span>สถานการณ์จำลอง · ไม่มี parser หรือ endpoint ทำงานจริง</span>
        </div>
      </div>

      <div className="archx-case-panel">
        <div className="archx-section-heading">
          <div>
            <p className="archx-kicker">CASE SWITCHER</p>
            <h2>เลือกสถานการณ์</h2>
          </div>
          <span className="archx-case-count">{scenarios.length.toString().padStart(2, '0')} CASES</span>
        </div>
        <div className="archx-case-grid" role="group" aria-label="เลือกกรณีจำลอง">
          {scenarios.map((item) => (
            <button
              className={`archx-case-button ${item.id === scenario.id ? 'archx-case-active' : ''}`}
              type="button"
              key={item.id}
              aria-pressed={item.id === scenario.id}
              onClick={() => setScenarioId(item.id)}
            >
              <span className="archx-case-code">{item.code}</span>
              <span className="archx-case-title">{item.title}</span>
              <span className="archx-case-subtitle">{item.subtitle}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="archx-scenario-banner">
        <div className="archx-scenario-copy">
          <div className="archx-scenario-meta">
            <span className="archx-code-pill">{scenario.code}</span>
            <span className="archx-scenario-divider" aria-hidden="true" />
            <span>{scenario.subtitle}</span>
          </div>
          <h2>{scenario.title}</h2>
          <p>{scenario.summary}</p>
        </div>
        <div className={`archx-outcome archx-outcome-${scenario.outcomeTone}`}>
          <span className="archx-outcome-label">{outcomeLabels[scenario.outcomeTone]}</span>
          <strong>{scenario.outcome}</strong>
        </div>
      </div>

      <div className="archx-controlbar" aria-label="ตัวควบคุมการจำลอง">
        <div className="archx-transport-controls">
          <button
            className="archx-transport-button archx-transport-primary"
            type="button"
            onClick={() => setIsPlaying((playing) => !playing)}
            disabled={isAtLastStep || reducedMotion}
            title={reducedMotion ? 'โหมดลดการเคลื่อนไหว: ใช้ปุ่มเดินทีละขั้น' : undefined}
            aria-label={isPlaying ? 'หยุดชั่วคราว' : 'เล่นต่อ'}
          >
            <span aria-hidden="true">{isPlaying ? 'Ⅱ' : '▶'}</span>
            <span>{isPlaying ? 'พัก' : 'เล่น'}</span>
          </button>
          <button className="archx-transport-button" type="button" onClick={resetAndPlay} aria-label="เริ่มสถานการณ์นี้ใหม่">
            <span aria-hidden="true">↻</span>
            <span>เริ่มใหม่</span>
          </button>
          <button
            className="archx-icon-transport"
            type="button"
            onClick={() => goToStep(currentStepIndex - 1)}
            disabled={currentStepIndex <= 0}
            aria-label="ขั้นตอนก่อนหน้า"
          >
            ‹
          </button>
          <button
            className="archx-icon-transport"
            type="button"
            onClick={() => goToStep(currentStepIndex + 1)}
            disabled={isAtLastStep}
            aria-label="ขั้นตอนถัดไป"
          >
            ›
          </button>
        </div>
        <div className="archx-speed-controls" role="group" aria-label="ความเร็วการเล่น">
          <span>ความเร็ว</span>
          {speedOptions.map((option) => (
            <button
              className={`archx-speed-button ${speed === option ? 'archx-speed-active' : ''}`}
              type="button"
              key={option}
              aria-pressed={speed === option}
              onClick={() => setSpeed(option)}
            >
              {option}x
            </button>
          ))}
        </div>
      </div>

      {reducedMotion && <p className="archx-motion-note" role="note">โหมดลดการเคลื่อนไหวเปิดอยู่ — ใช้ปุ่มก่อนหน้า/ถัดไปหรือเลือกขั้นตอนเพื่อดูเส้นทางแบบภาพนิ่ง</p>}

      <div className="archx-step-summary">
        <div className="archx-step-marker">STEP {String(currentStepIndex + 1).padStart(2, '0')}</div>
        <div>
          <h2>{currentStep?.title ?? 'รอข้อมูลขั้นตอน'}</h2>
          <p>{currentStep?.text ?? 'เลือกกรณีหรือขั้นตอนเพื่อดูคำอธิบายการทำงาน'}</p>
        </div>
        <p className="archx-live" aria-live="polite">
          <span>สถานะปัจจุบัน</span>
          {currentStep ? ` ขั้นตอนที่ ${currentStepIndex + 1} จาก ${steps.length}` : ' ไม่มีขั้นตอน'}
        </p>
      </div>

      <div className="archx-timeline" role="group" aria-label="ลำดับขั้นตอนของสถานการณ์">
        {steps.map((step, index) => (
          <button
            className={`archx-timeline-step ${index === currentStepIndex ? 'archx-timeline-current' : ''} ${index < currentStepIndex ? 'archx-timeline-done' : ''}`}
            type="button"
            key={`${scenario.id}-${index}`}
            aria-pressed={index === currentStepIndex}
            aria-label={`ขั้นตอนที่ ${index + 1}: ${step.title}`}
            onClick={() => goToStep(index)}
          >
            <span className="archx-timeline-number">{String(index + 1).padStart(2, '0')}</span>
            <span className="archx-timeline-title">{step.title}</span>
          </button>
        ))}
      </div>

      <div className="archx-diagram-layout">
        <div className="archx-graph-panel">
          <div className="archx-graph-heading">
            <div>
              <p className="archx-kicker">LIVE ROUTE MAP</p>
              <h2>แผนผังการทำงาน</h2>
            </div>
            <div className="archx-legend" aria-hidden="true">
              <span><i className="archx-legend-line archx-legend-normal" /> ปกติ</span>
              <span><i className="archx-legend-line archx-legend-optional" /> ทางเลือก</span>
              <span><i className="archx-legend-line archx-legend-error" /> ผิดพลาด</span>
            </div>
          </div>
          <div className="archx-graph-scroll">
            <div className="archx-diagram-canvas">
              <svg className="archx-edge-svg" viewBox={`0 0 ${CANVAS_WIDTH} ${CANVAS_HEIGHT}`} aria-hidden="true" focusable="false">
                <defs>
                  <marker id="archx-arrow-normal" markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto">
                    <path d="M 0 0 L 8 4 L 0 8 z" fill="#6d8a98" />
                  </marker>
                  <marker id="archx-arrow-optional" markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto">
                    <path d="M 0 0 L 8 4 L 0 8 z" fill="#b7a0eb" />
                  </marker>
                  <marker id="archx-arrow-error" markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto">
                    <path d="M 0 0 L 8 4 L 0 8 z" fill="#ec7979" />
                  </marker>
                </defs>
                <g className="archx-edge-layer">
                  {edgeRoutes.map(({ edge, key, route }) => {
                    const tone = edge.tone ?? 'normal';
                    const isActive = currentStep?.activeEdges.includes(edge.id) ?? false;
                    return (
                      <g className="archx-edge-group" key={key}>
                        <path
                          className={`archx-edge archx-edge-${tone} ${isActive ? 'archx-edge-active' : ''}`}
                          d={polylinePath(route.points)}
                          markerEnd={`url(#archx-arrow-${tone})`}
                        />
                        {edge.label ? (
                          <text className={`archx-edge-label archx-edge-label-${tone}`} x={route.label.x} y={route.label.y} textAnchor="middle">
                            {edge.label}
                          </text>
                        ) : null}
                      </g>
                    );
                  })}
                </g>
              </svg>
              {scenario.nodes.map((node) => {
                const nodeState = currentStep?.nodeStates[node.id] ?? 'idle';
                const isSelected = selectedNodeId === node.id;
                return (
                  <button
                    className={`archx-node archx-node-kind-${node.kind} archx-node-state-${nodeState} ${isSelected ? 'archx-node-selected' : ''}`}
                    type="button"
                    key={node.id}
                    style={nodePositionStyle(node)}
                    aria-pressed={isSelected}
                    aria-label={`${node.title}: ${stateLabels[nodeState]}`}
                    onClick={() => setSelectedNodeId(node.id)}
                  >
                    <span className="archx-node-kind">{kindLabels[node.kind]}</span>
                    <strong className="archx-node-title">{node.title}</strong>
                    <span className="archx-node-subtitle">{node.sub}</span>
                    <span className="archx-node-status"><i aria-hidden="true" /> {stateLabels[nodeState]}</span>
                  </button>
                );
              })}
            </div>
          </div>
          <p className="archx-graph-hint">คลิกโหนดเพื่อดูรายละเอียด · เลื่อนแนวนอนเมื่อเปิดบนจอแคบ</p>
        </div>

        <aside className="archx-inspector" aria-label="รายละเอียดโหนดที่เลือก">
          <div className="archx-inspector-heading">
            <div>
              <p className="archx-kicker">NODE INSPECTOR</p>
              <h2>รายละเอียดโหนด</h2>
            </div>
            {selectedNode ? <span className={`archx-inspector-state archx-inspector-state-${selectedNodeState}`}>{selectedNodeState ? stateLabels[selectedNodeState] : 'รอ'}</span> : null}
          </div>
          {selectedNode ? (
            <div className="archx-inspector-content">
              <span className="archx-inspector-kind">{kindLabels[selectedNode.kind]} / {selectedNode.id}</span>
              <h3>{selectedNode.title}</h3>
              <p className="archx-inspector-subtitle">{selectedNode.sub}</p>
              <p className="archx-inspector-detail">{selectedNode.detail}</p>
              <div className="archx-inspector-step">
                <span>ในขั้นตอนนี้</span>
                <strong>{selectedNodeState ? stateLabels[selectedNodeState] : 'รอ'}</strong>
              </div>
            </div>
          ) : (
            <div className="archx-inspector-empty">
              <span className="archx-inspector-empty-mark" aria-hidden="true">+</span>
              <p>เลือกกล่องใดก็ได้ในแผนผังเพื่ออ่านหน้าที่และสถานะปัจจุบัน</p>
            </div>
          )}
        </aside>
      </div>
    </section>
  );
}

export default ArchitectureExplorer;
