import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { Shield, Radio, Activity } from 'lucide-react';

interface CyberRadar3DProps {
  className?: string;
  height?: number;
  activeNodes?: number;
  threatDetected?: boolean;
}

export const CyberRadar3D: React.FC<CyberRadar3DProps> = ({
  className = '',
  height = 220,
  activeNodes = 6,
  threatDetected = false,
}) => {
  const mountRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const scene = new THREE.Scene();
    const width = container.clientWidth || 300;
    const camera = new THREE.PerspectiveCamera(40, width / height, 0.1, 1000);
    camera.position.set(0, 3.2, 3.6);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // 1. Concentric Radar Rings
    const ringsGroup = new THREE.Group();
    scene.add(ringsGroup);

    const ringRadii = [0.8, 1.4, 2.0];
    ringRadii.forEach((r, idx) => {
      const ringGeo = new THREE.RingGeometry(r - 0.015, r, 64);
      const ringMat = new THREE.MeshBasicMaterial({
        color: idx === 2 ? 0xef4444 : 0x991b1b,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: idx === 2 ? 0.7 : 0.4,
      });
      const ringMesh = new THREE.Mesh(ringGeo, ringMat);
      ringMesh.rotation.x = -Math.PI / 2;
      ringsGroup.add(ringMesh);
    });

    // 2. Crosshair Grid Lines
    const gridMat = new THREE.LineBasicMaterial({
      color: 0x7f1d1d,
      transparent: true,
      opacity: 0.35,
    });
    const xPoints = [new THREE.Vector3(-2.1, 0, 0), new THREE.Vector3(2.1, 0, 0)];
    const zPoints = [new THREE.Vector3(0, 0, -2.1), new THREE.Vector3(0, 0, 2.1)];
    const xLine = new THREE.Line(new THREE.BufferGeometry().setFromPoints(xPoints), gridMat);
    const zLine = new THREE.Line(new THREE.BufferGeometry().setFromPoints(zPoints), gridMat);
    ringsGroup.add(xLine);
    ringsGroup.add(zLine);

    // 3. Radar Sweep Beam (Rotating sector)
    const sweepGeo = new THREE.CircleGeometry(2.0, 32, 0, Math.PI / 4);
    const sweepMat = new THREE.MeshBasicMaterial({
      color: 0xff1744,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.22,
    });
    const sweepMesh = new THREE.Mesh(sweepGeo, sweepMat);
    sweepMesh.rotation.x = -Math.PI / 2;
    ringsGroup.add(sweepMesh);

    // Leading edge beam line
    const edgePoints = [new THREE.Vector3(0, 0, 0), new THREE.Vector3(2.0, 0, 0)];
    const edgeMat = new THREE.LineBasicMaterial({ color: 0xff4d4d, linewidth: 2 });
    const edgeLine = new THREE.Line(new THREE.BufferGeometry().setFromPoints(edgePoints), edgeMat);
    sweepMesh.add(edgeLine);

    // 4. Target Nodes (Security agents / Endpoints)
    const nodeGroup = new THREE.Group();
    scene.add(nodeGroup);

    const nodeGeo = new THREE.SphereGeometry(0.06, 12, 12);
    const nodePositions = [
      { x: 0.6, z: -0.8, color: 0x10b981 },
      { x: -1.0, z: 0.5, color: 0xef4444 },
      { x: 1.2, z: 0.7, color: 0x3b82f6 },
      { x: -0.4, z: -1.2, color: 0x10b981 },
      { x: 1.5, z: -0.4, color: 0xf59e0b },
      { x: -1.4, z: -0.9, color: 0xef4444 },
    ];

    const nodeMeshes: THREE.Mesh[] = [];
    nodePositions.forEach((pos) => {
      const mat = new THREE.MeshBasicMaterial({ color: pos.color });
      const mesh = new THREE.Mesh(nodeGeo, mat);
      mesh.position.set(pos.x, 0.08, pos.z);
      nodeMeshes.push(mesh);
      nodeGroup.add(mesh);

      // Node vertical pedestal beam
      const pedPoints = [new THREE.Vector3(pos.x, 0, pos.z), new THREE.Vector3(pos.x, 0.08, pos.z)];
      const pedLine = new THREE.Line(
        new THREE.BufferGeometry().setFromPoints(pedPoints),
        new THREE.LineBasicMaterial({ color: pos.color, transparent: true, opacity: 0.5 })
      );
      nodeGroup.add(pedLine);
    });

    // Resize Handler
    const handleResize = () => {
      if (!container) return;
      const newWidth = container.clientWidth;
      camera.aspect = newWidth / height;
      camera.updateProjectionMatrix();
      renderer.setSize(newWidth, height);
    };
    window.addEventListener('resize', handleResize);

    // Animation Loop
    let animationFrameId: number;
    let clock = new THREE.Clock();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);
      const delta = clock.getDelta();
      const time = clock.getElapsedTime();

      // Rotate radar sweep
      sweepMesh.rotation.z += 1.8 * delta;

      // Pulse target nodes
      nodeMeshes.forEach((mesh, idx) => {
        const s = 1.0 + Math.sin(time * 3 + idx) * 0.25;
        mesh.scale.set(s, s, s);
      });

      // Subtle tilt drift
      ringsGroup.rotation.y = Math.sin(time * 0.3) * 0.08;

      renderer.render(scene, camera);
    };

    animate();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', handleResize);
      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
      renderer.dispose();
      sweepGeo.dispose();
      sweepMat.dispose();
      nodeGeo.dispose();
    };
  }, [height]);

  return (
    <div
      className={`relative rounded-2xl overflow-hidden bg-gradient-to-b from-[#130d15] to-[#060408] border border-red-950/70 shadow-[0_0_25px_rgba(239,68,68,0.1)] ${className}`}
    >
      <div ref={mountRef} className="w-full flex items-center justify-center" style={{ height }} />

      {/* Cyber HUD overlays */}
      <div className="absolute top-2.5 left-3 pointer-events-none flex items-center gap-2">
        <Radio className="w-3.5 h-3.5 text-red-500 animate-pulse" />
        <span className="text-[10px] font-mono tracking-widest uppercase text-red-400 font-bold">
          AI THREAT RADAR // 3D
        </span>
      </div>

      <div className="absolute top-2.5 right-3 pointer-events-none text-right">
        <span className="text-[9px] font-mono tracking-wider text-slate-500 uppercase block">
          NODES SCANNED
        </span>
        <span className="text-[10px] font-mono text-emerald-400 font-bold">
          {activeNodes} AGENTS ACTIVE
        </span>
      </div>

      <div className="absolute bottom-2.5 left-3 pointer-events-none text-[9px] font-mono text-slate-500">
        FREQUENCY // 2.4 GHz ENCRYPTED
      </div>

      <div className="absolute bottom-2.5 right-3 pointer-events-none text-[9px] font-mono text-red-400 flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-ping" />
        RADAR SWEEP ONLINE
      </div>

      {/* Tech Corner Brackets */}
      <div className="absolute top-1 left-1 w-2 h-2 border-t border-l border-red-500/40 pointer-events-none" />
      <div className="absolute top-1 right-1 w-2 h-2 border-t border-r border-red-500/40 pointer-events-none" />
      <div className="absolute bottom-1 left-1 w-2 h-2 border-b border-l border-red-500/40 pointer-events-none" />
      <div className="absolute bottom-1 right-1 w-2 h-2 border-b border-r border-red-500/40 pointer-events-none" />
    </div>
  );
};
