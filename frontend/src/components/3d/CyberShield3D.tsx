import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { ShieldAlert, ShieldCheck, Zap } from 'lucide-react';

interface CyberShield3DProps {
  threatLevel?: 'nominal' | 'elevated' | 'critical';
  className?: string;
  height?: number;
}

export const CyberShield3D: React.FC<CyberShield3DProps> = ({
  threatLevel = 'nominal',
  className = '',
  height = 240,
}) => {
  const mountRef = useRef<HTMLDivElement | null>(null);
  const [isHovered, setIsHovered] = useState(false);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    // Scene setup
    const scene = new THREE.Scene();

    const width = container.clientWidth || 320;
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.z = 4.2;

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // Color definitions based on threat state
    const primaryColor = threatLevel === 'critical' ? 0xff1744 : 0xef4444;
    const secondaryColor = threatLevel === 'critical' ? 0xff5252 : 0xdc2626;
    const innerColor = 0x991b1b;

    // 1. Core Polyhedron (The AI Shield Core)
    const coreGeo = new THREE.IcosahedronGeometry(1.0, 1);
    const coreMat = new THREE.MeshBasicMaterial({
      color: primaryColor,
      wireframe: true,
      transparent: true,
      opacity: 0.85,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    scene.add(coreMesh);

    // 1b. Solid inner glow core
    const innerGeo = new THREE.IcosahedronGeometry(0.72, 0);
    const innerMat = new THREE.MeshBasicMaterial({
      color: innerColor,
      transparent: true,
      opacity: 0.45,
    });
    const innerMesh = new THREE.Mesh(innerGeo, innerMat);
    coreMesh.add(innerMesh);

    // 2. Orbital Defense Ring 1
    const ring1Geo = new THREE.TorusGeometry(1.65, 0.018, 8, 64);
    const ring1Mat = new THREE.MeshBasicMaterial({
      color: secondaryColor,
      transparent: true,
      opacity: 0.75,
    });
    const ring1 = new THREE.Mesh(ring1Geo, ring1Mat);
    ring1.rotation.x = Math.PI / 3;
    scene.add(ring1);

    // 3. Orbital Defense Ring 2 (Perpendicular Angle)
    const ring2Geo = new THREE.TorusGeometry(1.9, 0.015, 8, 64);
    const ring2Mat = new THREE.MeshBasicMaterial({
      color: 0xff1744,
      transparent: true,
      opacity: 0.6,
    });
    const ring2 = new THREE.Mesh(ring2Geo, ring2Mat);
    ring2.rotation.y = Math.PI / 4;
    ring2.rotation.x = -Math.PI / 6;
    scene.add(ring2);

    // 4. Defense Satellites (Orbiting security sensor nodes)
    const satGroup = new THREE.Group();
    scene.add(satGroup);

    const satGeo = new THREE.SphereGeometry(0.065, 8, 8);
    const satMat = new THREE.MeshBasicMaterial({ color: 0xffffff });

    const satellites: THREE.Mesh[] = [];
    const satAngles = [0, (2 * Math.PI) / 3, (4 * Math.PI) / 3];
    const satRadius = 1.65;

    satAngles.forEach((angle) => {
      const sat = new THREE.Mesh(satGeo, satMat);
      sat.position.x = Math.cos(angle) * satRadius;
      sat.position.y = Math.sin(angle) * satRadius;
      satellites.push(sat);
      ring1.add(sat);
    });

    // 5. Surrounding Cyber Particle Cloud
    const particleCount = 180;
    const particlePositions = new Float32Array(particleCount * 3);

    for (let i = 0; i < particleCount * 3; i += 3) {
      const r = 1.3 + Math.random() * 1.8;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);

      particlePositions[i] = r * Math.sin(phi) * Math.cos(theta);
      particlePositions[i + 1] = r * Math.sin(phi) * Math.sin(theta);
      particlePositions[i + 2] = r * Math.cos(phi);
    }

    const particleGeo = new THREE.BufferGeometry();
    particleGeo.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));

    const particleMat = new THREE.PointsMaterial({
      color: 0xef4444,
      size: 0.038,
      transparent: true,
      opacity: 0.65,
    });

    const particleSystem = new THREE.Points(particleGeo, particleMat);
    scene.add(particleSystem);

    // Mouse Interaction
    let targetRotationX = 0;
    let targetRotationY = 0;
    let mouseX = 0;
    let mouseY = 0;

    const handleMouseMove = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      const x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      const y = -(((e.clientY - rect.top) / rect.height) * 2 - 1);
      mouseX = x * 0.45;
      mouseY = y * 0.45;
    };

    container.addEventListener('mousemove', handleMouseMove);

    // Handle Window Resize
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

      // Core rotation
      coreMesh.rotation.y += 0.5 * delta;
      coreMesh.rotation.x += 0.25 * delta;

      // Pulse breathing scale
      const scale = 1.0 + Math.sin(time * 2.5) * 0.04;
      coreMesh.scale.set(scale, scale, scale);

      // Ring rotations
      ring1.rotation.z += 0.7 * delta;
      ring2.rotation.y += 0.5 * delta;
      ring2.rotation.x += 0.3 * delta;

      // Particle subtle drift
      particleSystem.rotation.y = time * 0.08;
      particleSystem.rotation.z = time * 0.04;

      // Mouse smoothing damping
      targetRotationX += (mouseY - targetRotationX) * 0.05;
      targetRotationY += (mouseX - targetRotationY) * 0.05;

      scene.rotation.x = targetRotationX;
      scene.rotation.y = targetRotationY;

      renderer.render(scene, camera);
    };

    animate();

    // Cleanup
    return () => {
      cancelAnimationFrame(animationFrameId);
      container.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('resize', handleResize);
      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
      renderer.dispose();
      coreGeo.dispose();
      coreMat.dispose();
      innerGeo.dispose();
      innerMat.dispose();
      ring1Geo.dispose();
      ring1Mat.dispose();
      ring2Geo.dispose();
      ring2Mat.dispose();
      satGeo.dispose();
      satMat.dispose();
      particleGeo.dispose();
      particleMat.dispose();
    };
  }, [threatLevel, height]);

  return (
    <div
      className={`relative rounded-2xl overflow-hidden bg-gradient-to-b from-[#0e0a10] to-[#060407] border border-red-950/60 shadow-[0_0_30px_rgba(239,68,68,0.12)] ${className}`}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      {/* 3D WebGL Canvas Mount */}
      <div ref={mountRef} className="w-full flex items-center justify-center cursor-grab active:cursor-grabbing" style={{ height }} />

      {/* Cyberpunk HUD Overlay Over the 3D Model */}
      <div className="absolute top-3 left-3 pointer-events-none flex items-center gap-2">
        <span className="flex h-2 w-2 relative">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
        </span>
        <span className="text-[10px] font-mono tracking-widest uppercase text-red-400/90 font-bold">
          CORE GRID // SECURE
        </span>
      </div>

      <div className="absolute top-3 right-3 pointer-events-none text-right">
        <span className="text-[9px] font-mono tracking-wider text-slate-500 uppercase block">
          3D DEFENSE MATRIX
        </span>
        <span className="text-[10px] font-mono text-red-400 font-bold">
          ACTIVE NODE
        </span>
      </div>

      <div className="absolute bottom-3 left-3 pointer-events-none text-[10px] font-mono text-slate-400 flex items-center gap-2">
        <ShieldCheck className="w-3.5 h-3.5 text-red-400" />
        <span className="text-slate-300">RULE 4 ENFORCEMENT</span>
      </div>

      <div className="absolute bottom-3 right-3 pointer-events-none text-[9px] font-mono text-slate-500">
        INTERACTIVE // TILT
      </div>

      {/* Corner Tech Brackets */}
      <div className="absolute top-1 left-1 w-2.5 h-2.5 border-t border-l border-red-500/40 pointer-events-none" />
      <div className="absolute top-1 right-1 w-2.5 h-2.5 border-t border-r border-red-500/40 pointer-events-none" />
      <div className="absolute bottom-1 left-1 w-2.5 h-2.5 border-b border-l border-red-500/40 pointer-events-none" />
      <div className="absolute bottom-1 right-1 w-2.5 h-2.5 border-b border-r border-red-500/40 pointer-events-none" />
    </div>
  );
};
