import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';

interface HeroShieldLogo3DProps {
  className?: string;
}

export const HeroShieldLogo3D: React.FC<HeroShieldLogo3DProps> = ({ className = '' }) => {
  const mountRef = useRef<HTMLDivElement | null>(null);
  const [isHovered, setIsHovered] = useState(false);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const width = container.clientWidth || 400;
    const height = container.clientHeight || 400;

    // 1. Scene & Camera
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.z = 4.8;

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // 2. Shield Crest Shape
    const shieldShape = new THREE.Shape();
    // Start at top center
    shieldShape.moveTo(0, 1.4);
    // Top right shoulder
    shieldShape.bezierCurveTo(0.6, 1.4, 1.1, 1.25, 1.3, 0.9);
    // Down right side curve to bottom point
    shieldShape.bezierCurveTo(1.3, 0.2, 0.9, -0.7, 0, -1.5);
    // Up left side from bottom point
    shieldShape.bezierCurveTo(-0.9, -0.7, -1.3, 0.2, -1.3, 0.9);
    // Top left shoulder back to top center
    shieldShape.bezierCurveTo(-1.1, 1.25, -0.6, 1.4, 0, 1.4);

    const extrudeSettings: THREE.ExtrudeGeometryOptions = {
      depth: 0.18,
      bevelEnabled: true,
      bevelSegments: 4,
      steps: 1,
      bevelSize: 0.08,
      bevelThickness: 0.08,
    };

    const shieldGeo = new THREE.ExtrudeGeometry(shieldShape, extrudeSettings);
    // Center the shield geometry
    shieldGeo.center();

    // Semi-translucent dark red obsidian base
    const shieldMat = new THREE.MeshBasicMaterial({
      color: 0x140407,
      transparent: true,
      opacity: 0.85,
    });
    const shieldMesh = new THREE.Mesh(shieldGeo, shieldMat);
    scene.add(shieldMesh);

    // Glowing wireframe outline of the shield
    const wireMat = new THREE.MeshBasicMaterial({
      color: 0xef4444,
      wireframe: true,
      transparent: true,
      opacity: 0.9,
    });
    const wireMesh = new THREE.Mesh(shieldGeo, wireMat);
    shieldMesh.add(wireMesh);

    // 3. Central AI Neural Core (Inner Polyhedron)
    const coreGeo = new THREE.IcosahedronGeometry(0.55, 1);
    const coreMat = new THREE.MeshBasicMaterial({
      color: 0xff1744,
      wireframe: true,
      transparent: true,
      opacity: 0.85,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    coreMesh.position.z = 0.22;
    shieldMesh.add(coreMesh);

    // Inner glowing sphere
    const innerGeo = new THREE.SphereGeometry(0.32, 16, 16);
    const innerMat = new THREE.MeshBasicMaterial({
      color: 0xff4444,
      transparent: true,
      opacity: 0.6,
    });
    const innerMesh = new THREE.Mesh(innerGeo, innerMat);
    coreMesh.add(innerMesh);

    // 4. Concentric Orbital Rings (Cyber Defense Boundaries)
    const ring1Geo = new THREE.TorusGeometry(1.75, 0.016, 8, 80);
    const ring1Mat = new THREE.MeshBasicMaterial({
      color: 0xff2222,
      transparent: true,
      opacity: 0.75,
    });
    const ring1 = new THREE.Mesh(ring1Geo, ring1Mat);
    ring1.rotation.x = Math.PI / 3.2;
    ring1.rotation.y = Math.PI / 8;
    scene.add(ring1);

    const ring2Geo = new THREE.TorusGeometry(2.05, 0.012, 8, 80);
    const ring2Mat = new THREE.MeshBasicMaterial({
      color: 0xdc2626,
      transparent: true,
      opacity: 0.5,
    });
    const ring2 = new THREE.Mesh(ring2Geo, ring2Mat);
    ring2.rotation.x = -Math.PI / 3.5;
    ring2.rotation.y = Math.PI / 4;
    scene.add(ring2);

    // 5. Orbiting Sensor Satellites
    const satGeo = new THREE.SphereGeometry(0.065, 8, 8);
    const satMat = new THREE.MeshBasicMaterial({ color: 0xffffff });
    const satCount = 4;
    const satellites: THREE.Mesh[] = [];

    for (let i = 0; i < satCount; i++) {
      const sat = new THREE.Mesh(satGeo, satMat);
      const angle = (i * 2 * Math.PI) / satCount;
      sat.position.x = Math.cos(angle) * 1.75;
      sat.position.y = Math.sin(angle) * 1.75;
      ring1.add(sat);
      satellites.push(sat);
    }

    // 6. Particle Field (Surrounding Ambient Cyber Dust)
    const particleCount = 120;
    const particleGeo = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);

    for (let i = 0; i < particleCount * 3; i += 3) {
      positions[i] = (Math.random() - 0.5) * 6;
      positions[i + 1] = (Math.random() - 0.5) * 6;
      positions[i + 2] = (Math.random() - 0.5) * 4;
    }

    particleGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    const particleMat = new THREE.PointsMaterial({
      color: 0xef4444,
      size: 0.035,
      transparent: true,
      opacity: 0.55,
    });
    const particleField = new THREE.Points(particleGeo, particleMat);
    scene.add(particleField);

    // Mouse Tracking Parallax
    let targetRotX = 0;
    let targetRotY = 0;

    const handleMouseMove = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      const x = (e.clientX - rect.left) / rect.width - 0.5;
      const y = (e.clientY - rect.top) / rect.height - 0.5;
      targetRotY = x * 0.7;
      targetRotX = -y * 0.5;
    };

    window.addEventListener('mousemove', handleMouseMove);

    // Resize Handler
    const handleResize = () => {
      if (!container) return;
      const newWidth = container.clientWidth;
      const newHeight = container.clientHeight;
      camera.aspect = newWidth / newHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(newWidth, newHeight);
    };

    window.addEventListener('resize', handleResize);

    // Animation Loop
    let animId: number;
    let clock = new THREE.Clock();

    const animate = () => {
      animId = requestAnimationFrame(animate);
      const elapsed = clock.getElapsedTime();

      // Smooth mouse follow
      shieldMesh.rotation.y += (targetRotY - shieldMesh.rotation.y) * 0.05;
      shieldMesh.rotation.x += (targetRotX - shieldMesh.rotation.x) * 0.05;

      // Gentle floating bob
      shieldMesh.position.y = Math.sin(elapsed * 1.5) * 0.08;

      // Inner neural core counter-rotation
      coreMesh.rotation.x = elapsed * 0.8;
      coreMesh.rotation.y = elapsed * 1.2;

      // Orbital rings rotation
      ring1.rotation.z = elapsed * 0.5;
      ring2.rotation.z = -elapsed * 0.35;

      // Ambient particle drift
      particleField.rotation.y = elapsed * 0.04;

      renderer.render(scene, camera);
    };

    animate();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('resize', handleResize);
      if (container && renderer.domElement) {
        container.removeChild(renderer.domElement);
      }
      renderer.dispose();
      shieldGeo.dispose();
      shieldMat.dispose();
      wireMat.dispose();
      coreGeo.dispose();
      coreMat.dispose();
      ring1Geo.dispose();
      ring1Mat.dispose();
      ring2Geo.dispose();
      ring2Mat.dispose();
      particleGeo.dispose();
      particleMat.dispose();
    };
  }, []);

  return (
    <div
      ref={mountRef}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={`relative w-full h-full min-h-[380px] flex items-center justify-center cursor-pointer select-none ${className}`}
    >
      {/* Background Soft Radial Glow */}
      <div className="absolute inset-0 bg-radial-gradient from-red-600/25 via-red-950/10 to-transparent blur-2xl pointer-events-none rounded-full" />

      {/* Floating Status Badge */}
      <div className="absolute bottom-4 left-1/2 -translate-x-1/2 px-3 py-1 rounded-full bg-black/80 border border-red-500/40 text-[10px] font-mono text-red-400 font-bold uppercase tracking-widest backdrop-blur-md shadow-lg flex items-center gap-1.5 pointer-events-none z-10">
        <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
        <span>AI-SHIELD CORE // LEAST-PRIVILEGE ACTIVE</span>
      </div>
    </div>
  );
};
