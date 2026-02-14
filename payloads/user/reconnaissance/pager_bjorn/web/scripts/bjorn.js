/* ========================================
   Bjorn Tab - LCD Mirror (Live Framebuffer)
   ======================================== */
'use strict';

var BjornTab = {
    canvas: null,
    ctx: null,
    webDelay: 5000,
    scale: 1,
    fbWidth: 222,
    fbHeight: 480,
    refreshing: false,

    init() {
        var panel = document.getElementById('tab-bjorn');
        panel.innerHTML = '<div class="bjorn-panel">' +
            '<div class="lcd-frame" id="lcd-frame">' +
            '<canvas id="lcd-canvas" width="222" height="480" class="lcd-img"></canvas>' +
            '</div>' +
            '<div class="lcd-controls">' +
            '<button class="btn btn-sm" id="lcd-zoom-out">-</button>' +
            '<span class="text-muted" id="lcd-zoom-label">100%</span>' +
            '<button class="btn btn-sm" id="lcd-zoom-in">+</button>' +
            '<button class="btn btn-sm" id="lcd-reset">Reset</button>' +
            '<button class="btn btn-sm btn-gold" id="lcd-refresh">Refresh</button>' +
            '</div></div>';

        this.canvas = document.getElementById('lcd-canvas');
        this.ctx = this.canvas.getContext('2d');

        document.getElementById('lcd-zoom-in').addEventListener('click', () => this.zoom(0.25));
        document.getElementById('lcd-zoom-out').addEventListener('click', () => this.zoom(-0.25));
        document.getElementById('lcd-reset').addEventListener('click', () => {
            this.scale = 1;
            this.applyZoom();
        });
        document.getElementById('lcd-refresh').addEventListener('click', () => this.refresh());

        // Scroll to zoom on desktop
        var frame = document.getElementById('lcd-frame');
        var self = this;
        frame.addEventListener('wheel', function(e) {
            e.preventDefault();
            self.zoom(e.deltaY < 0 ? 0.1 : -0.1);
        }, { passive: false });

        // Pinch to zoom on mobile
        var lastDist = 0;
        frame.addEventListener('touchstart', function(e) {
            if (e.touches.length === 2) {
                lastDist = Math.hypot(
                    e.touches[0].clientX - e.touches[1].clientX,
                    e.touches[0].clientY - e.touches[1].clientY
                );
            }
        });
        frame.addEventListener('touchmove', function(e) {
            if (e.touches.length === 2) {
                e.preventDefault();
                var dist = Math.hypot(
                    e.touches[0].clientX - e.touches[1].clientX,
                    e.touches[0].clientY - e.touches[1].clientY
                );
                if (lastDist) {
                    var delta = (dist - lastDist) / 100;
                    self.zoom(delta);
                }
                lastDist = dist;
            }
        }, { passive: false });

        this.loadDelay();
    },

    async loadDelay() {
        try {
            var data = await App.api('/get_web_delay');
            if (data && data.web_delay) {
                this.webDelay = data.web_delay * 1000;
            }
        } catch (e) {}
    },

    activate() {
        App.startPolling('bjorn', () => this.refresh(), this.webDelay);
    },

    deactivate() {
        App.stopPolling('bjorn');
    },

    async refresh() {
        if (this.refreshing) return;
        this.refreshing = true;
        try {
            var resp = await fetch('/screen.png?t=' + Date.now());
            if (!resp.ok) throw new Error('HTTP ' + resp.status);

            var ct = resp.headers.get('content-type') || '';
            if (ct.includes('octet-stream')) {
                // Raw RGB565 framebuffer data - convert client-side
                var buf = await resp.arrayBuffer();
                this.renderRGB565(buf);
            } else {
                // Fallback: PNG image (no framebuffer on device)
                var blob = await resp.blob();
                var img = new Image();
                var self = this;
                img.onload = function() {
                    self.ctx.drawImage(img, 0, 0);
                    URL.revokeObjectURL(img.src);
                };
                img.src = URL.createObjectURL(blob);
            }
        } catch (e) {
            // Silent retry
        } finally {
            this.refreshing = false;
        }
    },

    renderRGB565(buffer) {
        var pixels = new Uint16Array(buffer);
        var imageData = this.ctx.createImageData(this.fbWidth, this.fbHeight);
        var data = imageData.data;

        for (var i = 0; i < pixels.length; i++) {
            var px = pixels[i];
            var j = i * 4;
            data[j]     = ((px >> 11) & 0x1F) << 3; // R
            data[j + 1] = ((px >> 5) & 0x3F) << 2;  // G
            data[j + 2] = (px & 0x1F) << 3;          // B
            data[j + 3] = 255;                        // A
        }

        this.ctx.putImageData(imageData, 0, 0);
    },

    zoom(delta) {
        this.scale = Math.max(0.5, Math.min(4, this.scale + delta));
        this.applyZoom();
    },

    applyZoom() {
        if (this.canvas) {
            this.canvas.style.width = Math.round(this.fbWidth * this.scale) + 'px';
            this.canvas.style.height = Math.round(this.fbHeight * this.scale) + 'px';
        }
        var frame = document.getElementById('lcd-frame');
        if (frame) {
            frame.style.width = Math.round(this.fbWidth * this.scale + 20) + 'px';
            frame.style.height = Math.round(this.fbHeight * this.scale + 20) + 'px';
        }
        var label = document.getElementById('lcd-zoom-label');
        if (label) label.textContent = Math.round(this.scale * 100) + '%';
    }
};

App.registerTab('bjorn', BjornTab);
