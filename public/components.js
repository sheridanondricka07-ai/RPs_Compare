const Components = {
    renderStatCard(title, value, unit = "") {
        return `
            <div class="stat-card">
                <div style="color: var(--text-muted); font-size: 0.9rem;">${title}</div>
                <div class="stat-value">${value}${unit}</div>
            </div>
        `;
    },

    renderInsight(text) {
        return `
            <div class="insight-item">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                <span>${text}</span>
            </div>
        `;
    },

    renderDiffRow(diff) {
        const color = diff.diff > 0 ? 'var(--success)' : 'var(--error)';
        const prefix = diff.diff > 0 ? '+' : '';
        return `
            <tr>
                <td>${diff.metric}</td>
                <td>${Number(diff.best).toFixed(1)}%</td>
                <td>${Number(diff.bad).toFixed(1)}%</td>
                <td style="color: ${color}; font-weight: 600;">${prefix}${Number(diff.diff).toFixed(1)}%</td>
            </tr>
        `;
    },

    renderScoreRow(item) {
        const scoreColor = item.score > 70 ? 'var(--success)' : (item.score > 40 ? 'var(--warning)' : 'var(--error)');
        return `
            <tr>
                <td title="${item.domain}">${item.domain}</td>
                <td><span class="badge" style="background: ${scoreColor}33; color: ${scoreColor}">${item.score}</span></td>
            </tr>
        `;
    }
};
